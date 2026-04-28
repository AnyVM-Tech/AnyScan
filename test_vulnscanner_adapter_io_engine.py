"""Unit tests for ANYSCAN_SCANNER_IO_ENGINE plumbing in vulnscanner-zmap-adapter.py.

PR D of plans/2026-04-27-portscan-afxdp-plan-v1.md §3.7 wires the runtime
opt-in env knob into the adapter. AF_PACKET stays the unconditional
default and the AF_XDP request is gated on ANYSCAN_AF_XDP_AVAILABLE
(written by install-worker-bundle.sh's runtime probe). When the knob
points at af_xdp on a host where the kernel/libxdp probe failed, the
adapter must fall back to af_packet and emit a warning rather than
silently scanning at AF_PACKET speeds while the operator believes XDP
is engaged.

Run via ``python3 -m unittest test_vulnscanner_adapter_io_engine -v``
from the anyscan repo root.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parent
ADAPTER_PATH = REPO_ROOT / "vulnscanner-zmap-adapter.py"


def _load_adapter():
    spec = importlib.util.spec_from_file_location("vulnscanner_zmap_adapter", ADAPTER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adapter = _load_adapter()


IO_ENGINE_ENV_KEYS = ("ANYSCAN_SCANNER_IO_ENGINE", "ANYSCAN_AF_XDP_AVAILABLE")


def _clear_io_engine_env() -> None:
    for key in IO_ENGINE_ENV_KEYS:
        os.environ.pop(key, None)


class ResolveIoEngineTests(unittest.TestCase):
    """resolve_io_engine() must select af_packet/af_xdp per env + AF_XDP probe."""

    def setUp(self) -> None:
        self._snapshot = {key: os.environ.get(key) for key in IO_ENGINE_ENV_KEYS}
        _clear_io_engine_env()

    def tearDown(self) -> None:
        for key, value in self._snapshot.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_unset_defaults_to_af_packet(self) -> None:
        self.assertEqual(adapter.resolve_io_engine(), "af_packet")

    def test_explicit_af_packet(self) -> None:
        os.environ["ANYSCAN_SCANNER_IO_ENGINE"] = "af_packet"
        self.assertEqual(adapter.resolve_io_engine(), "af_packet")

    def test_af_packet_does_not_consult_af_xdp_available(self) -> None:
        # AF_XDP availability has no bearing when the operator did not
        # request the AF_XDP path; staying on af_packet must not depend
        # on libxdp being installed.
        os.environ["ANYSCAN_SCANNER_IO_ENGINE"] = "af_packet"
        os.environ["ANYSCAN_AF_XDP_AVAILABLE"] = "false"
        self.assertEqual(adapter.resolve_io_engine(), "af_packet")

    def test_af_xdp_with_runtime_available(self) -> None:
        os.environ["ANYSCAN_SCANNER_IO_ENGINE"] = "af_xdp"
        os.environ["ANYSCAN_AF_XDP_AVAILABLE"] = "true"
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            self.assertEqual(adapter.resolve_io_engine(), "af_xdp")
        self.assertEqual(captured.getvalue(), "")

    def test_af_xdp_request_uppercase_normalizes(self) -> None:
        os.environ["ANYSCAN_SCANNER_IO_ENGINE"] = "AF_XDP"
        os.environ["ANYSCAN_AF_XDP_AVAILABLE"] = "true"
        self.assertEqual(adapter.resolve_io_engine(), "af_xdp")

    def test_af_xdp_with_unavailable_runtime_falls_back_with_warning(self) -> None:
        os.environ["ANYSCAN_SCANNER_IO_ENGINE"] = "af_xdp"
        os.environ["ANYSCAN_AF_XDP_AVAILABLE"] = "false"
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            self.assertEqual(adapter.resolve_io_engine(), "af_packet")
        message = captured.getvalue()
        self.assertIn("af_xdp", message)
        self.assertIn("ANYSCAN_AF_XDP_AVAILABLE", message)

    def test_af_xdp_without_availability_var_falls_back(self) -> None:
        # Missing ANYSCAN_AF_XDP_AVAILABLE behaves the same as false:
        # the installer always writes the value (true OR false), so a
        # missing key implies an old install where libxdp probe never
        # ran. Be conservative.
        os.environ["ANYSCAN_SCANNER_IO_ENGINE"] = "af_xdp"
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            self.assertEqual(adapter.resolve_io_engine(), "af_packet")
        self.assertIn("ANYSCAN_AF_XDP_AVAILABLE", captured.getvalue())

    def test_invalid_value_falls_back_to_af_packet_with_warning(self) -> None:
        os.environ["ANYSCAN_SCANNER_IO_ENGINE"] = "dpdk"
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            self.assertEqual(adapter.resolve_io_engine(), "af_packet")
        self.assertIn("dpdk", captured.getvalue())

    def test_blank_value_defaults_to_af_packet_silently(self) -> None:
        os.environ["ANYSCAN_SCANNER_IO_ENGINE"] = ""
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            self.assertEqual(adapter.resolve_io_engine(), "af_packet")
        self.assertEqual(captured.getvalue(), "")


class BuildCommandIoEngineTests(unittest.TestCase):
    """build_command must append --io-engine=<value> as a flag."""

    def setUp(self) -> None:
        self._snapshot = {key: os.environ.get(key) for key in IO_ENGINE_ENV_KEYS}
        _clear_io_engine_env()
        self._scanner_patch = mock.patch.object(
            adapter, "resolve_scanner_binary", return_value=Path("/usr/bin/scanner")
        )
        self._scanner_patch.start()
        self.addCleanup(self._scanner_patch.stop)

    def tearDown(self) -> None:
        for key, value in self._snapshot.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _build(self) -> list[str]:
        invocation = {
            "target_range": "10.0.0.0/24",
            "ports": "80",
            "rate_limit": 0,
        }
        return adapter.build_command(invocation, Path("/tmp/out"))

    def test_default_appends_io_engine_af_packet(self) -> None:
        cmd = self._build()
        self.assertIn("--io-engine=af_packet", cmd)
        # Sanity: only one --io-engine flag, regardless of form.
        io_engine_args = [arg for arg in cmd if arg.startswith("--io-engine")]
        self.assertEqual(len(io_engine_args), 1)

    def test_af_xdp_request_with_runtime_available_appends_af_xdp(self) -> None:
        os.environ["ANYSCAN_SCANNER_IO_ENGINE"] = "af_xdp"
        os.environ["ANYSCAN_AF_XDP_AVAILABLE"] = "true"
        cmd = self._build()
        self.assertIn("--io-engine=af_xdp", cmd)
        self.assertNotIn("--io-engine=af_packet", cmd)

    def test_af_xdp_request_without_runtime_falls_back_to_af_packet(self) -> None:
        os.environ["ANYSCAN_SCANNER_IO_ENGINE"] = "af_xdp"
        os.environ["ANYSCAN_AF_XDP_AVAILABLE"] = "false"
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            cmd = self._build()
        self.assertIn("--io-engine=af_packet", cmd)
        self.assertNotIn("--io-engine=af_xdp", cmd)
        self.assertIn("ANYSCAN_AF_XDP_AVAILABLE", captured.getvalue())

    def test_invalid_request_falls_back_to_af_packet(self) -> None:
        os.environ["ANYSCAN_SCANNER_IO_ENGINE"] = "garbage"
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            cmd = self._build()
        self.assertIn("--io-engine=af_packet", cmd)


class AdapterIoEngineIntegrationTests(unittest.TestCase):
    """End-to-end: spawn the adapter and confirm the scanner gets --io-engine=."""

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="adapter-io-engine-"))
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)
        self._stub_log = self._tmp / "calls.log"
        self._stub = self._tmp / "stub-scanner.sh"
        self._stub.write_text(
            textwrap.dedent(
                """
                #!/usr/bin/env bash
                printf '%%s\\n' "$*" >>"%s"
                output=""
                while [ $# -gt 0 ]; do
                    case "$1" in
                        --output-file) output="$2"; shift 2 ;;
                        *) shift ;;
                    esac
                done
                if [ -n "$output" ]; then
                    : >"$output"
                fi
                printf '0:00 100%%; send: 1 1.00p/s (1.00p/s avg); recv: 0 0p/s\\n' >&2
                exit 0
                """
                % str(self._stub_log)
            ).strip()
            + "\n"
        )
        os.chmod(self._stub, 0o755)
        self._output_path = self._tmp / "adapter.out"

    def _run_adapter(self, env_overrides: dict[str, str]) -> subprocess.CompletedProcess[str]:
        invocation = {
            "target_range": "10.0.0.0-10.0.0.3",
            "ports": "80",
            "rate_limit": 0,
            "output_path": str(self._output_path),
        }
        env = os.environ.copy()
        env["SCANNER_BIN"] = str(self._stub)
        # Force the legacy static path so the AIMD respawn loop does not
        # add extra invocations the test would have to model.
        env["ANYSCAN_DYNAMIC_RATE_ENABLED"] = "false"
        # Strip ANYSCAN_SCANNER_INTERFACES so the parent does not engage
        # multi-NIC fan-out from a host inheriting it from the env.
        env.pop("ANYSCAN_SCANNER_INTERFACES", None)
        for key in IO_ENGINE_ENV_KEYS:
            env.pop(key, None)
        env.update(env_overrides)
        return subprocess.run(
            [sys.executable, str(ADAPTER_PATH)],
            input=json.dumps(invocation),
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
        )

    def _read_calls(self) -> list[str]:
        if not self._stub_log.exists():
            return []
        return [line for line in self._stub_log.read_text().splitlines() if line.strip()]

    def test_default_passes_io_engine_af_packet(self) -> None:
        result = self._run_adapter({})
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        calls = self._read_calls()
        self.assertEqual(len(calls), 1)
        self.assertIn("--io-engine=af_packet", calls[0])

    def test_af_xdp_request_with_runtime_available_passes_af_xdp(self) -> None:
        result = self._run_adapter(
            {
                "ANYSCAN_SCANNER_IO_ENGINE": "af_xdp",
                "ANYSCAN_AF_XDP_AVAILABLE": "true",
            }
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        calls = self._read_calls()
        self.assertEqual(len(calls), 1)
        self.assertIn("--io-engine=af_xdp", calls[0])
        self.assertNotIn("--io-engine=af_packet", calls[0])

    def test_af_xdp_request_without_runtime_falls_back_to_af_packet(self) -> None:
        result = self._run_adapter(
            {
                "ANYSCAN_SCANNER_IO_ENGINE": "af_xdp",
                "ANYSCAN_AF_XDP_AVAILABLE": "false",
            }
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        calls = self._read_calls()
        self.assertEqual(len(calls), 1)
        self.assertIn("--io-engine=af_packet", calls[0])
        # The warning must surface so operators see the downgrade in journal.
        self.assertIn("ANYSCAN_AF_XDP_AVAILABLE", result.stderr)


if __name__ == "__main__":
    unittest.main()
