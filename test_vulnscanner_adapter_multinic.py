"""Unit tests for the multi-NIC orchestration in vulnscanner-zmap-adapter.py.

Run via ``python3 -m unittest test_vulnscanner_adapter_multinic -v`` from
the anyscan repo root. Pure-Python; no scanner binary or NIC required.

The adapter file uses a hyphenated name so it cannot be imported via the
normal import statement; we load it via importlib so the tests can probe
the helpers directly.
"""

from __future__ import annotations

import importlib.util
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


class ParseScannerInterfacesTests(unittest.TestCase):
    def test_none_yields_empty(self) -> None:
        self.assertEqual(adapter.parse_scanner_interfaces(None), [])

    def test_empty_yields_empty(self) -> None:
        self.assertEqual(adapter.parse_scanner_interfaces(""), [])
        self.assertEqual(adapter.parse_scanner_interfaces("   "), [])
        self.assertEqual(adapter.parse_scanner_interfaces(",,,"), [])

    def test_single_interface(self) -> None:
        self.assertEqual(adapter.parse_scanner_interfaces("eth0"), ["eth0"])

    def test_comma_separated(self) -> None:
        self.assertEqual(
            adapter.parse_scanner_interfaces("eth0,eth1,eth2"),
            ["eth0", "eth1", "eth2"],
        )

    def test_whitespace_separated_and_mixed(self) -> None:
        self.assertEqual(
            adapter.parse_scanner_interfaces("eth0 eth1, eth2;eth3"),
            ["eth0", "eth1", "eth2", "eth3"],
        )

    def test_dedup_preserves_first_position(self) -> None:
        # Operators sometimes copy/paste the default-route iface into the
        # list; the result should keep the first occurrence and ignore
        # duplicates so the shard count is what they actually configured.
        self.assertEqual(
            adapter.parse_scanner_interfaces("eth0,eth1,eth0,eth2"),
            ["eth0", "eth1", "eth2"],
        )


class FormatTargetRangeTests(unittest.TestCase):
    def test_single_host_renders_bare_address(self) -> None:
        self.assertEqual(adapter.format_target_range(0x0A000001, 0x0A000001), "10.0.0.1")

    def test_range_renders_dashed(self) -> None:
        # 10.0.0.0 - 10.0.0.255
        self.assertEqual(
            adapter.format_target_range(0x0A000000, 0x0A0000FF),
            "10.0.0.0-10.0.0.255",
        )


class SplitTargetRangeForShardsTests(unittest.TestCase):
    def test_unparseable_returns_input_unchanged(self) -> None:
        # Hostnames or unsupported syntaxes are passed through; the API
        # layer is the source of truth for target_range syntax and the
        # adapter is just shovelware.
        self.assertEqual(
            adapter.split_target_range_for_shards("not-an-ip", 4),
            ["not-an-ip"],
        )

    def test_shard_count_one_returns_one_entry(self) -> None:
        self.assertEqual(
            adapter.split_target_range_for_shards("10.0.0.0/24", 1),
            ["10.0.0.0-10.0.0.255"],
        )

    def test_shard_count_zero_or_negative_returns_one_entry(self) -> None:
        self.assertEqual(
            adapter.split_target_range_for_shards("10.0.0.0/24", 0),
            ["10.0.0.0-10.0.0.255"],
        )

    def test_single_host_input_returns_single_shard(self) -> None:
        self.assertEqual(
            adapter.split_target_range_for_shards("10.0.0.1", 4),
            ["10.0.0.1"],
        )

    def test_even_split_for_a_24(self) -> None:
        # 256 hosts / 4 shards = 64 each, contiguous and disjoint.
        shards = adapter.split_target_range_for_shards("10.0.0.0/24", 4)
        self.assertEqual(
            shards,
            [
                "10.0.0.0-10.0.0.63",
                "10.0.0.64-10.0.0.127",
                "10.0.0.128-10.0.0.191",
                "10.0.0.192-10.0.0.255",
            ],
        )

    def test_remainder_distributed_to_first_shards(self) -> None:
        # 10 hosts / 3 shards = sizes 4,3,3. Mirrors the algorithm in
        # split_port_scan_target_range (Rust) so the parent fan-out and
        # the API-side fan-out partition the address space identically.
        shards = adapter.split_target_range_for_shards("10.0.0.0-10.0.0.9", 3)
        self.assertEqual(
            shards,
            [
                "10.0.0.0-10.0.0.3",
                "10.0.0.4-10.0.0.6",
                "10.0.0.7-10.0.0.9",
            ],
        )

    def test_dashed_range_input_round_trips(self) -> None:
        shards = adapter.split_target_range_for_shards("192.168.1.0-192.168.1.7", 2)
        self.assertEqual(shards, ["192.168.1.0-192.168.1.3", "192.168.1.4-192.168.1.7"])

    def test_more_shards_than_hosts_clamps(self) -> None:
        # 4 hosts but 8 shards requested: produce one shard per host, no
        # empty placeholders. Empty shards would cause the scanner to
        # exit immediately and look like a child crash to the parent.
        shards = adapter.split_target_range_for_shards("10.0.0.0-10.0.0.3", 8)
        self.assertEqual(len(shards), 4)
        self.assertEqual(
            shards,
            ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"],
        )

    def test_shards_are_disjoint_and_cover_full_range(self) -> None:
        # Property check: regardless of (shard_count, range) the union
        # covers exactly the input and shards do not overlap. Catches
        # off-by-one mistakes in the cursor advance.
        import ipaddress

        shards = adapter.split_target_range_for_shards("10.0.0.0/22", 7)
        self.assertGreater(len(shards), 1)
        seen: set[int] = set()
        for shard in shards:
            if "-" in shard:
                start_text, end_text = shard.split("-", 1)
                start = int(ipaddress.IPv4Address(start_text))
                end = int(ipaddress.IPv4Address(end_text))
            else:
                value = int(ipaddress.IPv4Address(shard))
                start = end = value
            for host in range(start, end + 1):
                self.assertNotIn(host, seen)
                seen.add(host)
        expected_total = 0x0A0003FF - 0x0A000000 + 1
        self.assertEqual(len(seen), expected_total)


class BuildShardInvocationTests(unittest.TestCase):
    def test_overrides_target_range_and_paths(self) -> None:
        parent = {
            "target_range": "10.0.0.0/24",
            "ports": "80,443",
            "rate_limit": 1_000_000,
            "checkpoint_path": "/var/lib/agentd/state.checkpoint",
        }
        out_path = Path("/tmp/shard.out")
        ckpt = Path("/tmp/shard.checkpoint")
        shard = adapter.build_shard_invocation(
            parent,
            shard_target_range="10.0.0.0-10.0.0.63",
            shard_output_path=out_path,
            shard_checkpoint_path=ckpt,
        )
        self.assertEqual(shard["target_range"], "10.0.0.0-10.0.0.63")
        self.assertEqual(shard["ports"], "80,443")
        self.assertEqual(shard["rate_limit"], 1_000_000)
        self.assertEqual(shard["output_path"], str(out_path))
        self.assertEqual(shard["checkpoint_path"], str(ckpt))
        # Must not mutate the caller's dict so the orchestrator can build
        # multiple shard invocations from the same parent invocation.
        self.assertEqual(parent["target_range"], "10.0.0.0/24")
        self.assertNotIn("output_path", parent)


class RunMultiNicScannerTests(unittest.TestCase):
    """Smoke test the orchestrator with a stubbed spawn.

    The real spawn fork-execs python on the adapter file; in the test we
    replace _spawn_shard_adapter with a stub that fakes a child writing
    sentinel output and exiting cleanly. That exercises the orchestration
    glue without needing a scanner binary or a NIC.
    """

    def test_orchestrates_one_child_per_interface_and_merges_output(self) -> None:
        invocation = {
            "target_range": "10.0.0.0-10.0.0.7",
            "ports": "80",
            "rate_limit": 0,
        }
        interfaces = ["eth0", "eth1"]
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "merged.out"
            output_path.touch()

            spawn_calls: list[tuple[dict, str]] = []

            class StubChild:
                def __init__(self, iface: str, shard_output: Path) -> None:
                    self._iface = iface
                    self._shard_output = shard_output
                    self.pid = 123456 + len(spawn_calls)
                    self.returncode = 0

                def wait(self) -> int:
                    self._shard_output.write_text(
                        f"10.0.0.{1 if self._iface == 'eth0' else 5}:80\n"
                    )
                    return 0

                def poll(self) -> int:
                    return 0

            def fake_spawn(invocation_dict, *, interface, stderr_log):
                shard_output = Path(invocation_dict["output_path"])
                shard_output.parent.mkdir(parents=True, exist_ok=True)
                stderr_log.parent.mkdir(parents=True, exist_ok=True)
                stderr_log.write_text(
                    f"[anyscan-rate-controller] metric=\"window\" iface={interface}\n"
                )
                spawn_calls.append((dict(invocation_dict), interface))
                return StubChild(interface, shard_output)

            with mock.patch.object(adapter, "_spawn_shard_adapter", side_effect=fake_spawn):
                exit_code = adapter.run_multi_nic_scanner(invocation, output_path, interfaces)

            self.assertEqual(exit_code, 0)
            self.assertEqual(len(spawn_calls), 2)
            shard_targets = sorted(call[0]["target_range"] for call in spawn_calls)
            self.assertEqual(
                shard_targets,
                ["10.0.0.0-10.0.0.3", "10.0.0.4-10.0.0.7"],
            )
            self.assertEqual(
                sorted(call[1] for call in spawn_calls),
                ["eth0", "eth1"],
            )
            merged = output_path.read_text()
            self.assertIn("10.0.0.1:80", merged)
            self.assertIn("10.0.0.5:80", merged)

    def test_first_child_failure_short_circuits_with_nonzero_exit(self) -> None:
        invocation = {
            "target_range": "10.0.0.0-10.0.0.7",
            "ports": "80",
            "rate_limit": 0,
        }
        interfaces = ["eth0", "eth1"]
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "merged.out"
            output_path.touch()

            class StubChild:
                def __init__(self, exit_code: int) -> None:
                    self.pid = 99999
                    self.returncode = exit_code
                    self._exit_code = exit_code

                def wait(self) -> int:
                    return self._exit_code

                def poll(self) -> int:
                    return self._exit_code

            def fake_spawn(invocation_dict, *, interface, stderr_log):
                Path(invocation_dict["output_path"]).touch()
                stderr_log.parent.mkdir(parents=True, exist_ok=True)
                stderr_log.write_text("scanner crashed\n")
                # First child fails, second would have succeeded but we
                # never reach its wait() in single-thread sequential mode.
                return StubChild(7 if interface == "eth0" else 0)

            with mock.patch.object(adapter, "_spawn_shard_adapter", side_effect=fake_spawn):
                with mock.patch.object(adapter, "_terminate_child_adapters") as fake_terminate:
                    exit_code = adapter.run_multi_nic_scanner(
                        invocation, output_path, interfaces
                    )

            self.assertEqual(exit_code, 7)
            # Surviving siblings must be reaped after the first failure
            # so a stuck child can't leave the worker hanging.
            self.assertTrue(fake_terminate.called)


class AdapterFanoutEnvTests(unittest.TestCase):
    """End-to-end check that ANYSCAN_SCANNER_INTERFACES gates the fan-out.

    Spawns the adapter as a real subprocess with SCANNER_BIN pointed at a
    stub script that records its argv to a per-call log. With two
    interfaces in the env we expect two scanner invocations (one per
    iface) with disjoint target_range arguments. With one interface the
    legacy single-NIC path runs and we get one invocation.
    """

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="adapter-fanout-"))
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)
        self._stub_log = self._tmp / "calls.log"
        self._stub = self._tmp / "stub-scanner.sh"
        # The stub mimics just enough of the bundled scanner to satisfy
        # the adapter: writes one endpoint to --output-file, prints a
        # progress line to stderr, exits 0. argv is appended (one line
        # per process) so the test can read back what the adapter passed.
        self._stub.write_text(
            textwrap.dedent(
                """
                #!/usr/bin/env bash
                exec >>"%s.stdout" 2>>"%s.stderr"
                printf '%%s\\n' "$*" >>"%s"
                output=""
                target=""
                while [ $# -gt 0 ]; do
                    case "$1" in
                        --output-file) output="$2"; shift 2 ;;
                        --target-range) target="$2"; shift 2 ;;
                        *) shift ;;
                    esac
                done
                if [ -n "$output" ]; then
                    case "$target" in
                        # The adapter routes both /30 (CIDR collapsed by
                        # ipaddress.summarize_address_range) and the
                        # original dashed form here, so match either.
                        10.0.0.0/30|10.0.0.0-10.0.0.3*) printf '10.0.0.1:80\\n' >"$output" ;;
                        10.0.0.4/30|10.0.0.4-10.0.0.7*) printf '10.0.0.5:80\\n' >"$output" ;;
                        *) printf '10.0.0.9:80\\n' >"$output" ;;
                    esac
                fi
                printf '0:00 100%%; send: 1 1.00p/s (1.00p/s avg); recv: 0 0p/s\\n' >&2
                exit 0
                """
                % (str(self._stub), str(self._stub), str(self._stub_log))
            ).strip()
            + "\n"
        )
        os.chmod(self._stub, 0o755)
        self._output_path = self._tmp / "adapter.out"

    def _run_adapter(self, env_overrides: dict[str, str]) -> subprocess.CompletedProcess[str]:
        invocation = {
            "target_range": "10.0.0.0-10.0.0.7",
            "ports": "80",
            "rate_limit": 0,
            "output_path": str(self._output_path),
        }
        env = os.environ.copy()
        env["SCANNER_BIN"] = str(self._stub)
        # Force the legacy static path so the AIMD respawn loop does not
        # add extra invocations the test would have to model.
        env["ANYSCAN_DYNAMIC_RATE_ENABLED"] = "false"
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

    def test_single_interface_runs_once(self) -> None:
        result = self._run_adapter({"ANYSCAN_SCANNER_INTERFACES": "eth0"})
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        calls = self._read_calls()
        self.assertEqual(len(calls), 1)
        # The adapter passes the unsharded target_range through
        # normalize_target_range_for_scanner which collapses
        # power-of-two-aligned dashes to CIDR. Either form is acceptable
        # here since both round-trip back to the same address set.
        self.assertTrue(
            "--target-range 10.0.0.0-10.0.0.7" in calls[0]
            or "--target-range 10.0.0.0/29" in calls[0],
            msg=calls[0],
        )

    def test_two_interfaces_fan_out_and_merge(self) -> None:
        result = self._run_adapter(
            {"ANYSCAN_SCANNER_INTERFACES": "eth0,eth1"}
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        calls = self._read_calls()
        self.assertEqual(len(calls), 2)
        # Each child must hit a disjoint sub-range and pin its --interface
        # to its assigned ENI. After normalization the /30 boundaries
        # collapse to CIDR; either CIDR or dashed form is acceptable.
        joined = "\n".join(calls)
        self.assertTrue(
            "--target-range 10.0.0.0-10.0.0.3" in joined
            or "--target-range 10.0.0.0/30" in joined,
            msg=joined,
        )
        self.assertTrue(
            "--target-range 10.0.0.4-10.0.0.7" in joined
            or "--target-range 10.0.0.4/30" in joined,
            msg=joined,
        )
        self.assertIn("--interface eth0", joined)
        self.assertIn("--interface eth1", joined)
        # The merged endpoints from both shards must surface on stdout
        # so the worker that consumes them sees the union, not just one
        # shard's hits.
        self.assertIn("10.0.0.1:80", result.stdout)
        self.assertIn("10.0.0.5:80", result.stdout)


class CapConcurrentSubprocessesTests(unittest.TestCase):
    """Verify the multi-NIC adapter caps concurrent shards (improvement #2)."""

    def test_cap_truncates_to_first_n_interfaces(self) -> None:
        ifaces = ["eth0", "eth1", "eth2", "eth3", "eth4", "eth5", "eth6", "eth7"]
        capped = adapter.cap_concurrent_subprocesses(ifaces, max_concurrent=4)
        self.assertEqual(capped, ["eth0", "eth1", "eth2", "eth3"])

    def test_cap_below_count_returns_full_list(self) -> None:
        capped = adapter.cap_concurrent_subprocesses(["eth0", "eth1"], max_concurrent=4)
        self.assertEqual(capped, ["eth0", "eth1"])

    def test_cap_zero_or_negative_disables_cap(self) -> None:
        ifaces = ["eth0", "eth1", "eth2"]
        self.assertEqual(adapter.cap_concurrent_subprocesses(ifaces, max_concurrent=0), ifaces)
        self.assertEqual(adapter.cap_concurrent_subprocesses(ifaces, max_concurrent=-1), ifaces)

    def test_cap_does_not_mutate_input(self) -> None:
        ifaces = ["eth0", "eth1", "eth2", "eth3", "eth4"]
        original = list(ifaces)
        adapter.cap_concurrent_subprocesses(ifaces, max_concurrent=2)
        self.assertEqual(ifaces, original)


class MultiNicSubprocessCapIntegrationTests(unittest.TestCase):
    """End-to-end: pass 8 interfaces, observe 4 spawn calls (default cap=4)."""

    def _run_with_interfaces(
        self, interfaces: list[str], *, env_max: str | None = None
    ) -> tuple[int, list[str]]:
        invocation = {
            "target_range": "10.0.0.0-10.0.0.255",
            "ports": "80",
            "rate_limit": 0,
        }
        spawn_calls: list[str] = []

        class StubChild:
            def __init__(self, iface: str, shard_output: Path) -> None:
                self._iface = iface
                self._shard_output = shard_output
                self.pid = 100000 + len(spawn_calls)
                self.returncode = 0

            def wait(self) -> int:
                self._shard_output.write_text("")
                return 0

            def poll(self) -> int:
                return 0

        def fake_spawn(invocation_dict, *, interface, stderr_log):
            shard_output = Path(invocation_dict["output_path"])
            shard_output.parent.mkdir(parents=True, exist_ok=True)
            stderr_log.parent.mkdir(parents=True, exist_ok=True)
            stderr_log.write_text("")
            spawn_calls.append(interface)
            return StubChild(interface, shard_output)

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "merged.out"
            output_path.touch()
            env_patch: dict[str, str] = {}
            if env_max is not None:
                env_patch["ANYSCAN_RATE_MAX_CONCURRENT_SUBPROCESSES"] = env_max
            with mock.patch.object(adapter, "_spawn_shard_adapter", side_effect=fake_spawn), \
                 mock.patch.dict(os.environ, env_patch, clear=False):
                exit_code = adapter.run_multi_nic_scanner(
                    invocation, output_path, interfaces
                )
        return exit_code, spawn_calls

    def test_eight_interfaces_capped_to_four_by_default(self) -> None:
        ifaces = [f"eth{i}" for i in range(8)]
        exit_code, spawned = self._run_with_interfaces(ifaces)
        self.assertEqual(exit_code, 0)
        self.assertEqual(spawned, ["eth0", "eth1", "eth2", "eth3"])

    def test_env_override_raises_cap(self) -> None:
        ifaces = [f"eth{i}" for i in range(8)]
        exit_code, spawned = self._run_with_interfaces(ifaces, env_max="6")
        self.assertEqual(exit_code, 0)
        self.assertEqual(spawned, ["eth0", "eth1", "eth2", "eth3", "eth4", "eth5"])

    def test_env_override_zero_disables_cap(self) -> None:
        ifaces = [f"eth{i}" for i in range(8)]
        exit_code, spawned = self._run_with_interfaces(ifaces, env_max="0")
        self.assertEqual(exit_code, 0)
        self.assertEqual(spawned, ifaces)

    def test_three_interfaces_unchanged_under_default_cap(self) -> None:
        # Cap=4 with 3 NICs is a no-op — common path on smaller boxes.
        ifaces = ["eth0", "eth1", "eth2"]
        exit_code, spawned = self._run_with_interfaces(ifaces)
        self.assertEqual(exit_code, 0)
        self.assertEqual(spawned, ifaces)


if __name__ == "__main__":
    unittest.main()
