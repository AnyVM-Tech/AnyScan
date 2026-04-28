#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

# AIMD dynamic-rate controller. Imported lazily so the legacy single-spawn
# code path keeps working in environments where the controller module is
# missing (e.g. older bundles deployed before this change).
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import anyscan_rate_controller as rate_controller  # type: ignore  # noqa: E402
except ImportError:  # pragma: no cover - bundle missing the module
    rate_controller = None  # type: ignore[assignment]

HOST_CPU_THREADS = max(1, os.cpu_count() or 1)
# Last-resort fallback when neither the per-scan invocation nor the
# SCANNER_DEFAULT_RATE env var supplies a rate. install-worker-bundle.sh
# writes SCANNER_DEFAULT_RATE=500000 by default, so this constant is only
# used in test/dev contexts where the env file is absent. Kept in sync
# with the installer default to avoid surprising operators who run the
# adapter outside the bundled service.
DEFAULT_RATE_LIMIT = 500_000
DEFAULT_SENDER_THREADS = HOST_CPU_THREADS
# Receivers serialize on the AF_PACKET queue, so per-CPU spawning wastes
# cycles on lock contention without raising capture throughput. Bench on
# c6in.xlarge confirms 1/2/4 receivers all hit the same send ceiling.
DEFAULT_RECEIVER_THREADS = 1
DEFAULT_COOLDOWN_SECONDS = 5
# Concurrency cap for the multi-NIC parent. anygpt-4 bench data shows the
# kernel TX path on c6in.metal-class boxes saturates around 4 concurrent
# scanner processes regardless of how many ENAs are attached: 4-NIC peaks
# at 12.8M aggregate, 8-NIC regressed to 1.3M because the 5th-8th
# children CPU-starved the first four into AIMD-cratering on every
# window. Keeping at most 4 active shards leaves headroom for agentd +
# other system processes and keeps the per-shard AIMD loops in their
# converged band. Override via ANYSCAN_RATE_MAX_CONCURRENT_SUBPROCESSES.
DEFAULT_MAX_CONCURRENT_SUBPROCESSES = 4
CURRENT_CHILD: subprocess.Popen[bytes] | None = None
PROGRESS_LINE_RE = re.compile(
    r"(?P<minutes>\d+):(?P<seconds>\d+)\s+(?P<percent>\d+)%;\s+send:\s+"
    r"(?P<sent>\d+)\s+(?P<send_rate>[0-9.]+\s*[KMG]?p/s)\s+\((?P<avg_send_rate>[0-9.]+\s*[KMG]?p/s)\s+avg\);"
    r"\s+recv:\s+(?P<recv>\d+)\s+(?P<recv_rate>[0-9.]+\s*[KMG]?p/s);"
)


def fail(message: str, exit_code: int = 1) -> "None":
    print(message, file=sys.stderr)
    raise SystemExit(exit_code)


def require_string(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        fail(f"missing required invocation field: {key}")
    return value.strip()


def normalize_target_range_for_scanner(target_range: str) -> str:
    trimmed = target_range.strip()
    if not trimmed or "/" in trimmed:
        return trimmed
    if "-" in trimmed:
        start_raw, end_raw = trimmed.split("-", 1)
        try:
            start = ipaddress.IPv4Address(start_raw.strip())
            end = ipaddress.IPv4Address(end_raw.strip())
        except ValueError:
            return trimmed
        if int(start) > int(end):
            return trimmed
        summarized = list(ipaddress.summarize_address_range(start, end))
        if len(summarized) == 1:
            return str(summarized[0])
        return trimmed
    try:
        ipaddress.IPv4Address(trimmed)
    except ValueError:
        return trimmed
    return f"{trimmed}/32"


def env_string(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    if value:
        return value
    return None


def env_int(name: str, default: int) -> int:
    value = env_string(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        fail(f"invalid integer for {name}: {value}")


def env_flag(name: str, default: bool = False) -> bool:
    value = env_string(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


# Phase 2 PR D of plans/2026-04-27-portscan-afxdp-plan-v1.md §3.7. The
# scanner accepts --io-engine={af_packet,af_xdp}; AF_PACKET stays the
# unconditional default and AF_XDP is opt-in per worker. The install-time
# probe in install-worker-bundle.sh::probe_afxdp_runtime_available
# writes ANYSCAN_AF_XDP_AVAILABLE=true|false based on kernel >=5.10
# AND libxdp.so being loadable; we refuse to forward af_xdp when the
# probe failed because the scanner would crash at startup with a dlopen
# error and the worker has no way to recover. The fall-back warning is
# loud on purpose: silently dropping back to AF_PACKET would let an
# operator who flipped the knob keep believing they were running on the
# fast path.
SUPPORTED_IO_ENGINES = ("af_packet", "af_xdp")
DEFAULT_IO_ENGINE = "af_packet"


def resolve_io_engine() -> str:
    """Resolve the scanner --io-engine value from env, with AF_XDP gating.

    Returns the engine string the adapter should pass to the scanner.
    Always returns a value from ``SUPPORTED_IO_ENGINES``; unrecognized,
    unset, or ungated requests collapse to ``af_packet`` so the scanner
    stays on its known-safe default. Warnings are emitted to stderr
    when a request is downgraded so the journal carries an audit trail.
    """

    raw = env_string("ANYSCAN_SCANNER_IO_ENGINE")
    if raw is None:
        return DEFAULT_IO_ENGINE
    requested = raw.lower()
    if requested not in SUPPORTED_IO_ENGINES:
        print(
            f"[anyscan-adapter] unrecognized ANYSCAN_SCANNER_IO_ENGINE={raw!r}; "
            f"falling back to {DEFAULT_IO_ENGINE}",
            file=sys.stderr,
        )
        return DEFAULT_IO_ENGINE
    if requested == "af_xdp" and not env_flag("ANYSCAN_AF_XDP_AVAILABLE"):
        print(
            "[anyscan-adapter] ANYSCAN_SCANNER_IO_ENGINE=af_xdp requested but "
            "ANYSCAN_AF_XDP_AVAILABLE!=true; the install-time probe did not "
            "detect a kernel/libxdp combination that supports AF_XDP. "
            f"Falling back to {DEFAULT_IO_ENGINE}.",
            file=sys.stderr,
        )
        return DEFAULT_IO_ENGINE
    return requested


def resolve_scanner_binary() -> Path:
    candidates: list[Path] = []
    configured = env_string("SCANNER_BIN")
    if configured is not None:
        candidates.append(Path(configured).expanduser())

    script_dir = Path(__file__).resolve().parent
    which_scanner = shutil.which("scanner")
    candidates.extend(
        [
            script_dir.parent / "bin" / "scanner",
            script_dir.parent.parent / "VulnScanner-zmap-alternative-" / "scanner",
            Path("/usr/bin/scanner"),
        ]
    )
    if which_scanner is not None:
        candidates.append(Path(which_scanner))

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()

    searched = ", ".join(str(candidate) for candidate in candidates)
    fail(
        "unable to locate the scanner binary; set SCANNER_BIN or provide the bundled scanner runtime "
        f"(searched: {searched})"
    )


def resolve_rate_limit(invocation: dict[str, object]) -> int:
    rate_limit = invocation.get("rate_limit")
    if not isinstance(rate_limit, int):
        rate_limit = max(1, env_int("SCANNER_DEFAULT_RATE", DEFAULT_RATE_LIMIT))
    return rate_limit


def build_command(
    invocation: dict[str, object],
    output_path: Path,
    *,
    rate_override: int | None = None,
    resume_override: bool | None = None,
) -> list[str]:
    scanner_binary = resolve_scanner_binary()
    target_range = normalize_target_range_for_scanner(
        require_string(invocation, "target_range")
    )
    ports = require_string(invocation, "ports")
    probe_module = env_string("SCANNER_PROBE_MODULE") or "tcp"
    cooldown = max(0, env_int("SCANNER_COOLDOWN_SECONDS", DEFAULT_COOLDOWN_SECONDS))

    rate_limit = rate_override if rate_override is not None else resolve_rate_limit(invocation)
    sender_threads = invocation.get("sender_threads")
    if not isinstance(sender_threads, int) or sender_threads <= 0:
        sender_threads = max(1, env_int("SCANNER_SENDER_THREADS", DEFAULT_SENDER_THREADS))
    receiver_threads = invocation.get("receiver_threads")
    if not isinstance(receiver_threads, int) or receiver_threads <= 0:
        receiver_threads = max(1, env_int("SCANNER_RECEIVER_THREADS", DEFAULT_RECEIVER_THREADS))

    command = [
        str(scanner_binary),
        "--target-range",
        target_range,
        "--port",
        ports,
        "--probe-module",
        probe_module,
        "--sender-threads",
        str(sender_threads),
        "--receivers",
        str(receiver_threads),
        "--cooldown-time",
        str(cooldown),
        "--output-file",
        str(output_path),
        f"--io-engine={resolve_io_engine()}",
    ]
    checkpoint_path = invocation.get("checkpoint_path")
    if isinstance(checkpoint_path, str) and checkpoint_path.strip():
        command.extend(["--checkpoint-file", checkpoint_path.strip()])
    resume = resume_override if resume_override is not None else bool(invocation.get("resume"))
    if resume:
        command.append("--resume")
    if rate_limit > 0:
        command.extend(["--rate", str(rate_limit)])

    optional_pairs = [
        ("SCANNER_INTERFACE", "--interface"),
        ("SCANNER_SOURCE_IP", "--source-ip"),
        ("SCANNER_GATEWAY_MAC", "--gateway-mac"),
        ("SCANNER_BANDWIDTH", "--bandwidth"),
        ("SCANNER_PROBE_ARGS", "--probe-args"),
        ("SCANNER_WHITELIST_FILE", "--whitelist-file"),
        ("SCANNER_BLACKLIST_FILE", "--blacklist-file"),
    ]
    for env_name, flag in optional_pairs:
        value = env_string(env_name)
        if value is not None:
            command.extend([flag, value])

    if env_flag("SCANNER_ICMP_PRESCAN"):
        command.append("--icmp")

    extra_args = env_string("SCANNER_EXTRA_ARGS")
    if extra_args is not None:
        command.extend(shlex.split(extra_args))

    return command


def detect_default_interface() -> str | None:
    explicit = env_string("SCANNER_INTERFACE")
    if explicit:
        return explicit
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as handle:
            for line in handle.readlines()[1:]:
                fields = line.split()
                if len(fields) < 11:
                    continue
                # Destination==00000000 means the default route entry.
                if fields[1] == "00000000" and (int(fields[3], 16) & 0x2):
                    return fields[0]
    except OSError:
        return None
    return None


def progress_path_for_output(output_path: Path) -> Path:
    return output_path.with_name(output_path.name + ".progress")


def checkpoint_path_for_output(output_path: Path) -> Path:
    return output_path.with_name(output_path.name + ".checkpoint")


def parse_rate_to_millis(value: str) -> int:
    match = re.match(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([KMG]?)p/s\s*$", value)
    if not match:
        return 0
    number = float(match.group(1))
    suffix = match.group(2).upper()
    multiplier = 1.0
    if suffix == "K":
        multiplier = 1_000.0
    elif suffix == "M":
        multiplier = 1_000_000.0
    elif suffix == "G":
        multiplier = 1_000_000_000.0
    return int(number * multiplier * 1000.0)


def write_progress_snapshot(progress_path: Path, line: str) -> None:
    match = PROGRESS_LINE_RE.search(line.strip())
    if not match:
        return
    payload = {
        "progress_percent": int(match.group("percent")),
        "sent_total": int(match.group("sent")),
        "recv_total": int(match.group("recv")),
        "probe_rate_millis": parse_rate_to_millis(match.group("send_rate")),
        "average_probe_rate_millis": parse_rate_to_millis(match.group("avg_send_rate")),
        "receive_rate_millis": parse_rate_to_millis(match.group("recv_rate")),
    }
    tmp_path = progress_path.with_suffix(progress_path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload))
    tmp_path.replace(progress_path)


def stream_stderr(child: subprocess.Popen[bytes], progress_path: Path, stderr_buffer: bytearray) -> None:
    assert child.stderr is not None
    current = ""
    while True:
        chunk = os.read(child.stderr.fileno(), 4096)
        if not chunk:
            break
        stderr_buffer.extend(chunk)
        current += chunk.decode("utf-8", errors="replace")
        write_progress_snapshot(progress_path, current)
        parts = re.split(r"[\r\n]", current)
        current = parts.pop() if parts else ""
        for part in parts:
            line = part.strip()
            if line:
                write_progress_snapshot(progress_path, line)
    line = current.strip()
    if line:
        write_progress_snapshot(progress_path, line)


def parse_target_range(target_range: str) -> tuple[int, int] | None:
    trimmed = target_range.strip()
    if not trimmed:
        return None
    if "/" in trimmed:
        try:
            network = ipaddress.ip_network(trimmed, strict=False)
        except ValueError:
            return None
        if network.version != 4:
            return None
        return int(network.network_address), int(network.broadcast_address)
    if "-" in trimmed:
        start_text, end_text = trimmed.split("-", 1)
        try:
            start = ipaddress.IPv4Address(start_text.strip())
            end = ipaddress.IPv4Address(end_text.strip())
        except ipaddress.AddressValueError:
            return None
        start_value = int(start)
        end_value = int(end)
        if start_value > end_value:
            return None
        return start_value, end_value
    try:
        address = ipaddress.IPv4Address(trimmed)
    except ipaddress.AddressValueError:
        return None
    value = int(address)
    return value, value


def parse_scanner_interfaces(value: str | None) -> list[str]:
    """Parse a comma/whitespace-separated NIC list, dedup, preserve order.

    Empty entries are dropped silently. Used by the multi-NIC orchestration
    parent to decide whether to fan out across ENIs; a single entry is
    treated as legacy single-NIC mode and the parent does not engage.
    """

    if value is None:
        return []
    seen: set[str] = set()
    result: list[str] = []
    for chunk in value.replace(";", ",").split(","):
        for token in chunk.split():
            iface = token.strip()
            if not iface or iface in seen:
                continue
            seen.add(iface)
            result.append(iface)
    return result


def cap_concurrent_subprocesses(
    interfaces: list[str], *, max_concurrent: int
) -> list[str]:
    """Truncate the per-shard interface list to ``max_concurrent`` entries.

    The kernel TX path saturates well below the per-NIC ENA spec on
    c6in.metal — anygpt-4 saw 4-NIC sustain 12.8M aggregate while 8-NIC
    cratered to 1.3M because the extra shards CPU-starved the originals.
    Capping the active shard count below the available NIC count keeps
    the working set inside the kernel sweet spot. ``max_concurrent`` of 0
    or negative disables the cap entirely so test harnesses can exercise
    the unbounded path.
    """

    if max_concurrent <= 0:
        return list(interfaces)
    return list(interfaces[:max_concurrent])


def format_target_range(start: int, end: int) -> str:
    """Render an IPv4 [start, end] inclusive range using the scanner's accepted forms.

    Single host -> bare address. Wider ranges use the dashed-IP format the
    scanner already accepts (the same form the API emits when sharding via
    split_port_scan_target_range in dragonfly_store.rs).
    """

    start_ip = ipaddress.IPv4Address(start)
    end_ip = ipaddress.IPv4Address(end)
    if start == end:
        return str(start_ip)
    return f"{start_ip}-{end_ip}"


def split_target_range_for_shards(target_range: str, shard_count: int) -> list[str]:
    """Split an IPv4 target range into roughly equal sub-ranges.

    Mirrors the algorithm in src/dragonfly_store.rs::split_port_scan_target_range
    so a single worker fans out the same way the control plane already does
    across workers. When the input cannot be parsed we fall back to a single
    entry so the caller can pass it through unchanged; same for shard_count
    <= 1 or a range smaller than the requested shard count.
    """

    bounds = parse_target_range(target_range)
    trimmed = target_range.strip()
    if bounds is None:
        return [trimmed]
    start, end = bounds
    if shard_count <= 1 or start >= end:
        return [format_target_range(start, end)]
    total_hosts = end - start + 1
    shard_total = max(1, min(shard_count, total_hosts))
    if shard_total <= 1:
        return [format_target_range(start, end)]
    base_hosts = total_hosts // shard_total
    remainder = total_hosts % shard_total
    cursor = start
    shards: list[str] = []
    for index in range(shard_total):
        shard_size = base_hosts + (1 if index < remainder else 0)
        shard_start = cursor
        shard_end = cursor + shard_size - 1
        shards.append(format_target_range(shard_start, shard_end))
        cursor = shard_end + 1
    return shards


def parse_requested_ports(ports: str) -> set[int]:
    requested: set[int] = set()
    for chunk in ports.split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        if '-' in chunk:
            start_text, end_text = chunk.split('-', 1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                start, end = end, start
            requested.update(range(start, end + 1))
            continue
        requested.add(int(chunk))
    return {port for port in requested if 0 < port < 65536}


def normalized_endpoint(line: str) -> tuple[str, int | None] | None:
    token = line.strip().split()[0] if line.strip() else ""
    if not token:
        return None

    if token.count(":") == 1:
        host, port = token.rsplit(":", 1)
        try:
            address = ipaddress.ip_address(host)
            port_number = int(port)
        except ValueError:
            return None
        if address.version != 4 or not 0 < port_number < 65536:
            return None
        return str(address), port_number

    try:
        address = ipaddress.ip_address(token)
    except ValueError:
        return None
    if address.version != 4:
        return None
    return str(address), None


def emit_endpoints(raw_output: str, target_range: str, requested_ports: str) -> None:
    allowed_range = parse_target_range(target_range)
    allowed_ports = parse_requested_ports(requested_ports)
    single_port = next(iter(allowed_ports)) if len(allowed_ports) == 1 else None
    emitted: set[str] = set()
    for line in raw_output.splitlines():
        endpoint = normalized_endpoint(line)
        if endpoint is None:
            continue
        host, port = endpoint
        host_value = int(ipaddress.IPv4Address(host))
        if allowed_range is not None and not (allowed_range[0] <= host_value <= allowed_range[1]):
            continue
        if port is None:
            if single_port is None:
                continue
            normalized = host
        else:
            if allowed_ports and port not in allowed_ports:
                continue
            normalized = f"{host}:{port}"
        if normalized in emitted:
            continue
        emitted.add(normalized)
        print(normalized)


def terminate_current_child(sig: int) -> None:
    global CURRENT_CHILD
    child = CURRENT_CHILD
    if child is None or child.poll() is not None:
        return
    try:
        os.killpg(child.pid, sig)
    except ProcessLookupError:
        return


def handle_termination(signum: int, _frame: object) -> "None":
    terminate_current_child(signal.SIGTERM)
    _terminate_child_adapters(signal.SIGTERM)
    raise SystemExit(128 + signum)


def _set_current_child(child: subprocess.Popen[bytes] | None) -> None:
    global CURRENT_CHILD
    CURRENT_CHILD = child


def run_static_scanner(
    invocation: dict[str, object],
    output_path: Path,
    progress_path: Path,
) -> tuple[int, str, str]:
    """Original single-spawn flow used when dynamic rate adjustment is off."""

    command = build_command(invocation, output_path)
    child = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        bufsize=0,
        start_new_session=True,
    )
    _set_current_child(child)
    stderr_buffer = bytearray()
    stderr_thread = threading.Thread(
        target=stream_stderr,
        args=(child, progress_path, stderr_buffer),
        daemon=True,
    )
    stderr_thread.start()
    assert child.stdout is not None
    stdout = child.stdout.read().decode("utf-8", errors="replace")
    return_code = child.wait()
    stderr_thread.join(timeout=5)
    stderr = stderr_buffer.decode("utf-8", errors="replace")
    _set_current_child(None)
    return return_code, stdout, stderr


def run_dynamic_scanner(
    invocation: dict[str, object],
    output_path: Path,
    progress_path: Path,
) -> tuple[int, str, str]:
    """AIMD-driven controller: respawns the scanner per window with a learned rate.

    Each window the scanner runs against its full target range with
    ``--checkpoint-file`` + (after window 1) ``--resume``. Per-window kernel
    NIC counters drive the AIMD math; the scheduler-jitter probe acts as a
    proxy for control-plane heartbeat slip — when zmap saturates the host
    the agentd heartbeat slips for the same reason this thread can't get
    CPU. Convergence settles within a handful of windows, after which the
    learned rate is persisted per-interface so future scans skip relearn.
    """

    if rate_controller is None:
        # Defensive fallback: bundle missing the controller module.
        return run_static_scanner(invocation, output_path, progress_path)

    env = os.environ
    policy = rate_controller.policy_from_env(env)
    interface = detect_default_interface()
    nic_reader = (
        rate_controller.NicStatsReader(interface) if interface is not None else None
    )
    system_load_reader = rate_controller.SystemLoadReader()
    fallback_rate = resolve_rate_limit(invocation)
    # Layer per-instance defaults underneath any explicit env knobs. The
    # detection short-circuits on ANYSCAN_INSTANCE_TYPE so a multi-NIC
    # parent that already detected once doesn't redo IMDS in every
    # child. apply_instance_defaults preserves operator overrides — env
    # knobs always win — and only fills in floor/ceiling/starting_rate
    # when the operator hasn't pinned them.
    instance_type = rate_controller.detect_instance_type(env=env)
    if instance_type:
        os.environ.setdefault("ANYSCAN_INSTANCE_TYPE", instance_type)
    policy, fallback_rate = rate_controller.apply_instance_defaults(
        policy=policy,
        fallback_rate=fallback_rate,
        instance_type=instance_type,
        env=env,
    )
    calibration_path = env_string("ANYSCAN_RATE_CALIBRATION_PATH") or str(
        rate_controller.DEFAULT_CALIBRATION_PATH
    )
    calibration = rate_controller.RateCalibrationStore(calibration_path)
    starting_rate = rate_controller.resolve_starting_rate(
        policy=policy,
        interface=interface,
        calibration=calibration,
        fallback_rate=fallback_rate,
    )

    rate_controller.emit_metric(
        "controller_started",
        {
            "interface": interface,
            "instance_type": instance_type,
            "starting_rate": starting_rate,
            "fallback_rate": fallback_rate,
            "policy_floor": policy.floor,
            "policy_ceiling": policy.ceiling,
            "additive_step": policy.additive_step,
            "multiplicative_factor": policy.multiplicative_factor,
            "window_seconds": policy.window_seconds,
            "heartbeat_threshold_ms": policy.heartbeat_latency_threshold_ms,
            "cpu_load_threshold": policy.cpu_load_threshold,
            "drop_ratio_threshold": policy.drop_ratio_threshold,
            "vcpu_count": system_load_reader.vcpu_count,
            "calibration_path": str(calibration.path),
        },
    )

    last_stderr_buffer = bytearray()
    stderr_thread_holder: dict[str, threading.Thread] = {}

    def spawn(command: list[str]) -> subprocess.Popen[bytes]:
        nonlocal last_stderr_buffer
        last_stderr_buffer = bytearray()
        child = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=False,
            bufsize=0,
            start_new_session=True,
        )
        stderr_thread = threading.Thread(
            target=stream_stderr,
            args=(child, progress_path, last_stderr_buffer),
            daemon=True,
        )
        stderr_thread.start()
        stderr_thread_holder["thread"] = stderr_thread
        return child

    def on_child(child: subprocess.Popen[bytes] | None) -> None:
        _set_current_child(child)
        if child is None:
            thread = stderr_thread_holder.pop("thread", None)
            if thread is not None:
                thread.join(timeout=5)

    def command_for_rate(rate: int, is_first_window: bool) -> list[str]:
        # First window: respect the upstream invocation's resume flag (the
        # worker may have already set it from the persisted store). Later
        # windows: always resume from the checkpoint we just wrote.
        resume_override = None if is_first_window else True
        return build_command(
            invocation,
            output_path,
            rate_override=rate,
            resume_override=resume_override,
        )

    jitter_monitor = rate_controller.JitterMonitor()
    jitter_monitor.start()
    return_code = 0
    try:
        runner = rate_controller.SubprocessWindowRunner(
            command_for_rate=command_for_rate,
            nic_reader=nic_reader,
            jitter_monitor=jitter_monitor,
            terminate_grace_seconds=rate_controller.DEFAULT_TERMINATE_GRACE_SECONDS,
            spawn=spawn,
            on_child=on_child,
        )
        controller = rate_controller.RateController(
            options=rate_controller.ControllerOptions(
                policy=policy,
                window_seconds=float(policy.window_seconds),
                interface=interface,
                starting_rate=starting_rate,
                calibration=calibration,
                system_load_reader=system_load_reader,
            ),
            runner=runner,
        )
        try:
            controller.run()
        except rate_controller.ScannerWindowError as error:
            return_code = error.exit_code if error.exit_code != 0 else 1
    finally:
        jitter_monitor.stop()
        on_child(None)

    stderr_text = last_stderr_buffer.decode("utf-8", errors="replace")
    return return_code, "", stderr_text


# ---------------------------------------------------------------------------
# Multi-NIC orchestration (Tier A)
#
# When ANYSCAN_SCANNER_INTERFACES lists more than one ENI we fan the
# invocation out into one child adapter process per interface. Each child
# runs the unmodified single-NIC code path with SCANNER_INTERFACE pinned
# to its own ENI; per-NIC AIMD calibration falls out for free because
# RateCalibrationStore is already keyed by interface name and each child
# observes its own /sys/class/net/<iface>/statistics counters.
#
# Background:
# A single AF_PACKET socket caps around 3M pps under the bundled scanner
# (anygpt-24 c6in.metal bench) because of per-socket TX lock contention;
# c6in.metal has 8 ENAs available with an aggregate ENA spec of ~14M pps,
# so going parallel across NICs is the only way to recover that headroom
# without a kernel-bypass change. The orchestrator does NOT touch the
# scanner binary or AIMD math — it is pure Python fan-out plus output
# stitching.
# ---------------------------------------------------------------------------


CHILD_ADAPTER_PROCESSES: list[subprocess.Popen[bytes]] = []
CHILD_ADAPTER_PROCESSES_LOCK = threading.Lock()


def _register_child_process(child: subprocess.Popen[bytes]) -> None:
    with CHILD_ADAPTER_PROCESSES_LOCK:
        CHILD_ADAPTER_PROCESSES.append(child)


def _unregister_child_process(child: subprocess.Popen[bytes]) -> None:
    with CHILD_ADAPTER_PROCESSES_LOCK:
        try:
            CHILD_ADAPTER_PROCESSES.remove(child)
        except ValueError:
            pass


def _terminate_child_adapters(sig: int) -> None:
    with CHILD_ADAPTER_PROCESSES_LOCK:
        children = list(CHILD_ADAPTER_PROCESSES)
    for child in children:
        if child.poll() is not None:
            continue
        try:
            os.killpg(child.pid, sig)
        except (ProcessLookupError, PermissionError):
            try:
                if sig == signal.SIGKILL:
                    child.kill()
                else:
                    child.terminate()
            except Exception:  # noqa: BLE001 - best-effort propagation
                pass


def build_shard_invocation(
    parent_invocation: dict[str, object],
    *,
    shard_target_range: str,
    shard_output_path: Path,
    shard_checkpoint_path: Path | None,
) -> dict[str, object]:
    """Clone the parent invocation with per-shard target/output overrides."""

    shard = dict(parent_invocation)
    shard["target_range"] = shard_target_range
    shard["output_path"] = str(shard_output_path)
    if shard_checkpoint_path is not None:
        shard["checkpoint_path"] = str(shard_checkpoint_path)
    return shard


def _spawn_shard_adapter(
    invocation: dict[str, object],
    *,
    interface: str,
    stderr_log: Path,
) -> subprocess.Popen[bytes]:
    env = os.environ.copy()
    # Pin the child to a single NIC and clear the multi-NIC list so the
    # child does not try to fan out again. Both knobs MUST be set: the
    # cleared list is what makes the child fall through to the legacy
    # single-NIC path; the pinned interface is what the scanner inherits
    # via the existing SCANNER_INTERFACE -> --interface mapping.
    env["SCANNER_INTERFACE"] = interface
    env["ANYSCAN_SCANNER_INTERFACES"] = ""
    # Mark the child so journal readers can correlate per-shard metrics
    # back to the parent fan-out without parsing pid trees.
    env["ANYSCAN_SCANNER_SHARD_INTERFACE"] = interface
    # Tell the child it is a shard so it skips the legacy
    # emit_endpoints + output_path.unlink() finally cleanup. The parent
    # owns the merged output: deduping + filtering happens once on the
    # union, and the parent reaps the temp work dir at the end. Without
    # this flag the child would print its own endpoints to its own
    # stdout (we point it at /dev/null) AND delete its per-shard output
    # file, leaving the parent with nothing to merge.
    env["ANYSCAN_ADAPTER_SHARD_MODE"] = "true"

    command = [sys.executable, str(Path(__file__).resolve())]
    stderr_handle = open(stderr_log, "wb")
    try:
        child = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=stderr_handle,
            env=env,
            start_new_session=True,
        )
    except Exception:
        stderr_handle.close()
        raise
    finally:
        # The child takes over the fd via dup; close our copy so EOF
        # reaches the reader when the child exits.
        stderr_handle.close()
    assert child.stdin is not None
    try:
        child.stdin.write(json.dumps(invocation).encode("utf-8"))
    finally:
        child.stdin.close()
    return child


def run_multi_nic_scanner(
    invocation: dict[str, object],
    output_path: Path,
    interfaces: list[str],
) -> int:
    """Fan out one adapter child per ENI and stitch the results.

    Returns an exit code suitable for the adapter to surface to the worker.
    Per-shard stderr logs are mirrored to the parent stderr at the end so
    operators see all rate-controller telemetry in one journal stream.
    """

    requested_interfaces = list(interfaces)
    max_concurrent = env_int(
        "ANYSCAN_RATE_MAX_CONCURRENT_SUBPROCESSES",
        DEFAULT_MAX_CONCURRENT_SUBPROCESSES,
    )
    interfaces = cap_concurrent_subprocesses(
        requested_interfaces, max_concurrent=max_concurrent
    )
    target_range = require_string(invocation, "target_range")
    shards = split_target_range_for_shards(target_range, len(interfaces))
    if len(shards) < len(interfaces):
        # Range was smaller than the interface count; trim interfaces to
        # match shards and let the unused NICs sit idle for this scan
        # rather than spawning empty children.
        interfaces = interfaces[: len(shards)]

    # Detect once at the parent so each shard child inherits the resolved
    # type via ANYSCAN_INSTANCE_TYPE without redoing the IMDS round-trip.
    if rate_controller is not None:
        instance_type = rate_controller.detect_instance_type(env=os.environ)
        if instance_type:
            os.environ.setdefault("ANYSCAN_INSTANCE_TYPE", instance_type)
    else:
        instance_type = None

    if rate_controller is not None:
        rate_controller.emit_metric(
            "multi_nic_orchestration_started",
            {
                "interfaces": interfaces,
                "requested_interfaces": requested_interfaces,
                "shard_count": len(shards),
                "max_concurrent": max_concurrent,
                "instance_type": instance_type,
                "target_range": target_range,
            },
        )

    work_dir = Path(tempfile.mkdtemp(prefix="anyscan-multi-nic-"))
    children: list[tuple[subprocess.Popen[bytes], Path, Path, str]] = []
    return_code = 0
    try:
        for index, (iface, shard_target_range) in enumerate(zip(interfaces, shards)):
            shard_output = work_dir / f"shard-{index}-{iface}.out"
            shard_output.parent.mkdir(parents=True, exist_ok=True)
            shard_output.touch()
            # Each shard gets its own checkpoint so resume after a crash
            # does not cross-contaminate the per-NIC iteration offsets.
            parent_checkpoint = invocation.get("checkpoint_path")
            if isinstance(parent_checkpoint, str) and parent_checkpoint.strip():
                shard_checkpoint: Path | None = Path(
                    f"{parent_checkpoint.strip()}.shard-{index}"
                )
            else:
                shard_checkpoint = work_dir / f"shard-{index}-{iface}.checkpoint"
            shard_invocation = build_shard_invocation(
                invocation,
                shard_target_range=shard_target_range,
                shard_output_path=shard_output,
                shard_checkpoint_path=shard_checkpoint,
            )
            shard_stderr = work_dir / f"shard-{index}-{iface}.stderr"
            child = _spawn_shard_adapter(
                shard_invocation,
                interface=iface,
                stderr_log=shard_stderr,
            )
            _register_child_process(child)
            children.append((child, shard_output, shard_stderr, iface))

        for child, _shard_output, _shard_stderr, iface in children:
            try:
                exit_code = child.wait()
            except KeyboardInterrupt:
                _terminate_child_adapters(signal.SIGTERM)
                exit_code = 128 + signal.SIGTERM
            finally:
                _unregister_child_process(child)
            if exit_code != 0 and return_code == 0:
                return_code = exit_code
                # First-failure wins; tear down the rest so we surface the
                # actual error fast instead of waiting for all stragglers.
                _terminate_child_adapters(signal.SIGTERM)

        # Stitch each shard's output file into the parent output_path. We
        # do this even on partial failure so any endpoints already
        # discovered by the surviving shards are not lost.
        with open(output_path, "wb") as merged:
            for _child, shard_output, _shard_stderr, _iface in children:
                if not shard_output.exists():
                    continue
                with open(shard_output, "rb") as handle:
                    while True:
                        chunk = handle.read(65536)
                        if not chunk:
                            break
                        merged.write(chunk)

        # Surface child stderr so journal-based debugging keeps working
        # exactly like the single-NIC path. Prefix each line with the
        # iface so operators can tell shards apart in the journal.
        for _child, _shard_output, shard_stderr, iface in children:
            if not shard_stderr.exists():
                continue
            try:
                payload = shard_stderr.read_text(errors="replace")
            except OSError:
                continue
            for line in payload.splitlines():
                if line.strip():
                    print(f"[shard {iface}] {line}", file=sys.stderr)
    finally:
        # Reap any leftover children so the parent never returns with
        # zombies attached to the agentd worker process.
        _terminate_child_adapters(signal.SIGKILL)
        with CHILD_ADAPTER_PROCESSES_LOCK:
            CHILD_ADAPTER_PROCESSES.clear()
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
        except OSError:
            pass

    return return_code


def main() -> int:
    try:
        invocation = json.load(sys.stdin)
    except json.JSONDecodeError as error:
        fail(f"invalid scanner adapter invocation json: {error}")

    if not isinstance(invocation, dict):
        fail("scanner adapter invocation must be a json object")

    output_name = invocation.get("output_path")
    if isinstance(output_name, str) and output_name.strip():
        output_path = Path(output_name.strip())
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.touch(exist_ok=True)
    else:
        output_fd, output_name = tempfile.mkstemp(prefix="exposure-vulnscanner-", suffix=".out")
        os.close(output_fd)
        output_path = Path(output_name)
    progress_path = progress_path_for_output(output_path)
    checkpoint_path = checkpoint_path_for_output(output_path)
    signal.signal(signal.SIGTERM, handle_termination)
    signal.signal(signal.SIGINT, handle_termination)

    multi_nic_interfaces = parse_scanner_interfaces(env_string("ANYSCAN_SCANNER_INTERFACES"))
    multi_nic_enabled = len(multi_nic_interfaces) > 1

    if multi_nic_enabled:
        try:
            return_code = run_multi_nic_scanner(
                invocation, output_path, multi_nic_interfaces
            )
            if return_code != 0:
                return return_code
            raw_output = output_path.read_text() if output_path.exists() else ""
            emit_endpoints(
                raw_output,
                require_string(invocation, "target_range"),
                require_string(invocation, "ports"),
            )
            return 0
        finally:
            _terminate_child_adapters(signal.SIGKILL)
            checkpoint_path.unlink(missing_ok=True)
            progress_path.unlink(missing_ok=True)
            output_path.unlink(missing_ok=True)

    dynamic_enabled = env_flag("ANYSCAN_DYNAMIC_RATE_ENABLED", default=True) and (
        rate_controller is not None
    )
    # Shard children skip post-processing (emit_endpoints + unlink) so
    # the multi-NIC parent can merge their raw output files and dedupe
    # the union exactly once. See run_multi_nic_scanner.
    shard_mode = env_flag("ANYSCAN_ADAPTER_SHARD_MODE")

    try:
        if dynamic_enabled:
            return_code, stdout, stderr = run_dynamic_scanner(
                invocation, output_path, progress_path
            )
        else:
            return_code, stdout, stderr = run_static_scanner(
                invocation, output_path, progress_path
            )

        if return_code != 0:
            stderr = stderr.strip()
            stdout = stdout.strip()
            detail = stderr or stdout or "unknown scanner failure"
            print(detail, file=sys.stderr)
            return return_code

        if shard_mode:
            stderr = stderr.strip()
            if stderr:
                print(stderr, file=sys.stderr)
            return 0

        raw_output = output_path.read_text() if output_path.exists() else stdout
        emit_endpoints(
            raw_output,
            require_string(invocation, "target_range"),
            require_string(invocation, "ports"),
        )

        stderr = stderr.strip()
        if stderr:
            print(stderr, file=sys.stderr)
        return 0
    finally:
        terminate_current_child(signal.SIGKILL)
        checkpoint_path.unlink(missing_ok=True)
        progress_path.unlink(missing_ok=True)
        if not shard_mode:
            output_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
