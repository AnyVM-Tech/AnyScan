"""AIMD-based dynamic port-scan rate controller.

Drives a single zmap-style ``--rate`` value through an additive-increase /
multiplicative-decrease loop so each worker self-tunes to its natural pps
ceiling. Stateless math lives in :func:`compute_next_rate` and
:func:`classify_window`; runtime orchestration sits in :class:`RateController`.

Bench facts that motivate the policy (see PR #55):
* rate=100k achieved 175k (cap cosmetic below natural)
* rate=1M achieved 1.76M (sweet spot)
* rate=2M achieved 2.22M (max)
* rate=5M achieved 1.59M (rate-limit overhead hurts)

So the ceiling is set well above the sweet spot and the floor well below it,
and we respawn the scanner per window via the existing checkpoint+resume
flow. PR #28's tc reservation guarantees the control plane keeps a
5 Mbit/s slice regardless of where AIMD lands.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Iterable, Mapping, Optional


DEFAULT_FLOOR = 100_000
DEFAULT_CEILING = 4_000_000
DEFAULT_ADDITIVE_STEP = 200_000
DEFAULT_MULTIPLICATIVE_FACTOR = 0.5
DEFAULT_WINDOW_SECONDS = 30
DEFAULT_HEARTBEAT_LATENCY_THRESHOLD_MS = 5_000
DEFAULT_ACHIEVED_RATIO_FLOOR = 0.9
DEFAULT_CALIBRATION_PATH = Path("/var/lib/agentd/rate-calibration.json")
DEFAULT_TERMINATE_GRACE_SECONDS = 5

CLEAN = "clean"
SLIP = "slip"


@dataclass(frozen=True)
class AimdPolicy:
    """Knobs for the AIMD loop."""

    floor: int = DEFAULT_FLOOR
    ceiling: int = DEFAULT_CEILING
    additive_step: int = DEFAULT_ADDITIVE_STEP
    multiplicative_factor: float = DEFAULT_MULTIPLICATIVE_FACTOR
    achieved_ratio_floor: float = DEFAULT_ACHIEVED_RATIO_FLOOR
    heartbeat_latency_threshold_ms: int = DEFAULT_HEARTBEAT_LATENCY_THRESHOLD_MS
    window_seconds: int = DEFAULT_WINDOW_SECONDS

    def __post_init__(self) -> None:
        if self.floor <= 0:
            raise ValueError("floor must be > 0")
        if self.ceiling < self.floor:
            raise ValueError("ceiling must be >= floor")
        if self.additive_step <= 0:
            raise ValueError("additive_step must be > 0")
        if not 0.0 < self.multiplicative_factor < 1.0:
            raise ValueError("multiplicative_factor must be in (0, 1)")
        if not 0.0 < self.achieved_ratio_floor <= 1.0:
            raise ValueError("achieved_ratio_floor must be in (0, 1]")
        if self.heartbeat_latency_threshold_ms <= 0:
            raise ValueError("heartbeat_latency_threshold_ms must be > 0")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")


@dataclass(frozen=True)
class WindowMeasurement:
    """What we observed during a single window."""

    set_rate: int
    elapsed_seconds: float
    tx_packets_delta: int
    tx_dropped_delta: int
    heartbeat_max_latency_ms: int
    scanner_finished_naturally: bool = False
    scanner_exit_code: int = 0
    # When False, tx_packets_delta/tx_dropped_delta are not real
    # measurements (NIC counters were unavailable, e.g. /sys/class/net was
    # masked or the interface couldn't be detected). The classifier must
    # not gate on the achieved-ratio or drops when this is False or every
    # window will be marked SLIP and the controller will hammer down to
    # the floor rate.
    nic_stats_available: bool = True

    @property
    def achieved_pps(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return float(self.tx_packets_delta) / float(self.elapsed_seconds)


class ScannerWindowError(RuntimeError):
    """The scanner exited mid-window with a non-zero status."""

    def __init__(self, exit_code: int, *, window_index: int, set_rate: int) -> None:
        super().__init__(
            f"scanner exited unexpectedly during window {window_index} "
            f"(rate={set_rate}, code={exit_code})"
        )
        self.exit_code = exit_code
        self.window_index = window_index
        self.set_rate = set_rate


def classify_window(
    measurement: WindowMeasurement,
    policy: AimdPolicy,
) -> str:
    """Return ``CLEAN`` or ``SLIP`` for the supplied window measurement.

    A window is clean iff the kernel is not dropping packets, the host can
    still service its own scheduler (no heartbeat slip), and the scanner is
    actually consuming the rate budget we set. The achieved-rate floor is
    skipped when the scanner finished naturally inside the window because
    that means it ran out of targets, not throttle.

    When ``nic_stats_available`` is False the NIC counter deltas carry no
    information, so we skip the drops check and the achieved-ratio check
    and rely on the scheduler-jitter signal alone — otherwise zero-deltas
    would force every window to SLIP.
    """

    if measurement.nic_stats_available and measurement.tx_dropped_delta > 0:
        return SLIP
    if measurement.heartbeat_max_latency_ms > policy.heartbeat_latency_threshold_ms:
        return SLIP
    if measurement.scanner_finished_naturally:
        return CLEAN
    if not measurement.nic_stats_available:
        return CLEAN
    threshold = policy.achieved_ratio_floor * float(measurement.set_rate)
    if measurement.achieved_pps + 1e-9 < threshold:
        return SLIP
    return CLEAN


def compute_next_rate(
    policy: AimdPolicy,
    current_rate: int,
    measurement: WindowMeasurement,
) -> int:
    """Return the rate to use for the next window.

    Clean -> additive bump capped at ceiling. Slip -> multiplicative shrink
    floored at policy.floor. Clamped on both sides regardless of the
    starting point so a misconfigured ``current_rate`` cannot escape the
    bounds.
    """

    classification = classify_window(measurement, policy)
    if classification == CLEAN:
        proposed = current_rate + policy.additive_step
    else:
        proposed = int(current_rate * policy.multiplicative_factor)
    return clamp_rate(proposed, policy)


def clamp_rate(rate: int, policy: AimdPolicy) -> int:
    if rate < policy.floor:
        return policy.floor
    if rate > policy.ceiling:
        return policy.ceiling
    return rate


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


@dataclass
class CalibrationEntry:
    learned_rate: int
    updated_at: str


class RateCalibrationStore:
    """Thin JSON-on-disk persistence for per-interface learned rates.

    Keeps state across scans so a freshly dispatched worker doesn't have to
    re-discover its ceiling on every job. Writes go through a tempfile +
    atomic rename so a half-written file can never be observed.
    """

    SCHEMA_VERSION = 1

    def __init__(self, path: os.PathLike[str] | str = DEFAULT_CALIBRATION_PATH) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> dict[str, CalibrationEntry]:
        try:
            raw = self._path.read_text()
        except FileNotFoundError:
            return {}
        except OSError:
            return {}
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if not isinstance(payload, dict):
            return {}
        interfaces = payload.get("interfaces")
        if not isinstance(interfaces, dict):
            return {}
        out: dict[str, CalibrationEntry] = {}
        for key, value in interfaces.items():
            if not isinstance(key, str) or not isinstance(value, dict):
                continue
            rate = value.get("learned_rate")
            updated_at = value.get("updated_at", "")
            if isinstance(rate, int) and rate > 0 and isinstance(updated_at, str):
                out[key] = CalibrationEntry(rate, updated_at)
        return out

    def lookup(self, interface: str) -> Optional[CalibrationEntry]:
        return self.load().get(interface)

    def store(self, interface: str, learned_rate: int, *, now_iso: Optional[str] = None) -> None:
        if learned_rate <= 0:
            return
        entries = self.load()
        timestamp = now_iso if now_iso is not None else _utc_now_iso()
        entries[interface] = CalibrationEntry(learned_rate, timestamp)
        payload = {
            "version": self.SCHEMA_VERSION,
            "interfaces": {
                key: {"learned_rate": entry.learned_rate, "updated_at": entry.updated_at}
                for key, entry in entries.items()
            },
        }
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return
        tmp_path = self._path.with_suffix(self._path.suffix + ".tmp")
        try:
            tmp_path.write_text(json.dumps(payload, sort_keys=True))
            os.replace(tmp_path, self._path)
        except OSError:
            try:
                tmp_path.unlink()
            except OSError:
                pass


def _utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# Scheduler-jitter heartbeat probe
# ---------------------------------------------------------------------------


class JitterMonitor:
    """Background thread that measures Python scheduler jitter.

    When zmap saturates the host the Python interpreter (and agentd, which
    shares the same kernel scheduling) gets less wall-clock per second. The
    monitor wakes at a fixed cadence and records the largest gap it
    observed; a gap that exceeds the AIMD heartbeat threshold is the
    canonical signal that the control plane will start missing
    heartbeats too.

    Not a perfect proxy for an actual control-plane RTT measurement, but
    much cheaper, and aligns directly with the failure mode we care about
    (host CPU starvation from over-rated zmap).
    """

    def __init__(self, *, interval_seconds: float = 0.05) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        self._interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._max_gap_seconds = 0.0
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        thread = threading.Thread(target=self._run, name="jitter-monitor", daemon=True)
        self._thread = thread
        thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2.0)
        self._thread = None

    def reset(self) -> None:
        with self._lock:
            self._max_gap_seconds = 0.0

    def max_gap_ms(self) -> int:
        with self._lock:
            return int(self._max_gap_seconds * 1000.0)

    def _run(self) -> None:
        last = time.monotonic()
        while not self._stop.is_set():
            self._stop.wait(self._interval_seconds)
            now = time.monotonic()
            gap = now - last
            last = now
            with self._lock:
                if gap > self._max_gap_seconds:
                    self._max_gap_seconds = gap


# ---------------------------------------------------------------------------
# NIC stats
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NicCounters:
    tx_packets: int
    tx_dropped: int


class NicStatsReader:
    """Reads tx_packets/tx_dropped counters from /sys/class/net/<iface>/statistics.

    Wrapped in an object so tests can supply a synthetic counter source.
    """

    def __init__(self, interface: str, *, root: os.PathLike[str] | str = "/sys/class/net") -> None:
        self._interface = interface
        self._root = Path(root)

    def read(self) -> NicCounters:
        return NicCounters(
            tx_packets=self._read_counter("tx_packets"),
            tx_dropped=self._read_counter("tx_dropped"),
        )

    def _read_counter(self, name: str) -> int:
        try:
            raw = (self._root / self._interface / "statistics" / name).read_text()
        except OSError:
            return 0
        try:
            return int(raw.strip())
        except ValueError:
            return 0


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------


METRIC_PREFIX = "[anyscan-rate-controller]"


def emit_metric(event: str, payload: Mapping[str, object], *, sink=sys.stderr) -> None:
    """Emit a single structured telemetry line.

    journalctl + a simple grep is enough to follow convergence per scan; an
    out-of-band metrics scraper can also pick these up by matching the
    prefix. We deliberately keep this stderr-only so adapter stdout remains
    the pure scan-result channel agentd already consumes.
    """

    record: dict[str, object] = {"event": event}
    for key, value in payload.items():
        record[key] = value
    print(f"{METRIC_PREFIX} metric={json.dumps(record, sort_keys=True)}", file=sink)


# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------


@dataclass
class WindowReport:
    index: int
    set_rate: int
    measurement: WindowMeasurement
    classification: str
    next_rate: int


@dataclass
class ControllerOptions:
    policy: AimdPolicy
    window_seconds: float
    interface: Optional[str]
    starting_rate: int
    calibration: Optional[RateCalibrationStore]
    persist_on_clean: bool = True
    terminate_grace_seconds: float = DEFAULT_TERMINATE_GRACE_SECONDS


class WindowRunner:
    """Runs a single window of the scanner subprocess.

    Default implementation is a thin protocol the controller drives; tests
    inject a deterministic stub to assert convergence without spawning the
    real scanner.
    """

    def run(
        self,
        *,
        rate: int,
        window_seconds: float,
        is_first_window: bool,
    ) -> WindowMeasurement:
        raise NotImplementedError


class RateController:
    """Drives the spawn-measure-respawn loop and AIMD math."""

    def __init__(
        self,
        options: ControllerOptions,
        runner: WindowRunner,
        *,
        log_sink=sys.stderr,
        max_windows: Optional[int] = None,
    ) -> None:
        self._options = options
        self._runner = runner
        self._log_sink = log_sink
        self._max_windows = max_windows

    def run(self) -> list[WindowReport]:
        rate = clamp_rate(self._options.starting_rate, self._options.policy)
        reports: list[WindowReport] = []
        max_clean_rate = 0
        idx = 0
        while True:
            idx += 1
            if self._max_windows is not None and idx > self._max_windows:
                break
            measurement = self._runner.run(
                rate=rate,
                window_seconds=self._options.window_seconds,
                is_first_window=idx == 1,
            )
            # Distinguish "scanner finished and exited cleanly" from
            # "scanner crashed mid-window". The former is success and stops
            # the loop; the latter is a hard failure that must propagate so
            # we don't quietly respawn into the same broken state.
            if (
                not measurement.scanner_finished_naturally
                and measurement.scanner_exit_code != 0
                and measurement.elapsed_seconds < self._options.window_seconds
            ):
                raise ScannerWindowError(
                    measurement.scanner_exit_code,
                    window_index=idx,
                    set_rate=rate,
                )
            classification = classify_window(measurement, self._options.policy)
            next_rate = compute_next_rate(self._options.policy, rate, measurement)
            report = WindowReport(
                index=idx,
                set_rate=rate,
                measurement=measurement,
                classification=classification,
                next_rate=next_rate,
            )
            reports.append(report)
            emit_metric(
                "rate_adjustment",
                {
                    "window": idx,
                    "set_rate": rate,
                    "achieved_pps": int(measurement.achieved_pps),
                    "tx_dropped_delta": measurement.tx_dropped_delta,
                    "heartbeat_max_latency_ms": measurement.heartbeat_max_latency_ms,
                    "scanner_finished_naturally": measurement.scanner_finished_naturally,
                    "classification": classification,
                    "next_rate": next_rate,
                    "interface": self._options.interface,
                },
                sink=self._log_sink,
            )
            if classification == CLEAN and rate > max_clean_rate:
                max_clean_rate = rate
            if measurement.scanner_finished_naturally:
                break
            rate = next_rate

        if (
            self._options.persist_on_clean
            and self._options.calibration is not None
            and self._options.interface
            and max_clean_rate > 0
        ):
            try:
                self._options.calibration.store(self._options.interface, max_clean_rate)
            except Exception as error:  # noqa: BLE001 - best-effort persistence
                emit_metric(
                    "calibration_persist_failed",
                    {"interface": self._options.interface, "error": str(error)},
                    sink=self._log_sink,
                )
        return reports


# ---------------------------------------------------------------------------
# Subprocess-backed window runner used in production.
# ---------------------------------------------------------------------------


class SubprocessWindowRunner(WindowRunner):
    """Spawns the scanner once per window, gracefully terminates at the deadline.

    The scanner already supports ``--checkpoint-file`` + ``--resume`` so each
    respawn picks up exactly where the previous window left off (same
    iteration offset, no duplicated probes). The runner only orchestrates
    the lifecycle; rate selection lives in :class:`RateController`.
    """

    def __init__(
        self,
        *,
        command_for_rate: Callable[[int, bool], list[str]],
        nic_reader: Optional[NicStatsReader],
        jitter_monitor: JitterMonitor,
        terminate_grace_seconds: float,
        spawn: Callable[[list[str]], subprocess.Popen[bytes]],
        on_child: Callable[[Optional[subprocess.Popen[bytes]]], None] = lambda _: None,
    ) -> None:
        self._command_for_rate = command_for_rate
        self._nic_reader = nic_reader
        self._jitter_monitor = jitter_monitor
        self._terminate_grace_seconds = terminate_grace_seconds
        self._spawn = spawn
        self._on_child = on_child

    def run(
        self,
        *,
        rate: int,
        window_seconds: float,
        is_first_window: bool,
    ) -> WindowMeasurement:
        command = self._command_for_rate(rate, is_first_window)
        nic_available = self._nic_reader is not None
        nic_before = self._nic_reader.read() if nic_available else NicCounters(0, 0)
        self._jitter_monitor.reset()
        start_time = time.monotonic()
        child = self._spawn(command)
        self._on_child(child)
        finished_naturally = False
        try:
            try:
                child.wait(timeout=window_seconds)
                # Snapshot the active-send window AT exit time, not after
                # teardown — _terminate_process_tree's SIGINT grace period
                # would otherwise inflate the achieved-pps denominator and
                # falsely fail the achieved-ratio check.
                send_elapsed = time.monotonic() - start_time
                nic_after = (
                    self._nic_reader.read() if nic_available else NicCounters(0, 0)
                )
                finished_naturally = True
            except subprocess.TimeoutExpired:
                # Same reasoning: snapshot at the deadline before we begin
                # graceful shutdown, not after the SIGINT/SIGTERM handshake
                # completes. window_seconds is the rate budget we gave the
                # scanner; teardown isn't part of it.
                send_elapsed = time.monotonic() - start_time
                nic_after = (
                    self._nic_reader.read() if nic_available else NicCounters(0, 0)
                )
                _terminate_process_tree(child, self._terminate_grace_seconds)
        finally:
            self._on_child(None)
        tx_packets_delta = max(0, nic_after.tx_packets - nic_before.tx_packets)
        tx_dropped_delta = max(0, nic_after.tx_dropped - nic_before.tx_dropped)
        heartbeat_latency_ms = self._jitter_monitor.max_gap_ms()
        exit_code = child.returncode if child.returncode is not None else 0
        return WindowMeasurement(
            set_rate=rate,
            elapsed_seconds=send_elapsed,
            tx_packets_delta=tx_packets_delta,
            tx_dropped_delta=tx_dropped_delta,
            heartbeat_max_latency_ms=heartbeat_latency_ms,
            scanner_finished_naturally=finished_naturally and exit_code == 0,
            scanner_exit_code=exit_code,
            nic_stats_available=nic_available,
        )


def _terminate_process_tree(child: subprocess.Popen[bytes], grace_seconds: float) -> None:
    """Best-effort graceful shutdown of the scanner process group.

    The bundled scanner installs a SIGINT handler that flips ``stop_signal``
    and lets the engine fall through to its final ``save_scan_checkpoint``
    call. SIGTERM has no handler and just kills the process, so we send
    SIGINT first; the periodic 1s checkpoint thread guarantees that even a
    rude follow-up SIGTERM/SIGKILL won't lose more than the last ~1s of
    progress.
    """

    if child.poll() is not None:
        return
    import signal as _signal

    for sig in (_signal.SIGINT, _signal.SIGTERM, _signal.SIGKILL):
        try:
            os.killpg(child.pid, sig)
        except (ProcessLookupError, PermissionError):
            try:
                if sig == _signal.SIGKILL:
                    child.kill()
                else:
                    child.terminate()
            except Exception:  # noqa: BLE001 - best-effort
                pass
        try:
            child.wait(timeout=grace_seconds)
            return
        except subprocess.TimeoutExpired:
            continue


# ---------------------------------------------------------------------------
# Env helpers
# ---------------------------------------------------------------------------


def policy_from_env(env: Mapping[str, str]) -> AimdPolicy:
    return AimdPolicy(
        floor=_env_int(env, "ANYSCAN_RATE_FLOOR", DEFAULT_FLOOR),
        ceiling=_env_int(env, "ANYSCAN_RATE_CEILING", DEFAULT_CEILING),
        additive_step=_env_int(env, "ANYSCAN_RATE_ADDITIVE_STEP", DEFAULT_ADDITIVE_STEP),
        multiplicative_factor=_env_float(
            env,
            "ANYSCAN_RATE_MULTIPLICATIVE_FACTOR",
            DEFAULT_MULTIPLICATIVE_FACTOR,
        ),
        achieved_ratio_floor=_env_float(
            env,
            "ANYSCAN_RATE_ACHIEVED_RATIO_FLOOR",
            DEFAULT_ACHIEVED_RATIO_FLOOR,
        ),
        heartbeat_latency_threshold_ms=_env_int(
            env,
            "ANYSCAN_HEARTBEAT_LATENCY_THRESHOLD_MS",
            DEFAULT_HEARTBEAT_LATENCY_THRESHOLD_MS,
        ),
        window_seconds=_env_int(env, "ANYSCAN_RATE_WINDOW_SECONDS", DEFAULT_WINDOW_SECONDS),
    )


def _env_int(env: Mapping[str, str], key: str, default: int) -> int:
    value = env.get(key)
    if value is None or not value.strip():
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def _env_float(env: Mapping[str, str], key: str, default: float) -> float:
    value = env.get(key)
    if value is None or not value.strip():
        return default
    try:
        return float(value.strip())
    except ValueError:
        return default


def env_flag(env: Mapping[str, str], key: str, *, default: bool) -> bool:
    raw = env.get(key)
    if raw is None:
        return default
    value = raw.strip().lower()
    if not value:
        return default
    return value in {"1", "true", "yes", "on"}


def resolve_starting_rate(
    *,
    policy: AimdPolicy,
    interface: Optional[str],
    calibration: Optional[RateCalibrationStore],
    fallback_rate: int,
) -> int:
    if interface and calibration is not None:
        entry = calibration.lookup(interface)
        if entry is not None:
            return clamp_rate(entry.learned_rate, policy)
    return clamp_rate(fallback_rate, policy)


__all__ = [
    "AimdPolicy",
    "WindowMeasurement",
    "WindowReport",
    "ControllerOptions",
    "RateController",
    "RateCalibrationStore",
    "CalibrationEntry",
    "JitterMonitor",
    "NicStatsReader",
    "NicCounters",
    "SubprocessWindowRunner",
    "WindowRunner",
    "compute_next_rate",
    "classify_window",
    "clamp_rate",
    "policy_from_env",
    "env_flag",
    "resolve_starting_rate",
    "emit_metric",
    "DEFAULT_FLOOR",
    "DEFAULT_CEILING",
    "DEFAULT_ADDITIVE_STEP",
    "DEFAULT_MULTIPLICATIVE_FACTOR",
    "DEFAULT_WINDOW_SECONDS",
    "DEFAULT_HEARTBEAT_LATENCY_THRESHOLD_MS",
    "DEFAULT_ACHIEVED_RATIO_FLOOR",
    "DEFAULT_CALIBRATION_PATH",
    "CLEAN",
    "SLIP",
]
