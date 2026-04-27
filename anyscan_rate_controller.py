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

import fcntl
import json
import os
import re
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Iterable, Iterator, Mapping, Optional


DEFAULT_FLOOR = 100_000
DEFAULT_CEILING = 4_000_000
DEFAULT_ADDITIVE_STEP = 200_000
DEFAULT_MULTIPLICATIVE_FACTOR = 0.5
DEFAULT_WINDOW_SECONDS = 30
DEFAULT_HEARTBEAT_LATENCY_THRESHOLD_MS = 5_000
DEFAULT_ACHIEVED_RATIO_FLOOR = 0.9
DEFAULT_CALIBRATION_PATH = Path("/var/lib/agentd/rate-calibration.json")
DEFAULT_TERMINATE_GRACE_SECONDS = 5
# Loadavg / vcpu ratio above which we treat the host as CPU-saturated.
# A 1-min loadavg per vCPU >= 0.8 means the run-queue is sized close to
# the available CPUs; combined with a heartbeat-jitter signal that means
# our process is starved, not the NIC.
DEFAULT_CPU_LOAD_THRESHOLD = 0.8
# Below this drop ratio we treat the few packets the kernel dropped as
# noise rather than evidence of NIC saturation, so when CPU pressure is
# also present we attribute the slip to CPU. 0.001 = 0.1% of tx_packets.
DEFAULT_DROP_RATIO_THRESHOLD = 0.001
# Default DMI path Linux uses to expose the system product name. On AWS
# bare-metal hosts (c6in.metal et al) this often contains the actual
# instance type; on EC2 VMs it usually contains "Amazon EC2" and we have
# to fall back to IMDS for the type.
DEFAULT_DMI_PRODUCT_PATH = "/sys/devices/virtual/dmi/id/product_name"
DEFAULT_IMDS_TIMEOUT_SECONDS = 1.0

CLEAN = "clean"
# Network-side slip: kernel TX queue overflow, rate-limit overhead, or
# under-achieved rate without a CPU explanation. Response: shrink rate.
SLIP_NETWORK = "slip_network"
# Host-CPU starvation: heartbeat slip co-occurs with high loadavg/vcpu.
# Response: leave the rate alone — shrinking it does not free CPU and
# wastes the headroom we already converged to.
SLIP_CPU = "slip_cpu"
# Backwards-compatibility alias. The pre-PR controller only emitted a
# single SLIP value (semantically equivalent to SLIP_NETWORK), and
# external callers + tests still compare against it.
SLIP = SLIP_NETWORK


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
    cpu_load_threshold: float = DEFAULT_CPU_LOAD_THRESHOLD
    drop_ratio_threshold: float = DEFAULT_DROP_RATIO_THRESHOLD

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
        if self.cpu_load_threshold <= 0:
            raise ValueError("cpu_load_threshold must be > 0")
        if not 0.0 <= self.drop_ratio_threshold <= 1.0:
            raise ValueError("drop_ratio_threshold must be in [0, 1]")


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
    *,
    system_load: Optional["SystemLoad"] = None,
) -> str:
    """Return ``CLEAN``, ``SLIP_NETWORK``, or ``SLIP_CPU`` for a window.

    A window is clean iff the kernel is not dropping packets, the host can
    still service its own scheduler (no heartbeat slip), and the scanner is
    actually consuming the rate budget we set. The achieved-rate floor is
    skipped when the scanner finished naturally inside the window because
    that means it ran out of targets, not throttle.

    When ``system_load`` is supplied we further distinguish CPU-caused
    slips (heartbeat slip co-occurring with a saturated run-queue) from
    network-caused slips (kernel TX drops or rate-limit overhead). On CPU
    slips the controller leaves the rate alone — halving it would not
    free any CPU and would just waste the headroom we already learned.
    When ``system_load`` is None we keep the legacy "any slip is network"
    behavior so existing call sites and bundles without the loadavg
    reader keep their pre-improvement semantics.
    """

    network_drops = measurement.tx_dropped_delta > 0
    rate_starved = (
        not measurement.scanner_finished_naturally
        and measurement.achieved_pps + 1e-9
        < policy.achieved_ratio_floor * float(measurement.set_rate)
    )
    heartbeat_slip = (
        measurement.heartbeat_max_latency_ms > policy.heartbeat_latency_threshold_ms
    )

    if system_load is None:
        if network_drops or heartbeat_slip or rate_starved:
            return SLIP_NETWORK
        return CLEAN

    cpu_saturated = system_load.load_average_per_vcpu > policy.cpu_load_threshold
    cpu_pressure = cpu_saturated and heartbeat_slip
    network_pressure = network_drops or rate_starved or (heartbeat_slip and not cpu_saturated)

    if not cpu_pressure and not network_pressure:
        return CLEAN
    if cpu_pressure and not network_pressure:
        return SLIP_CPU
    if network_pressure and not cpu_pressure:
        return SLIP_NETWORK

    # Both signals firing — pick the dominant cause. A non-trivial drop
    # ratio means the NIC is genuinely overrun (shrink rate); pure
    # rate-starvation with no drops on a saturated host points at CPU
    # contention starving the scanner threads, not the wire.
    drop_ratio = (
        measurement.tx_dropped_delta / measurement.tx_packets_delta
        if measurement.tx_packets_delta > 0
        else 0.0
    )
    if drop_ratio > policy.drop_ratio_threshold:
        return SLIP_NETWORK
    return SLIP_CPU


def compute_next_rate(
    policy: AimdPolicy,
    current_rate: int,
    measurement: WindowMeasurement,
    *,
    system_load: Optional["SystemLoad"] = None,
) -> int:
    """Return the rate to use for the next window.

    Clean -> additive bump capped at ceiling. SLIP_NETWORK -> multiplicative
    shrink floored at policy.floor. SLIP_CPU -> rate is held; the right
    response is to shed subprocess concurrency (handled by the multi-NIC
    parent), not to crater the rate we already learned. Clamped on both
    sides regardless of the starting point so a misconfigured
    ``current_rate`` cannot escape the bounds.
    """

    classification = classify_window(measurement, policy, system_load=system_load)
    if classification == CLEAN:
        proposed = current_rate + policy.additive_step
    elif classification == SLIP_CPU:
        proposed = current_rate
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
    re-discover its ceiling on every job. Writes go through a per-pid
    tempfile + atomic rename so a half-written file can never be observed,
    and the read-modify-write cycle is serialized across processes via
    fcntl.flock on a sibling lockfile so the multi-NIC parent's concurrent
    shards don't clobber each other (each shard converges on its own
    interface; pre-lock the last writer's view of {interfaces: {iface_X:
    ...}} silently wiped every other shard's entry).
    """

    SCHEMA_VERSION = 1

    def __init__(self, path: os.PathLike[str] | str = DEFAULT_CALIBRATION_PATH) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def _lock_path(self) -> Path:
        return self._path.with_suffix(self._path.suffix + ".lock")

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
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return
        timestamp = now_iso if now_iso is not None else _utc_now_iso()
        with self._locked_for_write():
            # Re-read inside the lock so concurrent shards observe each
            # other's entries instead of clobbering with a stale view.
            entries = self.load()
            entries[interface] = CalibrationEntry(learned_rate, timestamp)
            payload = {
                "version": self.SCHEMA_VERSION,
                "interfaces": {
                    key: {"learned_rate": entry.learned_rate, "updated_at": entry.updated_at}
                    for key, entry in entries.items()
                },
            }
            # Per-pid tmp filename so concurrent shards don't overwrite
            # each other's pre-rename payloads. The flock above already
            # serializes them, but per-pid tmp keeps cleanup well-defined
            # if a shard dies between write and rename.
            tmp_path = self._path.with_suffix(
                self._path.suffix + f".tmp.{os.getpid()}"
            )
            try:
                tmp_path.write_text(json.dumps(payload, sort_keys=True))
                os.replace(tmp_path, self._path)
            except OSError:
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    @contextmanager
    def _locked_for_write(self) -> Iterator[None]:
        """Hold an exclusive flock for the lifetime of a read-modify-write.

        On hosts where flock is unsupported (rare; most filesystems with a
        Linux kernel grant it) the lock acquisition is best-effort — we
        fall through to the unprotected write rather than blocking
        calibration entirely. Contention is bounded: the held interval is
        a few millis (json.dumps + tempfile write + rename).
        """

        lock_handle = None
        try:
            lock_handle = open(self._lock_path, "w")
        except OSError:
            yield
            return
        try:
            try:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            except OSError:
                # Filesystem refused the lock; proceed unprotected so a
                # missing lock primitive doesn't drop calibration entirely.
                yield
                return
            try:
                yield
            finally:
                try:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            try:
                lock_handle.close()
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
# System load (for CPU-vs-network slip distinction)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SystemLoad:
    """Snapshot of the host's run-queue pressure relative to its vCPU count.

    Sampled once per AIMD window so :func:`classify_window` can tell a
    CPU-starved process apart from a NIC-saturated one. Both can produce
    heartbeat slip; only the network case responds to shrinking the rate.
    """

    load_average_1min: float
    vcpu_count: int

    @property
    def load_average_per_vcpu(self) -> float:
        if self.vcpu_count <= 0:
            return self.load_average_1min
        return self.load_average_1min / float(self.vcpu_count)


class SystemLoadReader:
    """Reads /proc/loadavg and reports loadavg-per-vcpu.

    The vCPU count is captured once at construction time (default
    ``os.cpu_count()``) because the topology is stable for the lifetime
    of a worker process; the loadavg field is re-read on every
    :meth:`read` call so the controller observes contention on a
    per-window basis. Tests inject ``loadavg_path`` and ``vcpu_count``
    so they don't depend on the host's actual /proc.
    """

    def __init__(
        self,
        *,
        loadavg_path: os.PathLike[str] | str = "/proc/loadavg",
        vcpu_count: Optional[int] = None,
    ) -> None:
        self._loadavg_path = Path(loadavg_path)
        self._vcpu_count = (
            vcpu_count if vcpu_count is not None and vcpu_count > 0 else max(1, os.cpu_count() or 1)
        )

    @property
    def vcpu_count(self) -> int:
        return self._vcpu_count

    def read(self) -> SystemLoad:
        try:
            raw = self._loadavg_path.read_text().strip()
        except OSError:
            return SystemLoad(0.0, self._vcpu_count)
        parts = raw.split()
        if not parts:
            return SystemLoad(0.0, self._vcpu_count)
        try:
            load = float(parts[0])
        except ValueError:
            return SystemLoad(0.0, self._vcpu_count)
        if load < 0:
            load = 0.0
        return SystemLoad(load, self._vcpu_count)


# ---------------------------------------------------------------------------
# Per-instance defaults
#
# Different AWS instance classes have wildly different natural pps ceilings
# — c6in.xlarge tops out around 1.7M, c6in.metal delivers 12M+ at 1-NIC
# (anygpt-4 bench data). Starting every host at the conservative 500k seed
# means c6in.metal wastes 4-6 windows ramping; pinning the seed and
# ceiling per-class skips that ramp and lets the controller settle into
# the correct band on window 1.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InstanceDefaults:
    """Per-class starting rate and AIMD bounds.

    ``starting_rate`` seeds the controller when there is no per-interface
    calibration to reuse. ``floor`` and ``ceiling`` widen / clamp the
    AIMD band so the controller can both ramp up to the host's natural
    ceiling and shrink down to a useful floor on slip.
    """

    starting_rate: int
    floor: int
    ceiling: int


# Conservative table; ceilings are kernel-TX bounds we have measured (or
# estimated linearly within a class), not ENA spec maxima. Anything not
# listed falls through to DEFAULT_FLOOR/DEFAULT_CEILING and the
# operator-supplied SCANNER_DEFAULT_RATE.
INSTANCE_TYPE_DEFAULTS: dict[str, InstanceDefaults] = {
    "m5.xlarge": InstanceDefaults(200_000, 100_000, 1_000_000),
    "m5.2xlarge": InstanceDefaults(400_000, 100_000, 1_500_000),
    "c6in.xlarge": InstanceDefaults(500_000, 100_000, 2_000_000),
    "c6in.2xlarge": InstanceDefaults(1_000_000, 100_000, 4_000_000),
    "c6in.4xlarge": InstanceDefaults(1_500_000, 200_000, 6_000_000),
    "c6in.8xlarge": InstanceDefaults(3_000_000, 500_000, 8_000_000),
    "c6in.16xlarge": InstanceDefaults(3_500_000, 500_000, 10_000_000),
    "c6in.32xlarge": InstanceDefaults(4_000_000, 1_000_000, 12_000_000),
    "c6in.metal": InstanceDefaults(4_000_000, 1_000_000, 12_000_000),
}


_INSTANCE_TYPE_RE = re.compile(r"^[a-z0-9]+\.[a-z0-9]+$")


def _looks_like_instance_type(value: str) -> bool:
    return bool(_INSTANCE_TYPE_RE.match(value))


def detect_instance_type(
    *,
    env: Optional[Mapping[str, str]] = None,
    dmi_path: os.PathLike[str] | str = DEFAULT_DMI_PRODUCT_PATH,
    imds_fetcher: Optional[Callable[[], Optional[str]]] = None,
) -> Optional[str]:
    """Best-effort detection of the EC2 instance type running this worker.

    Resolution order, first hit wins:
    1. ``ANYSCAN_INSTANCE_TYPE`` from ``env`` — explicit override for
       tests, dev runs, and to skip IMDS round-trips on subsequent
       child processes (the parent caches its detection there).
    2. ``/sys/devices/virtual/dmi/id/product_name``: on AWS bare-metal
       hosts this often exposes the actual instance type. On VMs it
       is usually ``Amazon EC2`` and we fall through.
    3. ``imds_fetcher()`` (defaults to a real IMDSv2 round-trip): the
       authoritative source for VM instance types. Tightly bounded
       timeout so a missing IMDS does not delay scanner startup.

    Returns ``None`` when no source produces a recognizable type. The
    fetcher hook exists so unit tests do not have to monkey-patch
    urllib.
    """

    env = env if env is not None else os.environ
    explicit = env.get("ANYSCAN_INSTANCE_TYPE")
    if explicit and explicit.strip():
        candidate = explicit.strip()
        if _looks_like_instance_type(candidate):
            return candidate

    try:
        product = Path(dmi_path).read_text().strip()
    except OSError:
        product = ""
    if product and _looks_like_instance_type(product):
        return product

    fetcher = imds_fetcher if imds_fetcher is not None else _default_imds_fetcher
    try:
        fetched = fetcher()
    except Exception:  # noqa: BLE001 - best-effort detection
        fetched = None
    if fetched and _looks_like_instance_type(fetched.strip()):
        return fetched.strip()
    return None


def _default_imds_fetcher() -> Optional[str]:
    """Real-world IMDSv2 round-trip used when no test fetcher is supplied."""

    import urllib.error
    import urllib.request

    timeout = DEFAULT_IMDS_TIMEOUT_SECONDS
    try:
        token_req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        )
        with urllib.request.urlopen(token_req, timeout=timeout) as resp:
            token = resp.read().decode("ascii", errors="replace").strip()
    except (urllib.error.URLError, OSError, ValueError):
        return None
    try:
        type_req = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/instance-type",
            headers={"X-aws-ec2-metadata-token": token},
        )
        with urllib.request.urlopen(type_req, timeout=timeout) as resp:
            return resp.read().decode("ascii", errors="replace").strip()
    except (urllib.error.URLError, OSError, ValueError):
        return None


def lookup_instance_defaults(instance_type: Optional[str]) -> Optional[InstanceDefaults]:
    if not instance_type:
        return None
    return INSTANCE_TYPE_DEFAULTS.get(instance_type.strip())


def apply_instance_defaults(
    *,
    policy: AimdPolicy,
    fallback_rate: int,
    instance_type: Optional[str],
    env: Optional[Mapping[str, str]] = None,
) -> tuple[AimdPolicy, int]:
    """Layer the per-instance defaults under any explicit env overrides.

    The contract is: env-supplied knobs always win. We only fill in floor,
    ceiling, and starting (fallback) rate when the corresponding env var
    is missing. This means an operator who pins ANYSCAN_RATE_CEILING by
    hand still gets exactly that value on c6in.metal, while a stock host
    silently picks up the table's c6in.metal ceiling.
    """

    defaults = lookup_instance_defaults(instance_type)
    if defaults is None:
        return policy, fallback_rate

    env = env if env is not None else os.environ
    new_floor = (
        defaults.floor
        if not _env_value_present(env, "ANYSCAN_RATE_FLOOR")
        else policy.floor
    )
    new_ceiling = (
        defaults.ceiling
        if not _env_value_present(env, "ANYSCAN_RATE_CEILING")
        else policy.ceiling
    )
    if new_ceiling < new_floor:
        new_ceiling = new_floor

    new_policy = replace(policy, floor=new_floor, ceiling=new_ceiling)

    if _env_value_present(env, "SCANNER_DEFAULT_RATE"):
        new_starting = fallback_rate
    else:
        new_starting = defaults.starting_rate
    return new_policy, new_starting


def _env_value_present(env: Mapping[str, str], key: str) -> bool:
    raw = env.get(key)
    return raw is not None and raw.strip() != ""


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
    # Optional CPU-pressure source. Sampled once per window and passed
    # into ``classify_window`` so the controller can hold rate when the
    # slip is CPU-caused. When ``None`` (e.g. older bundles or test
    # harnesses) the controller falls back to the legacy
    # any-slip-is-network classification.
    system_load_reader: Optional["SystemLoadReader"] = None


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
        last_persisted_rate = 0
        idx = 0
        try:
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
                system_load = (
                    self._options.system_load_reader.read()
                    if self._options.system_load_reader is not None
                    else None
                )
                classification = classify_window(
                    measurement, self._options.policy, system_load=system_load
                )
                next_rate = compute_next_rate(
                    self._options.policy, rate, measurement, system_load=system_load
                )
                report = WindowReport(
                    index=idx,
                    set_rate=rate,
                    measurement=measurement,
                    classification=classification,
                    next_rate=next_rate,
                )
                reports.append(report)
                metric_payload: dict[str, object] = {
                    "window": idx,
                    "set_rate": rate,
                    "achieved_pps": int(measurement.achieved_pps),
                    "tx_dropped_delta": measurement.tx_dropped_delta,
                    "heartbeat_max_latency_ms": measurement.heartbeat_max_latency_ms,
                    "scanner_finished_naturally": measurement.scanner_finished_naturally,
                    "classification": classification,
                    "next_rate": next_rate,
                    "interface": self._options.interface,
                }
                if system_load is not None:
                    metric_payload["loadavg_per_vcpu"] = round(
                        system_load.load_average_per_vcpu, 3
                    )
                    metric_payload["vcpu_count"] = system_load.vcpu_count
                emit_metric("rate_adjustment", metric_payload, sink=self._log_sink)
                if classification == CLEAN and rate > max_clean_rate:
                    max_clean_rate = rate
                    # Persist on every clean window where we set a new
                    # high-water mark. PR #58 only wrote at end-of-run, so
                    # a scanner crash mid-loop dropped the calibration on
                    # the floor; this guarantees the learned rate
                    # survives even partial windows.
                    last_persisted_rate = self._maybe_persist_calibration(
                        max_clean_rate, last_persisted_rate
                    )
                if measurement.scanner_finished_naturally:
                    break
                rate = next_rate
        finally:
            # Terminal persist regardless of how the loop exited (natural
            # finish, max_windows cap, ScannerWindowError). Idempotent
            # against the per-window writes above so we don't spam the
            # store on a clean exit.
            if max_clean_rate > 0:
                self._maybe_persist_calibration(max_clean_rate, last_persisted_rate)
        return reports

    def _maybe_persist_calibration(
        self, learned_rate: int, last_persisted_rate: int
    ) -> int:
        """Best-effort write of ``learned_rate`` to the calibration store.

        Returns the rate now reflected on disk (either the new write or
        ``last_persisted_rate`` when the write was a no-op or failed).
        Never raises; persistence is always best-effort.
        """

        if not (
            self._options.persist_on_clean
            and self._options.calibration is not None
            and self._options.interface
            and learned_rate > last_persisted_rate
        ):
            return last_persisted_rate
        try:
            self._options.calibration.store(self._options.interface, learned_rate)
            return learned_rate
        except Exception as error:  # noqa: BLE001 - best-effort persistence
            emit_metric(
                "calibration_persist_failed",
                {"interface": self._options.interface, "error": str(error)},
                sink=self._log_sink,
            )
            return last_persisted_rate


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
        nic_before = self._nic_reader.read() if self._nic_reader is not None else NicCounters(0, 0)
        self._jitter_monitor.reset()
        start_time = time.monotonic()
        child = self._spawn(command)
        self._on_child(child)
        finished_naturally = False
        try:
            try:
                child.wait(timeout=window_seconds)
                finished_naturally = True
            except subprocess.TimeoutExpired:
                _terminate_process_tree(child, self._terminate_grace_seconds)
        finally:
            self._on_child(None)
        elapsed = time.monotonic() - start_time
        nic_after = self._nic_reader.read() if self._nic_reader is not None else NicCounters(0, 0)
        tx_packets_delta = max(0, nic_after.tx_packets - nic_before.tx_packets)
        tx_dropped_delta = max(0, nic_after.tx_dropped - nic_before.tx_dropped)
        heartbeat_latency_ms = self._jitter_monitor.max_gap_ms()
        exit_code = child.returncode if child.returncode is not None else 0
        return WindowMeasurement(
            set_rate=rate,
            elapsed_seconds=elapsed,
            tx_packets_delta=tx_packets_delta,
            tx_dropped_delta=tx_dropped_delta,
            heartbeat_max_latency_ms=heartbeat_latency_ms,
            scanner_finished_naturally=finished_naturally and exit_code == 0,
            scanner_exit_code=exit_code,
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
        cpu_load_threshold=_env_float(
            env,
            "ANYSCAN_CPU_LOAD_THRESHOLD",
            DEFAULT_CPU_LOAD_THRESHOLD,
        ),
        drop_ratio_threshold=_env_float(
            env,
            "ANYSCAN_DROP_RATIO_THRESHOLD",
            DEFAULT_DROP_RATIO_THRESHOLD,
        ),
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
    "SystemLoad",
    "SystemLoadReader",
    "InstanceDefaults",
    "INSTANCE_TYPE_DEFAULTS",
    "detect_instance_type",
    "lookup_instance_defaults",
    "apply_instance_defaults",
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
    "DEFAULT_CPU_LOAD_THRESHOLD",
    "DEFAULT_DROP_RATIO_THRESHOLD",
    "DEFAULT_DMI_PRODUCT_PATH",
    "CLEAN",
    "SLIP",
    "SLIP_NETWORK",
    "SLIP_CPU",
]
