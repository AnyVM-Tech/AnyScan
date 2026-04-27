"""Unit + smoke tests for the AIMD port-scan rate controller.

Run via ``python3 -m unittest test_anyscan_rate_controller -v`` from the
anyscan repo root. Pure-Python; no scanner binary or NIC required.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

import anyscan_rate_controller as rc


def make_measurement(
    *,
    set_rate: int,
    achieved_pps: float,
    elapsed_seconds: float = 30.0,
    tx_dropped_delta: int = 0,
    heartbeat_max_latency_ms: int = 0,
    scanner_finished_naturally: bool = False,
) -> rc.WindowMeasurement:
    return rc.WindowMeasurement(
        set_rate=set_rate,
        elapsed_seconds=elapsed_seconds,
        tx_packets_delta=int(achieved_pps * elapsed_seconds),
        tx_dropped_delta=tx_dropped_delta,
        heartbeat_max_latency_ms=heartbeat_max_latency_ms,
        scanner_finished_naturally=scanner_finished_naturally,
    )


class AimdMathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = rc.AimdPolicy()

    def test_clean_window_bumps_additively(self) -> None:
        measurement = make_measurement(set_rate=500_000, achieved_pps=480_000)
        self.assertEqual(rc.classify_window(measurement, self.policy), rc.CLEAN)
        next_rate = rc.compute_next_rate(self.policy, 500_000, measurement)
        self.assertEqual(next_rate, 700_000)

    def test_slip_due_to_drops_halves(self) -> None:
        measurement = make_measurement(
            set_rate=2_000_000,
            achieved_pps=1_900_000,
            tx_dropped_delta=42,
        )
        self.assertEqual(rc.classify_window(measurement, self.policy), rc.SLIP)
        next_rate = rc.compute_next_rate(self.policy, 2_000_000, measurement)
        self.assertEqual(next_rate, 1_000_000)

    def test_slip_due_to_heartbeat_halves(self) -> None:
        measurement = make_measurement(
            set_rate=3_000_000,
            achieved_pps=2_800_000,
            heartbeat_max_latency_ms=6_000,
        )
        self.assertEqual(rc.classify_window(measurement, self.policy), rc.SLIP)
        next_rate = rc.compute_next_rate(self.policy, 3_000_000, measurement)
        self.assertEqual(next_rate, 1_500_000)

    def test_slip_due_to_starved_achieved_rate(self) -> None:
        # set 5M but achieved only 1.5M — rate-limit overhead tax that PR #55
        # observed. Should be classified as slip even with no drops.
        measurement = make_measurement(set_rate=5_000_000, achieved_pps=1_500_000)
        self.assertEqual(rc.classify_window(measurement, self.policy), rc.SLIP)
        next_rate = rc.compute_next_rate(self.policy, 5_000_000, measurement)
        self.assertEqual(next_rate, 2_500_000)

    def test_natural_finish_skips_achieved_floor(self) -> None:
        # Tiny target ranges finish in milliseconds — achieved/set will look
        # tiny but that just means we ran out of work, not that we're being
        # throttled. Don't punish that.
        measurement = make_measurement(
            set_rate=2_000_000,
            achieved_pps=80_000,
            elapsed_seconds=0.5,
            scanner_finished_naturally=True,
        )
        self.assertEqual(rc.classify_window(measurement, self.policy), rc.CLEAN)

    def test_ceiling_clamp_on_clean(self) -> None:
        policy = rc.AimdPolicy(ceiling=1_000_000)
        measurement = make_measurement(set_rate=950_000, achieved_pps=940_000)
        self.assertEqual(rc.compute_next_rate(policy, 950_000, measurement), 1_000_000)

    def test_floor_clamp_on_slip(self) -> None:
        policy = rc.AimdPolicy(floor=300_000, multiplicative_factor=0.25)
        measurement = make_measurement(
            set_rate=400_000,
            achieved_pps=10_000,
            tx_dropped_delta=10,
        )
        self.assertEqual(rc.compute_next_rate(policy, 400_000, measurement), 300_000)

    def test_clamp_rate_pulls_in_outside_band(self) -> None:
        policy = rc.AimdPolicy(floor=100_000, ceiling=4_000_000)
        self.assertEqual(rc.clamp_rate(50_000, policy), 100_000)
        self.assertEqual(rc.clamp_rate(10_000_000, policy), 4_000_000)
        self.assertEqual(rc.clamp_rate(2_000_000, policy), 2_000_000)

    def test_invalid_policy_rejected(self) -> None:
        with self.assertRaises(ValueError):
            rc.AimdPolicy(floor=0)
        with self.assertRaises(ValueError):
            rc.AimdPolicy(floor=500_000, ceiling=400_000)
        with self.assertRaises(ValueError):
            rc.AimdPolicy(multiplicative_factor=0.0)
        with self.assertRaises(ValueError):
            rc.AimdPolicy(multiplicative_factor=1.0)


class CalibrationStoreTests(unittest.TestCase):
    def test_load_returns_empty_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = rc.RateCalibrationStore(Path(tmpdir) / "rate-calibration.json")
            self.assertEqual(store.load(), {})
            self.assertIsNone(store.lookup("eth0"))

    def test_store_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "rate-calibration.json"
            store = rc.RateCalibrationStore(path)
            store.store("eth0", 1_700_000, now_iso="2026-04-27T00:00:00Z")
            store.store("eth1", 800_000, now_iso="2026-04-27T00:01:00Z")
            self.assertEqual(store.lookup("eth0").learned_rate, 1_700_000)
            self.assertEqual(store.lookup("eth1").learned_rate, 800_000)
            payload = json.loads(path.read_text())
            self.assertEqual(payload["version"], 1)
            self.assertIn("eth0", payload["interfaces"])

    def test_corrupt_file_treated_as_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "rate-calibration.json"
            path.write_text("not json{}")
            store = rc.RateCalibrationStore(path)
            self.assertEqual(store.load(), {})

    def test_zero_or_negative_rates_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "rate-calibration.json"
            store = rc.RateCalibrationStore(path)
            store.store("eth0", 0)
            store.store("eth0", -100)
            self.assertFalse(path.exists())


@dataclass
class StubWindow:
    achieved_pps_for_set: dict[int, float]
    drops_for_set: dict[int, int]
    heartbeat_for_set: dict[int, int]
    natural_finish_after_window: int = 100  # effectively never


class StubRunner(rc.WindowRunner):
    def __init__(self, scenario: StubWindow, *, profile: callable | None = None) -> None:
        self._scenario = scenario
        self._profile = profile
        self._invocation = 0

    def run(
        self,
        *,
        rate: int,
        window_seconds: float,
        is_first_window: bool,
    ) -> rc.WindowMeasurement:
        self._invocation += 1
        if self._profile is not None:
            achieved, dropped, heartbeat = self._profile(rate)
        else:
            achieved = self._scenario.achieved_pps_for_set.get(rate, 0)
            dropped = self._scenario.drops_for_set.get(rate, 0)
            heartbeat = self._scenario.heartbeat_for_set.get(rate, 0)
        finished = self._invocation >= self._scenario.natural_finish_after_window
        return rc.WindowMeasurement(
            set_rate=rate,
            elapsed_seconds=window_seconds,
            tx_packets_delta=int(achieved * window_seconds),
            tx_dropped_delta=dropped,
            heartbeat_max_latency_ms=heartbeat,
            scanner_finished_naturally=finished,
        )


class ConvergenceSmokeTests(unittest.TestCase):
    """Synthetic convergence test using PR #55's measured numbers as ground truth."""

    def _profile_from_pr55(self, rate: int) -> tuple[float, int, int]:
        # rate=100k achieved 175k (cap cosmetic below natural)
        # rate=500k achieved ~480k (estimated linear region)
        # rate=700k achieved ~680k
        # rate=900k achieved ~880k
        # rate=1M  achieved 1_760_000 (sweet spot kicked in here in real bench)
        # rate=2M  achieved 2_220_000 (max)
        # rate=2.2M+ rate-limit overhead starts hurting; achieved drops
        # rate=5M  achieved 1_590_000 (rate-limit overhead hurts)
        natural_ceiling = 2_220_000
        sweet_spot = 1_700_000
        if rate <= 100_000:
            achieved = float(rate) * 1.75
            return achieved, 0, 50
        if rate <= 1_000_000:
            achieved = min(float(rate) * 0.97, natural_ceiling)
            return achieved, 0, 100
        if rate <= 2_000_000:
            achieved = min(natural_ceiling - (rate - 2_000_000) * 0.0, sweet_spot + (rate - 1_000_000) * 0.5)
            return achieved, 0, 800
        if rate <= 3_000_000:
            # Some packets dropped as we cross the host's natural ceiling.
            achieved = natural_ceiling - (rate - 2_000_000) * 0.4
            return achieved, int((rate - 2_000_000) * 0.05), 4_500
        # Above 3M: rate-limit overhead AND drops AND scheduler starvation.
        return 1_500_000.0, int((rate - 3_000_000) * 0.1), 7_000

    def test_converges_into_sweet_spot_within_a_handful_of_windows(self) -> None:
        policy = rc.AimdPolicy(window_seconds=30)
        scenario = StubWindow(
            achieved_pps_for_set={},
            drops_for_set={},
            heartbeat_for_set={},
        )
        runner = StubRunner(scenario, profile=self._profile_from_pr55)
        sink = io.StringIO()
        controller = rc.RateController(
            options=rc.ControllerOptions(
                policy=policy,
                window_seconds=float(policy.window_seconds),
                interface="eth0",
                starting_rate=500_000,
                calibration=None,
                persist_on_clean=False,
            ),
            runner=runner,
            log_sink=sink,
            max_windows=10,
        )
        reports = controller.run()

        self.assertEqual(len(reports), 10)
        first_set_rates = [r.set_rate for r in reports[:4]]
        self.assertEqual(first_set_rates, [500_000, 700_000, 900_000, 1_100_000])

        # Within the cap of 10 windows we should have already touched a rate
        # that exercises the sweet-spot region (>= 1.5M) and never explored
        # the dangerous-overhead zone (>= 4M).
        self.assertTrue(any(r.set_rate >= 1_500_000 for r in reports))
        self.assertTrue(all(r.set_rate <= 4_000_000 for r in reports))

        # Settled rate (last window) should be in the productive range —
        # not stuck at the floor and not parked at the ceiling.
        settled = reports[-1].set_rate
        self.assertGreaterEqual(settled, 900_000)
        self.assertLessEqual(settled, 4_000_000)

    def test_clean_only_scenario_walks_up_to_ceiling(self) -> None:
        policy = rc.AimdPolicy(
            floor=100_000,
            ceiling=1_000_000,
            additive_step=200_000,
            window_seconds=30,
        )

        def profile(rate: int) -> tuple[float, int, int]:
            return float(rate) * 0.95, 0, 50

        scenario = StubWindow(
            achieved_pps_for_set={},
            drops_for_set={},
            heartbeat_for_set={},
        )
        runner = StubRunner(scenario, profile=profile)
        controller = rc.RateController(
            options=rc.ControllerOptions(
                policy=policy,
                window_seconds=float(policy.window_seconds),
                interface=None,
                starting_rate=200_000,
                calibration=None,
                persist_on_clean=False,
            ),
            runner=runner,
            log_sink=io.StringIO(),
            max_windows=8,
        )
        reports = controller.run()
        rates = [r.set_rate for r in reports]
        self.assertEqual(
            rates,
            [200_000, 400_000, 600_000, 800_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000],
        )

    def test_persists_max_clean_rate_after_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            calibration = rc.RateCalibrationStore(
                Path(tmpdir) / "rate-calibration.json"
            )
            policy = rc.AimdPolicy(window_seconds=30)
            runner = StubRunner(
                StubWindow(
                    achieved_pps_for_set={},
                    drops_for_set={},
                    heartbeat_for_set={},
                ),
                profile=self._profile_from_pr55,
            )
            controller = rc.RateController(
                options=rc.ControllerOptions(
                    policy=policy,
                    window_seconds=float(policy.window_seconds),
                    interface="eth0",
                    starting_rate=500_000,
                    calibration=calibration,
                ),
                runner=runner,
                log_sink=io.StringIO(),
                max_windows=8,
            )
            controller.run()
            entry = calibration.lookup("eth0")
            self.assertIsNotNone(entry)
            self.assertGreaterEqual(entry.learned_rate, 900_000)


class ScannerFailureTests(unittest.TestCase):
    def test_mid_window_failure_aborts_loop(self) -> None:
        class CrashingRunner(rc.WindowRunner):
            def __init__(self) -> None:
                self.calls = 0

            def run(
                self, *, rate: int, window_seconds: float, is_first_window: bool
            ) -> rc.WindowMeasurement:
                self.calls += 1
                return rc.WindowMeasurement(
                    set_rate=rate,
                    elapsed_seconds=1.0,
                    tx_packets_delta=0,
                    tx_dropped_delta=0,
                    heartbeat_max_latency_ms=0,
                    scanner_finished_naturally=False,
                    scanner_exit_code=139,
                )

        runner = CrashingRunner()
        controller = rc.RateController(
            options=rc.ControllerOptions(
                policy=rc.AimdPolicy(window_seconds=30),
                window_seconds=30.0,
                interface=None,
                starting_rate=500_000,
                calibration=None,
            ),
            runner=runner,
            log_sink=io.StringIO(),
            max_windows=5,
        )
        with self.assertRaises(rc.ScannerWindowError) as ctx:
            controller.run()
        self.assertEqual(ctx.exception.exit_code, 139)
        self.assertEqual(runner.calls, 1)


class JitterMonitorTests(unittest.TestCase):
    def test_reset_clears_recorded_gap(self) -> None:
        monitor = rc.JitterMonitor(interval_seconds=0.01)
        monitor.start()
        try:
            import time as _t

            _t.sleep(0.1)
            self.assertGreaterEqual(monitor.max_gap_ms(), 0)
            monitor.reset()
            self.assertEqual(monitor.max_gap_ms(), 0)
        finally:
            monitor.stop()


class NicStatsReaderTests(unittest.TestCase):
    def test_reads_counters_from_synthetic_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            iface_root = Path(tmpdir) / "eth0" / "statistics"
            iface_root.mkdir(parents=True)
            (iface_root / "tx_packets").write_text("123\n")
            (iface_root / "tx_dropped").write_text("4\n")
            reader = rc.NicStatsReader("eth0", root=tmpdir)
            counters = reader.read()
            self.assertEqual(counters.tx_packets, 123)
            self.assertEqual(counters.tx_dropped, 4)

    def test_missing_files_return_zero(self) -> None:
        reader = rc.NicStatsReader("ghost0", root="/nonexistent")
        counters = reader.read()
        self.assertEqual(counters.tx_packets, 0)
        self.assertEqual(counters.tx_dropped, 0)


class EnvHelpersTests(unittest.TestCase):
    def test_policy_from_env_round_trip(self) -> None:
        env = {
            "ANYSCAN_RATE_FLOOR": "150000",
            "ANYSCAN_RATE_CEILING": "3500000",
            "ANYSCAN_RATE_ADDITIVE_STEP": "250000",
            "ANYSCAN_RATE_MULTIPLICATIVE_FACTOR": "0.25",
            "ANYSCAN_RATE_WINDOW_SECONDS": "45",
            "ANYSCAN_HEARTBEAT_LATENCY_THRESHOLD_MS": "3000",
        }
        policy = rc.policy_from_env(env)
        self.assertEqual(policy.floor, 150_000)
        self.assertEqual(policy.ceiling, 3_500_000)
        self.assertEqual(policy.additive_step, 250_000)
        self.assertAlmostEqual(policy.multiplicative_factor, 0.25)
        self.assertEqual(policy.window_seconds, 45)
        self.assertEqual(policy.heartbeat_latency_threshold_ms, 3_000)

    def test_env_flag_default_when_missing(self) -> None:
        self.assertTrue(rc.env_flag({}, "MISSING", default=True))
        self.assertFalse(rc.env_flag({"X": "no"}, "X", default=True))
        self.assertTrue(rc.env_flag({"X": "1"}, "X", default=False))

    def test_resolve_starting_rate_prefers_calibration(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            calibration = rc.RateCalibrationStore(Path(tmpdir) / "calib.json")
            calibration.store("eth0", 1_700_000)
            policy = rc.AimdPolicy()
            resolved = rc.resolve_starting_rate(
                policy=policy,
                interface="eth0",
                calibration=calibration,
                fallback_rate=500_000,
            )
            self.assertEqual(resolved, 1_700_000)

    def test_resolve_starting_rate_clamps_calibration_into_band(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            calibration = rc.RateCalibrationStore(Path(tmpdir) / "calib.json")
            calibration.store("eth0", 99_000_000)
            policy = rc.AimdPolicy(ceiling=4_000_000)
            resolved = rc.resolve_starting_rate(
                policy=policy,
                interface="eth0",
                calibration=calibration,
                fallback_rate=500_000,
            )
            self.assertEqual(resolved, 4_000_000)


if __name__ == "__main__":
    unittest.main()
