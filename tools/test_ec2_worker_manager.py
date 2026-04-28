"""Unit tests for the multi-ENI launch path in ec2_worker_manager.py.

Covers env-var parsing, hardware-cap detection, ENI distribution across
network cards, and the recreate_instance launch payload. boto3 is stubbed
out at import time so the tests run without AWS credentials.

Run from the anyscan repo root:

    python3 -m unittest tools.test_ec2_worker_manager -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "tools" / "ec2_worker_manager.py"


class _StubClientError(Exception):
    """Stand-in for botocore.exceptions.ClientError used by the module."""

    def __init__(self, response: dict[str, Any]) -> None:
        super().__init__(response.get("Error", {}).get("Message", "stub"))
        self.response = response


def _load_module():
    if "ec2_worker_manager" in sys.modules:
        del sys.modules["ec2_worker_manager"]
    boto3_stub = mock.MagicMock()
    botocore_stub = mock.MagicMock()
    botocore_exc = mock.MagicMock()
    botocore_exc.ClientError = _StubClientError
    sys.modules["boto3"] = boto3_stub
    sys.modules["botocore"] = botocore_stub
    sys.modules["botocore.exceptions"] = botocore_exc
    botocore_stub.exceptions = botocore_exc

    spec = importlib.util.spec_from_file_location(
        "ec2_worker_manager", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["ec2_worker_manager"] = module
    spec.loader.exec_module(module)
    return module


m = _load_module()


def _c6in_metal_describe() -> dict[str, Any]:
    """The DescribeInstanceTypes payload AWS returns for c6in.metal.

    Recorded from `aws ec2 describe-instance-types --instance-types
    c6in.metal --region us-east-1` (anygpt-48, 2026-04-28). The shape
    is 2 NetworkCards × 8 = 16, NOT the 4-card 5/4/3/3=15 the original
    fixture claimed — see PR 65 issuecomment-4338158487 for the live
    capture.
    """
    return {
        "InstanceTypes": [
            {
                "InstanceType": "c6in.metal",
                "NetworkInfo": {
                    "MaximumNetworkInterfaces": 16,
                    "MaximumNetworkCards": 2,
                    "NetworkCards": [
                        {
                            "NetworkCardIndex": 0,
                            "MaximumNetworkInterfaces": 8,
                            "NetworkPerformance": "Up to 170 Gigabit",
                        },
                        {
                            "NetworkCardIndex": 1,
                            "MaximumNetworkInterfaces": 8,
                            "NetworkPerformance": "Up to 170 Gigabit",
                        },
                    ],
                },
            }
        ]
    }


def _c6in_xlarge_describe() -> dict[str, Any]:
    return {
        "InstanceTypes": [
            {
                "InstanceType": "c6in.xlarge",
                "NetworkInfo": {
                    "MaximumNetworkInterfaces": 4,
                    "NetworkCards": [
                        {"NetworkCardIndex": 0, "MaximumNetworkInterfaces": 4}
                    ],
                },
            }
        ]
    }


class ParseMaxEnisTests(unittest.TestCase):
    """ANYSCAN_MAX_ENIS env parsing — explicit opt-in is the only signal."""

    def test_unset_returns_none(self):
        self.assertIsNone(m.parse_max_enis(None))

    def test_empty_string_returns_none(self):
        self.assertIsNone(m.parse_max_enis(""))
        self.assertIsNone(m.parse_max_enis("   "))

    def test_positive_integer_parses(self):
        self.assertEqual(m.parse_max_enis("15"), 15)
        self.assertEqual(m.parse_max_enis("  4  "), 4)

    def test_zero_raises(self):
        with self.assertRaises(SystemExit):
            m.parse_max_enis("0")

    def test_negative_raises(self):
        with self.assertRaises(SystemExit):
            m.parse_max_enis("-5")

    def test_non_integer_raises(self):
        with self.assertRaises(SystemExit):
            m.parse_max_enis("fifteen")


class ComputeTargetEniCountTests(unittest.TestCase):
    """target = 1 unless operator opted in; otherwise min(hw_cap, max_enis)."""

    def test_unset_max_enis_keeps_single_nic(self):
        self.assertEqual(m.compute_target_eni_count(15, None), 1)

    def test_clamped_to_hardware_cap(self):
        self.assertEqual(m.compute_target_eni_count(4, 15), 4)

    def test_below_hardware_cap_passes_through(self):
        self.assertEqual(m.compute_target_eni_count(15, 8), 8)

    def test_equal_to_hardware_cap_passes_through(self):
        self.assertEqual(m.compute_target_eni_count(15, 15), 15)

    def test_zero_or_negative_hardware_cap_floors_at_one(self):
        self.assertEqual(m.compute_target_eni_count(0, 15), 1)
        self.assertEqual(m.compute_target_eni_count(-3, 15), 1)


class EniCapFromDescribeResponseTests(unittest.TestCase):
    """eni_cap_from_describe_response handles AWS payload edge cases."""

    def test_c6in_metal_payload(self):
        self.assertEqual(m.eni_cap_from_describe_response(_c6in_metal_describe()), 16)

    def test_c6in_xlarge_payload(self):
        self.assertEqual(m.eni_cap_from_describe_response(_c6in_xlarge_describe()), 4)

    def test_missing_instance_types_returns_none(self):
        self.assertIsNone(m.eni_cap_from_describe_response({}))
        self.assertIsNone(m.eni_cap_from_describe_response({"InstanceTypes": []}))

    def test_missing_network_info_returns_none(self):
        self.assertIsNone(m.eni_cap_from_describe_response({"InstanceTypes": [{}]}))

    def test_non_integer_cap_returns_none(self):
        payload = {"InstanceTypes": [{"NetworkInfo": {"MaximumNetworkInterfaces": "15"}}]}
        self.assertIsNone(m.eni_cap_from_describe_response(payload))

    def test_zero_cap_returns_none(self):
        payload = {"InstanceTypes": [{"NetworkInfo": {"MaximumNetworkInterfaces": 0}}]}
        self.assertIsNone(m.eni_cap_from_describe_response(payload))


class NetworkCardsFromDescribeResponseTests(unittest.TestCase):
    def test_c6in_metal_payload(self):
        cards = m.network_cards_from_describe_response(_c6in_metal_describe())
        self.assertEqual(len(cards), 2)
        self.assertEqual(
            sum(c["MaximumNetworkInterfaces"] for c in cards), 16
        )

    def test_missing_returns_empty(self):
        self.assertEqual(m.network_cards_from_describe_response({}), [])
        self.assertEqual(
            m.network_cards_from_describe_response({"InstanceTypes": [{}]}), []
        )

    def test_drops_non_dict_entries(self):
        payload = {
            "InstanceTypes": [
                {"NetworkInfo": {"NetworkCards": [None, "garbage", {"NetworkCardIndex": 0, "MaximumNetworkInterfaces": 1}]}}
            ]
        }
        cards = m.network_cards_from_describe_response(payload)
        self.assertEqual(cards, [{"NetworkCardIndex": 0, "MaximumNetworkInterfaces": 1}])


class DistributeEnisAcrossCardsTests(unittest.TestCase):
    """ENI distribution preserves per-card capacity and round-robins across cards."""

    def test_no_card_data_lays_out_sequentially_on_card_zero(self):
        self.assertEqual(
            m.distribute_enis_across_cards(3, []),
            [(0, 0), (0, 1), (0, 2)],
        )

    def test_none_card_data_lays_out_sequentially_on_card_zero(self):
        self.assertEqual(
            m.distribute_enis_across_cards(2, None),
            [(0, 0), (0, 1)],
        )

    def test_c6in_metal_16_eni_layout_respects_per_card_caps(self):
        cards = _c6in_metal_describe()["InstanceTypes"][0]["NetworkInfo"][
            "NetworkCards"
        ]
        placement = m.distribute_enis_across_cards(16, cards)
        self.assertEqual(len(placement), 16)
        per_card: dict[int, list[int]] = {}
        for card_idx, dev_idx in placement:
            per_card.setdefault(card_idx, []).append(dev_idx)
        # Each card should be at exactly its declared capacity for the
        # full-16 case; the round-robin policy fills evenly.
        self.assertEqual(per_card[0], [0, 1, 2, 3, 4, 5, 6, 7])
        self.assertEqual(per_card[1], [0, 1, 2, 3, 4, 5, 6, 7])

    def test_primary_eni_lands_on_card_zero(self):
        cards = _c6in_metal_describe()["InstanceTypes"][0]["NetworkInfo"][
            "NetworkCards"
        ]
        placement = m.distribute_enis_across_cards(1, cards)
        self.assertEqual(placement, [(0, 0)])

    def test_partial_count_round_robins_across_cards(self):
        cards = _c6in_metal_describe()["InstanceTypes"][0]["NetworkInfo"][
            "NetworkCards"
        ]
        # 4 ENIs across 2 cards × 8 cap: round-robin alternates card 0 / 1
        # starting from the primary ENI on card 0.
        placement = m.distribute_enis_across_cards(4, cards)
        self.assertEqual(
            [card_idx for card_idx, _ in placement],
            [0, 1, 0, 1],
        )

    def test_zero_target_raises(self):
        with self.assertRaises(ValueError):
            m.distribute_enis_across_cards(0, None)


class BuildNetworkInterfacesTests(unittest.TestCase):
    """The boto3 NetworkInterfaces parameter shape."""

    def test_legacy_single_card_path_omits_network_card_index(self):
        ifs = m.build_network_interfaces(
            target_count=2,
            subnet_ids=["subnet-aaa"],
            security_group_ids=["sg-1"],
            network_cards=None,
        )
        self.assertEqual(len(ifs), 2)
        for spec in ifs:
            self.assertNotIn("NetworkCardIndex", spec)
            self.assertEqual(spec["SubnetId"], "subnet-aaa")
            self.assertEqual(spec["Groups"], ["sg-1"])
        self.assertEqual([s["DeviceIndex"] for s in ifs], [0, 1])

    def test_multi_card_path_emits_network_card_index(self):
        cards = _c6in_metal_describe()["InstanceTypes"][0]["NetworkInfo"][
            "NetworkCards"
        ]
        ifs = m.build_network_interfaces(
            target_count=15,
            subnet_ids=["subnet-aaa"],
            security_group_ids=["sg-1"],
            network_cards=cards,
        )
        self.assertEqual(len(ifs), 15)
        for spec in ifs:
            self.assertIn("NetworkCardIndex", spec)

    def test_subnet_pool_round_robins(self):
        ifs = m.build_network_interfaces(
            target_count=4,
            subnet_ids=["subnet-A", "subnet-B"],
            security_group_ids=["sg-1"],
        )
        self.assertEqual(
            [s["SubnetId"] for s in ifs],
            ["subnet-A", "subnet-B", "subnet-A", "subnet-B"],
        )

    def test_empty_subnet_pool_raises(self):
        with self.assertRaises(ValueError):
            m.build_network_interfaces(
                target_count=2,
                subnet_ids=[],
                security_group_ids=["sg-1"],
            )

    def test_no_security_groups_omits_groups_key(self):
        ifs = m.build_network_interfaces(
            target_count=1,
            subnet_ids=["subnet-aaa"],
            security_group_ids=[],
        )
        self.assertNotIn("Groups", ifs[0])


def _make_config(**overrides) -> Any:
    base = dict(
        region="us-east-1",
        instance_type="c6in.metal",
        ami_id="ami-fake",
        key_name="anyscan-ec2-us-east-1",
        ssh_private_key_path=Path("/tmp/anyscan-fake.key"),
        subnet_id="subnet-primary",
        security_group_id="sg-1",
        instance_profile_arn=None,
        worker_name="anyscan-ec2-worker",
        worker_pool=None,
        worker_tags=["anyscan-ec2-managed"],
        control_plane_url="http://127.0.0.1:8088",
        control_plane_username="admin",
        control_plane_password=None,
        install_url="https://example.invalid/install.sh",
        google_healthcheck_url="https://example.invalid/healthz",
        state_file=Path("/tmp/anyscan-fake-state.json"),
        instance_id=None,
        ssh_username="admin",
        ssh_source_cidr=None,
        auto_authorize_ssh=False,
        bootstrap_grace_seconds=900,
        worker_stale_seconds=90,
        loop_interval_seconds=60,
        max_enis=None,
        eni_subnet_ids=[],
    )
    base.update(overrides)
    return m.ManagerConfig(**base)


class _FakeEc2Client:
    """Minimal in-memory EC2 stub recording RunInstances calls."""

    def __init__(self, describe_payload: dict[str, Any] | None = None) -> None:
        self.describe_payload = describe_payload
        self.run_instances_calls: list[dict[str, Any]] = []
        self.terminate_calls: list[list[str]] = []

    def describe_instance_types(self, *, InstanceTypes):
        if self.describe_payload is None:
            raise _StubClientError(
                {"Error": {"Code": "UnauthorizedOperation", "Message": "no IAM"}}
            )
        return self.describe_payload

    def run_instances(self, **kwargs):
        self.run_instances_calls.append(kwargs)
        return {"Instances": [{"InstanceId": "i-fake-123"}]}

    def terminate_instances(self, *, InstanceIds):
        self.terminate_calls.append(list(InstanceIds))
        return {"TerminatingInstances": [{"InstanceId": InstanceIds[0]}]}

    # describe_instances + status calls happen in current_instance_id /
    # _describe_instance; the tests below stub current_instance_id() to
    # return None so those paths never fire.


def _make_manager(config: Any, ec2_client: _FakeEc2Client) -> Any:
    """Construct an Ec2WorkerManager bypassing __init__ side-effects."""
    manager = m.Ec2WorkerManager.__new__(m.Ec2WorkerManager)
    manager.config = config
    manager.state = {}
    manager.ec2 = ec2_client
    manager.session = mock.MagicMock()
    manager.ec2_resource = mock.MagicMock()
    manager.sts = mock.MagicMock()
    manager.api = mock.MagicMock()
    manager._save_state = mock.MagicMock()
    manager._load_state = mock.MagicMock(return_value={})
    return manager


class RecreateInstanceLaunchPathTests(unittest.TestCase):
    """Multi-ENI vs single-NIC RunInstances payload selection."""

    def test_unset_preserves_legacy_single_nic_payload(self):
        """ANYSCAN_MAX_ENIS unset → legacy SubnetId/SecurityGroupIds shape."""
        config = _make_config(max_enis=None)
        ec2 = _FakeEc2Client(describe_payload=_c6in_metal_describe())
        manager = _make_manager(config, ec2)

        with mock.patch.object(manager, "current_instance_id", return_value=None), \
             mock.patch.object(manager, "ensure_ssh_access", return_value=None), \
             mock.patch.object(manager, "build_user_data", return_value="#!fake"):
            result = manager.recreate_instance()

        self.assertEqual(len(ec2.run_instances_calls), 1)
        call = ec2.run_instances_calls[0]
        self.assertNotIn("NetworkInterfaces", call)
        self.assertEqual(call.get("SubnetId"), "subnet-primary")
        self.assertEqual(call.get("SecurityGroupIds"), ["sg-1"])
        self.assertEqual(result["eni_attach"]["requested"], None)
        # Describe should not be called when the operator hasn't opted in.
        self.assertEqual(ec2.describe_payload, _c6in_metal_describe())  # untouched

    def test_max_enis_16_on_c6in_metal_emits_16_network_interfaces(self):
        config = _make_config(max_enis=16, instance_type="c6in.metal")
        ec2 = _FakeEc2Client(describe_payload=_c6in_metal_describe())
        manager = _make_manager(config, ec2)

        with mock.patch.object(manager, "current_instance_id", return_value=None), \
             mock.patch.object(manager, "ensure_ssh_access", return_value=None), \
             mock.patch.object(manager, "build_user_data", return_value="#!fake"):
            result = manager.recreate_instance()

        call = ec2.run_instances_calls[0]
        self.assertNotIn("SubnetId", call)
        self.assertNotIn("SecurityGroupIds", call)
        self.assertIn("NetworkInterfaces", call)
        self.assertEqual(len(call["NetworkInterfaces"]), 16)
        # Every NIC carries the security group on its Groups key.
        for nic in call["NetworkInterfaces"]:
            self.assertEqual(nic["Groups"], ["sg-1"])
            self.assertEqual(nic["SubnetId"], "subnet-primary")
            self.assertIn("NetworkCardIndex", nic)
        self.assertEqual(result["eni_attach"]["attached"], 16)
        self.assertEqual(result["eni_attach"]["hardware_cap"], 16)

    def test_max_enis_15_on_c6in_xlarge_clamps_to_4(self):
        config = _make_config(max_enis=15, instance_type="c6in.xlarge")
        ec2 = _FakeEc2Client(describe_payload=_c6in_xlarge_describe())
        manager = _make_manager(config, ec2)

        with mock.patch.object(manager, "current_instance_id", return_value=None), \
             mock.patch.object(manager, "ensure_ssh_access", return_value=None), \
             mock.patch.object(manager, "build_user_data", return_value="#!fake"):
            result = manager.recreate_instance()

        call = ec2.run_instances_calls[0]
        self.assertEqual(len(call["NetworkInterfaces"]), 4)
        self.assertEqual(result["eni_attach"]["attached"], 4)
        self.assertEqual(result["eni_attach"]["hardware_cap"], 4)

    def test_describe_failure_falls_back_to_single_nic(self):
        """Describe denial → single-NIC launch + reason recorded."""
        config = _make_config(max_enis=15, instance_type="c6in.metal")
        ec2 = _FakeEc2Client(describe_payload=None)  # raises ClientError
        manager = _make_manager(config, ec2)

        with mock.patch.object(manager, "current_instance_id", return_value=None), \
             mock.patch.object(manager, "ensure_ssh_access", return_value=None), \
             mock.patch.object(manager, "build_user_data", return_value="#!fake"):
            result = manager.recreate_instance()

        call = ec2.run_instances_calls[0]
        self.assertNotIn("NetworkInterfaces", call)
        self.assertEqual(call.get("SubnetId"), "subnet-primary")
        self.assertIn("fallback_reason", result["eni_attach"])

    def test_max_enis_set_but_no_subnet_falls_back_to_single_nic(self):
        config = _make_config(
            max_enis=15, instance_type="c6in.metal", subnet_id=None, eni_subnet_ids=[]
        )
        ec2 = _FakeEc2Client(describe_payload=_c6in_metal_describe())
        manager = _make_manager(config, ec2)

        with mock.patch.object(manager, "current_instance_id", return_value=None), \
             mock.patch.object(manager, "ensure_ssh_access", return_value=None), \
             mock.patch.object(manager, "build_user_data", return_value="#!fake"):
            result = manager.recreate_instance()

        call = ec2.run_instances_calls[0]
        self.assertNotIn("NetworkInterfaces", call)
        self.assertIn("fallback_reason", result["eni_attach"])

    def test_eni_subnet_ids_pool_round_robins(self):
        config = _make_config(
            max_enis=4,
            instance_type="c6in.metal",
            eni_subnet_ids=["subnet-X", "subnet-Y"],
        )
        ec2 = _FakeEc2Client(describe_payload=_c6in_metal_describe())
        manager = _make_manager(config, ec2)

        with mock.patch.object(manager, "current_instance_id", return_value=None), \
             mock.patch.object(manager, "ensure_ssh_access", return_value=None), \
             mock.patch.object(manager, "build_user_data", return_value="#!fake"):
            manager.recreate_instance()

        call = ec2.run_instances_calls[0]
        subnet_sequence = [nic["SubnetId"] for nic in call["NetworkInterfaces"]]
        self.assertEqual(
            subnet_sequence, ["subnet-X", "subnet-Y", "subnet-X", "subnet-Y"]
        )


class FromEnvIntegrationTests(unittest.TestCase):
    """ManagerConfig.from_env honors ANYSCAN_MAX_ENIS / ENI_SUBNET_IDS."""

    def setUp(self) -> None:
        self._snapshot = dict(os.environ)
        # Ensure required env is set so from_env doesn't SystemExit on AMI lookup.
        os.environ["ANYSCAN_EC2_REGION"] = "us-east-1"
        os.environ["ANYSCAN_EC2_AMI_ID"] = "ami-fake"

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._snapshot)

    def test_unset_max_enis(self):
        os.environ.pop("ANYSCAN_MAX_ENIS", None)
        cfg = m.ManagerConfig.from_env()
        self.assertIsNone(cfg.max_enis)
        self.assertEqual(cfg.eni_subnet_ids, [])

    def test_set_max_enis(self):
        os.environ["ANYSCAN_MAX_ENIS"] = "15"
        os.environ["ANYSCAN_EC2_ENI_SUBNET_IDS"] = "subnet-A, subnet-B"
        cfg = m.ManagerConfig.from_env()
        self.assertEqual(cfg.max_enis, 15)
        self.assertEqual(cfg.eni_subnet_ids, ["subnet-A", "subnet-B"])

    def test_invalid_max_enis_exits(self):
        os.environ["ANYSCAN_MAX_ENIS"] = "0"
        with self.assertRaises(SystemExit):
            m.ManagerConfig.from_env()


class RecordedDescribeInstanceTypesIntegrityTests(unittest.TestCase):
    """Anchor the synthetic c6in.metal fixture to a recorded AWS payload.

    `tools/c6in_metal_describe_instance_types.json` is a verbatim capture
    of `aws ec2 describe-instance-types --instance-types c6in.metal
    --region us-east-1` (anygpt-48, 2026-04-28). Asserting against the
    real payload prevents the mock-vs-reality drift PR 65
    issuecomment-4338158487 caught after the launch path had already
    shipped: the synthetic fixture claimed 4 cards × (5/4/3/3)=15 while
    AWS actually returns 2 cards × 8 = 16.
    """

    RECORDED_PAYLOAD_PATH = (
        Path(__file__).resolve().parent / "c6in_metal_describe_instance_types.json"
    )

    def setUp(self) -> None:
        with self.RECORDED_PAYLOAD_PATH.open() as fh:
            self.recorded = json.load(fh)

    def test_recorded_payload_eni_cap_is_16(self):
        self.assertEqual(m.eni_cap_from_describe_response(self.recorded), 16)

    def test_recorded_payload_has_two_network_cards(self):
        cards = m.network_cards_from_describe_response(self.recorded)
        self.assertEqual(len(cards), 2)

    def test_recorded_payload_each_card_has_capacity_8(self):
        cards = m.network_cards_from_describe_response(self.recorded)
        for card in cards:
            self.assertEqual(card["MaximumNetworkInterfaces"], 8)

    def test_recorded_payload_card_indexes_are_zero_and_one(self):
        cards = m.network_cards_from_describe_response(self.recorded)
        self.assertEqual(
            sorted(c["NetworkCardIndex"] for c in cards),
            [0, 1],
        )

    def test_synthetic_fixture_agrees_with_recorded_on_load_bearing_fields(self):
        """The synthetic _c6in_metal_describe() must match the recorded
        payload on the fields the launch path actually consumes.

        Drops the bandwidth fields (the synthetic fixture intentionally
        omits them) and any future AWS-side additions; only the fields
        eni_cap_from_describe_response and distribute_enis_across_cards
        read are required to match.
        """
        synthetic = _c6in_metal_describe()
        self.assertEqual(
            m.eni_cap_from_describe_response(synthetic),
            m.eni_cap_from_describe_response(self.recorded),
        )
        synthetic_cards = m.network_cards_from_describe_response(synthetic)
        recorded_cards = m.network_cards_from_describe_response(self.recorded)
        self.assertEqual(len(synthetic_cards), len(recorded_cards))
        synthetic_caps = sorted(
            (c["NetworkCardIndex"], c["MaximumNetworkInterfaces"])
            for c in synthetic_cards
        )
        recorded_caps = sorted(
            (c["NetworkCardIndex"], c["MaximumNetworkInterfaces"])
            for c in recorded_cards
        )
        self.assertEqual(synthetic_caps, recorded_caps)


if __name__ == "__main__":
    unittest.main()
