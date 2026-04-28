#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

import boto3
import botocore


DEFAULT_REGION = "us-east-1"
DEFAULT_INSTANCE_TYPE = "c6in.xlarge"
DEFAULT_DEBIAN_13_AMI_BY_REGION = {
    "us-east-1": "ami-06e3e2b7faca0265d",
}
DEFAULT_MANAGER_TAG = "anyscan-ec2-managed"
DEFAULT_WORKER_NAME = "anyscan-ec2-worker"
DEFAULT_CONTROL_PLANE_URL = "http://127.0.0.1:8088"
DEFAULT_INSTALL_URL = "https://scan.anyvm.tech/api/agent/install.sh?rebuild=false"
DEFAULT_GOOGLE_URL = "https://www.google.com"
DEFAULT_BOOTSTRAP_GRACE_SECONDS = 900
DEFAULT_WORKER_STALE_SECONDS = 90


def env_string(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return default
    value = value.strip()
    if not value:
        return default
    return value


def env_int(name: str, default: int) -> int:
    raw = env_string(name)
    if raw is None:
        return default
    return int(raw)


def split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    parts: list[str] = []
    for item in value.split(","):
        cleaned = item.strip()
        if cleaned and cleaned not in parts:
            parts.append(cleaned)
    return parts


def parse_max_enis(value: str | None) -> int | None:
    """Parse ANYSCAN_MAX_ENIS. Empty/unset preserves single-NIC behavior.

    Multi-ENI attach engages only when the operator opts in by setting
    ANYSCAN_MAX_ENIS to a positive integer. The recommended value on
    c6in.metal (and any instance type whose `MaximumNetworkInterfaces`
    reaches 15) is 15; the manager will clamp the requested count down
    to whatever the hardware actually exposes via DescribeInstanceTypes.
    Non-positive or non-integer inputs raise SystemExit so a typo in the
    operator's environment fails loudly rather than silently dropping
    back to single-NIC.
    """
    if value is None:
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        parsed = int(raw)
    except ValueError as exc:
        raise SystemExit(
            f"ANYSCAN_MAX_ENIS must be a positive integer, got {value!r}"
        ) from exc
    if parsed <= 0:
        raise SystemExit(
            f"ANYSCAN_MAX_ENIS must be a positive integer, got {parsed}"
        )
    return parsed


def compute_target_eni_count(hardware_cap: int, max_enis: int | None) -> int:
    """Return how many ENIs to attach at launch.

    When max_enis is None the manager keeps the legacy single-NIC launch
    path. When set, the attach count is clamped to min(hardware_cap,
    max_enis) — and to at least 1 even if the AWS describe call returned
    a clearly-bogus zero, so the launch never goes out with an empty
    NetworkInterfaces list.
    """
    if max_enis is None:
        return 1
    cap = max(1, hardware_cap)
    return max(1, min(cap, max_enis))


def distribute_enis_across_cards(
    target_count: int, network_cards: list[dict[str, Any]] | None
) -> list[tuple[int, int]]:
    """Place `target_count` ENIs across the instance's network cards.

    Returns a list of (NetworkCardIndex, per-card-DeviceIndex) tuples in
    the order ENIs should appear in the RunInstances NetworkInterfaces
    array. Round-robin across cards is preferred over packing one card:
    every additional card unlocks an independent PCIe queue/IRQ tree,
    which is the whole point of attaching more ENIs at this scale.

    On c6in.metal DescribeInstanceTypes returns NetworkCards = [
      {NetworkCardIndex:0, MaximumNetworkInterfaces:5},  (primary)
      {NetworkCardIndex:1, MaximumNetworkInterfaces:4},
      {NetworkCardIndex:2, MaximumNetworkInterfaces:3},
      {NetworkCardIndex:3, MaximumNetworkInterfaces:3},
    ] — total 15. Without per-card distribution, attaching 15 ENIs to
    card 0 (the default) hard-fails RunInstances because card 0 only
    has 5 slots.

    When `network_cards` is None or empty (single-card instance types,
    or a stripped-down DescribeInstanceTypes payload), all ENIs land on
    card 0 with sequential DeviceIndex values — the legacy single-card
    behavior every pre-c6in instance type uses.
    """
    if target_count < 1:
        raise ValueError("target_count must be >= 1")

    if not network_cards:
        return [(0, idx) for idx in range(target_count)]

    cards: list[tuple[int, int]] = []
    for card in network_cards:
        if not isinstance(card, dict):
            continue
        index = card.get("NetworkCardIndex")
        capacity = card.get("MaximumNetworkInterfaces")
        if not isinstance(index, int) or not isinstance(capacity, int):
            continue
        if capacity < 1:
            continue
        cards.append((index, capacity))
    if not cards:
        return [(0, idx) for idx in range(target_count)]
    cards.sort(key=lambda entry: entry[0])

    # Per-card next-DeviceIndex counter. The primary ENI must land on
    # the primary card (NetworkCardIndex 0) at DeviceIndex 0, and each
    # subsequent ENI takes the next free slot on the next card in
    # round-robin order.
    used: dict[int, int] = {index: 0 for index, _ in cards}
    capacity_by_card = dict(cards)
    placement: list[tuple[int, int]] = []

    # Force ENI 0 onto card 0 if card 0 exists; AWS rejects a primary
    # ENI on a non-zero card.
    primary_card = cards[0][0]
    placement.append((primary_card, 0))
    used[primary_card] = 1
    if target_count == 1:
        return placement

    card_order = [index for index, _ in cards]
    cursor = 1  # next card index in round-robin
    placed = 1
    while placed < target_count:
        # Advance through cards looking for the next one with a free
        # slot. If every card is full we silently truncate; the caller
        # has already clamped target_count to MaximumNetworkInterfaces
        # so this branch should be unreachable, but it keeps the helper
        # total instead of raising mid-launch.
        attempts = 0
        while attempts < len(card_order):
            card_index = card_order[cursor % len(card_order)]
            cursor += 1
            attempts += 1
            if used[card_index] < capacity_by_card[card_index]:
                placement.append((card_index, used[card_index]))
                used[card_index] += 1
                placed += 1
                break
        else:
            break
    return placement


def build_network_interfaces(
    *,
    target_count: int,
    subnet_ids: list[str],
    security_group_ids: list[str],
    network_cards: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Construct the NetworkInterfaces parameter for ec2:RunInstances.

    Subnets rotate round-robin through `subnet_ids` so an operator with
    a multi-AZ-incompatible /28 primary subnet can supply a comma list
    in ANYSCAN_EC2_ENI_SUBNET_IDS to spread secondaries across larger
    subnets in the same AZ. Single-subnet operators are unaffected:
    every ENI lands in `subnet_ids[0]`.

    `network_cards` (when supplied from DescribeInstanceTypes' NetworkInfo
    payload) drives ENI placement across physical network cards via
    `distribute_enis_across_cards` — required on multi-card instance
    types like c6in.metal where the primary card holds only 5 of the 15
    available ENI slots.
    """
    if target_count < 1:
        raise ValueError("target_count must be >= 1")
    if not subnet_ids:
        raise ValueError("subnet_ids must contain at least one subnet")
    placements = distribute_enis_across_cards(target_count, network_cards)
    interfaces: list[dict[str, Any]] = []
    for sequence_index, (card_index, device_index) in enumerate(placements):
        spec: dict[str, Any] = {
            "DeviceIndex": device_index,
            "SubnetId": subnet_ids[sequence_index % len(subnet_ids)],
        }
        # Only emit NetworkCardIndex when we actually had per-card data
        # to act on. Single-card instance types (the entire pre-c6in
        # fleet) keep the legacy payload shape; that matters because
        # some older instance types reject NetworkCardIndex outright.
        if network_cards:
            spec["NetworkCardIndex"] = card_index
        if security_group_ids:
            spec["Groups"] = list(security_group_ids)
        interfaces.append(spec)
    return interfaces


def eni_cap_from_describe_response(response: dict[str, Any]) -> int | None:
    """Pull MaximumNetworkInterfaces out of DescribeInstanceTypes payload.

    Returns None when the field is missing/malformed; callers fall back
    to a safe single-NIC launch in that case rather than guessing a
    higher number.
    """
    types = response.get("InstanceTypes") or []
    if not types:
        return None
    network = (types[0] or {}).get("NetworkInfo") or {}
    cap = network.get("MaximumNetworkInterfaces")
    if not isinstance(cap, int) or cap < 1:
        return None
    return cap


def network_cards_from_describe_response(
    response: dict[str, Any],
) -> list[dict[str, Any]]:
    """Pull the NetworkCards list out of DescribeInstanceTypes payload.

    Returns an empty list when the payload is missing the field — the
    caller treats that as "single-card instance type" and skips the
    NetworkCardIndex assignment.
    """
    types = response.get("InstanceTypes") or []
    if not types:
        return []
    network = (types[0] or {}).get("NetworkInfo") or {}
    cards = network.get("NetworkCards") or []
    if not isinstance(cards, list):
        return []
    return [card for card in cards if isinstance(card, dict)]


@dataclass
class ManagerConfig:
    region: str
    instance_type: str
    ami_id: str
    key_name: str | None
    ssh_private_key_path: Path
    subnet_id: str | None
    security_group_id: str | None
    instance_profile_arn: str | None
    worker_name: str
    worker_pool: str | None
    worker_tags: list[str]
    control_plane_url: str
    control_plane_username: str
    control_plane_password: str | None
    install_url: str
    google_healthcheck_url: str
    state_file: Path
    instance_id: str | None
    ssh_username: str
    ssh_source_cidr: str | None
    auto_authorize_ssh: bool
    bootstrap_grace_seconds: int
    worker_stale_seconds: int
    loop_interval_seconds: int
    # Multi-ENI launch knobs. When `max_enis` is None the manager preserves
    # the legacy single-NIC launch path (top-level SubnetId/SecurityGroupIds
    # passed to RunInstances). When `max_enis` is set, RunInstances is
    # invoked with an explicit NetworkInterfaces array sized to
    # min(hw_cap_from_describe_instance_types, max_enis); each ENI rotates
    # through `eni_subnet_ids` (defaults to `[subnet_id]`) and shares the
    # primary ENI's security group.
    max_enis: int | None
    eni_subnet_ids: list[str]

    @classmethod
    def from_env(cls) -> "ManagerConfig":
        region = env_string("ANYSCAN_EC2_REGION", env_string("AWS_DEFAULT_REGION", DEFAULT_REGION)) or DEFAULT_REGION
        ami_id = env_string("ANYSCAN_EC2_AMI_ID", DEFAULT_DEBIAN_13_AMI_BY_REGION.get(region))
        if not ami_id:
            raise SystemExit(
                f"No Debian 13 AMI configured for region {region}. Set ANYSCAN_EC2_AMI_ID explicitly."
            )
        default_key_name = f"anyscan-ec2-{region}"
        default_key_path = Path.home() / ".ssh" / default_key_name
        worker_tags = split_csv(env_string("ANYSCAN_EC2_WORKER_TAGS", DEFAULT_MANAGER_TAG))
        if DEFAULT_MANAGER_TAG not in worker_tags:
            worker_tags.insert(0, DEFAULT_MANAGER_TAG)
        return cls(
            region=region,
            instance_type=env_string("ANYSCAN_EC2_INSTANCE_TYPE", DEFAULT_INSTANCE_TYPE) or DEFAULT_INSTANCE_TYPE,
            ami_id=ami_id,
            key_name=env_string("ANYSCAN_EC2_KEY_NAME", default_key_name),
            ssh_private_key_path=Path(
                env_string("ANYSCAN_EC2_SSH_PRIVATE_KEY_PATH", str(default_key_path))
            ).expanduser(),
            subnet_id=env_string("ANYSCAN_EC2_SUBNET_ID"),
            security_group_id=env_string("ANYSCAN_EC2_SECURITY_GROUP_ID"),
            instance_profile_arn=env_string("ANYSCAN_EC2_INSTANCE_PROFILE_ARN"),
            worker_name=env_string("ANYSCAN_EC2_WORKER_NAME", DEFAULT_WORKER_NAME) or DEFAULT_WORKER_NAME,
            worker_pool=env_string("ANYSCAN_EC2_WORKER_POOL"),
            worker_tags=worker_tags,
            control_plane_url=env_string("ANYSCAN_EC2_CONTROL_PLANE_URL", DEFAULT_CONTROL_PLANE_URL)
            or DEFAULT_CONTROL_PLANE_URL,
            control_plane_username=env_string("ANYSCAN_EC2_CONTROL_PLANE_USERNAME", "admin") or "admin",
            control_plane_password=env_string("ANYSCAN_EC2_CONTROL_PLANE_PASSWORD"),
            install_url=env_string("ANYSCAN_EC2_INSTALL_URL", DEFAULT_INSTALL_URL) or DEFAULT_INSTALL_URL,
            google_healthcheck_url=env_string(
                "ANYSCAN_EC2_HEALTHCHECK_URL", DEFAULT_GOOGLE_URL
            )
            or DEFAULT_GOOGLE_URL,
            state_file=Path(
                env_string(
                    "ANYSCAN_EC2_STATE_FILE",
                    str(Path.home() / ".local" / "state" / "anyscan-ec2-manager.json"),
                )
            ).expanduser(),
            instance_id=env_string("ANYSCAN_EC2_INSTANCE_ID"),
            ssh_username=env_string("ANYSCAN_EC2_SSH_USERNAME", "admin") or "admin",
            ssh_source_cidr=env_string("ANYSCAN_EC2_SSH_SOURCE_CIDR"),
            auto_authorize_ssh=(env_string("ANYSCAN_EC2_AUTO_AUTHORIZE_SSH", "true") or "true").lower()
            in {"1", "true", "yes", "on"},
            bootstrap_grace_seconds=env_int(
                "ANYSCAN_EC2_BOOTSTRAP_GRACE_SECONDS", DEFAULT_BOOTSTRAP_GRACE_SECONDS
            ),
            worker_stale_seconds=env_int(
                "ANYSCAN_EC2_WORKER_STALE_SECONDS", DEFAULT_WORKER_STALE_SECONDS
            ),
            loop_interval_seconds=env_int("ANYSCAN_EC2_LOOP_INTERVAL_SECONDS", 60),
            max_enis=parse_max_enis(env_string("ANYSCAN_MAX_ENIS")),
            eni_subnet_ids=split_csv(env_string("ANYSCAN_EC2_ENI_SUBNET_IDS")),
        )


def parse_iso_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def select_best_matching_worker(
    workers: list[dict[str, Any]], instance: dict[str, Any] | None
) -> dict[str, Any] | None:
    if not workers:
        return None
    if instance:
        private_ip = instance.get("PrivateIpAddress")
        public_ip = instance.get("PublicIpAddress")
        for worker in workers:
            local_ips = worker.get("local_ip_addresses") or []
            if private_ip and private_ip in local_ips:
                return worker
            if public_ip and worker.get("public_ip_address") == public_ip:
                return worker
    workers = sorted(
        workers,
        key=lambda worker: parse_iso_datetime(worker.get("last_seen_at")) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return workers[0]


class AnyScanApiClient:
    def __init__(self, config: ManagerConfig) -> None:
        self.base_url = config.control_plane_url.rstrip("/")
        self.username = config.control_plane_username
        self.password = config.control_plane_password
        self.cookie: str | None = None

    def _request(
        self, path: str, *, method: str = "GET", json_body: dict[str, Any] | None = None, auth: bool = True
    ) -> Any:
        if auth and not self.cookie:
            self.login()
        headers: dict[str, str] = {}
        if self.cookie:
            headers["Cookie"] = self.cookie
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode()
            headers["content-type"] = "application/json"
        req = urlrequest.Request(
            f"{self.base_url}{path}",
            method=method,
            data=data,
            headers=headers,
        )
        with urlrequest.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode()
            if "Set-Cookie" in resp.headers:
                self.cookie = resp.headers["Set-Cookie"].split(";", 1)[0]
            if not raw:
                return None
            return json.loads(raw)

    def login(self) -> None:
        if not self.password:
            raise RuntimeError("ANYSCAN_EC2_CONTROL_PLANE_PASSWORD is required for AnyScan health checks")
        self._request(
            "/api/session",
            method="POST",
            json_body={"username": self.username, "password": self.password},
            auth=False,
        )

    def list_workers(self) -> list[dict[str, Any]]:
        workers = self._request("/api/workers")
        return workers or []


class Ec2WorkerManager:
    def __init__(self, config: ManagerConfig) -> None:
        self.config = config
        self.state = self._load_state()
        self.session = boto3.Session(
            aws_access_key_id=env_string("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=env_string("AWS_SECRET_ACCESS_KEY"),
            aws_session_token=env_string("AWS_SESSION_TOKEN"),
            region_name=config.region,
        )
        self.ec2 = self.session.client("ec2")
        self.ec2_resource = self.session.resource("ec2")
        self.sts = self.session.client("sts")
        self.api = AnyScanApiClient(config)

    def _load_state(self) -> dict[str, Any]:
        if self.config.state_file.exists():
            return json.loads(self.config.state_file.read_text())
        return {}

    def _save_state(self) -> None:
        self.config.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.config.state_file.write_text(
            json.dumps(self.state, indent=2, sort_keys=True, default=str)
        )

    def _list_managed_instances(self) -> list[dict[str, Any]]:
        response = self.ec2.describe_instances(
            Filters=[
                {"Name": "tag:Name", "Values": [self.config.worker_name]},
                {
                    "Name": "instance-state-name",
                    "Values": ["pending", "running", "stopping", "stopped"],
                },
            ]
        )
        instances: list[dict[str, Any]] = []
        for reservation in response.get("Reservations", []):
            instances.extend(reservation.get("Instances", []))
        return instances

    def current_instance_id(self) -> str | None:
        instance_id = self.state.get("instance_id") or self.config.instance_id
        if instance_id:
            return instance_id
        instances = self._list_managed_instances()
        if len(instances) == 1:
            adopted = instances[0]
            self.state["instance_id"] = adopted["InstanceId"]
            launch_time = adopted.get("LaunchTime")
            if launch_time is not None:
                try:
                    self.state["launched_at_epoch"] = launch_time.timestamp()
                except Exception:
                    pass
            self.state["last_launch"] = adopted
            self._save_state()
            return adopted["InstanceId"]
        return None

    def set_instance_id(self, instance_id: str | None) -> None:
        if instance_id:
            self.state["instance_id"] = instance_id
        else:
            self.state.pop("instance_id", None)
        self._save_state()

    def preflight(self) -> dict[str, Any]:
        results: dict[str, Any] = {"config": asdict(self.config)}
        try:
            results["identity"] = self.sts.get_caller_identity()
        except Exception as exc:
            results["identity_error"] = str(exc)
            return results

        checks = {
            "ec2_describe_instances": lambda: self.ec2.describe_instances(MaxResults=5),
            "ec2_describe_instance_status": lambda: self.ec2.describe_instance_status(
                InstanceIds=[self.current_instance_id()] if self.current_instance_id() else [],
                IncludeAllInstances=True,
                DryRun=False,
            ),
            "ec2_run_instances_dry_run": lambda: self.ec2.run_instances(
                ImageId=self.config.ami_id,
                MinCount=1,
                MaxCount=1,
                InstanceType=self.config.instance_type,
                DryRun=True,
            ),
            "ec2_create_key_pair_dry_run": lambda: self.ec2.create_key_pair(
                KeyName=(self.config.key_name or "anyscan-ec2"), DryRun=True
            ),
            "ec2_import_key_pair_dry_run": lambda: self.ec2.import_key_pair(
                KeyName=(self.config.key_name or "anyscan-ec2"),
                PublicKeyMaterial=b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest anyscan",
                DryRun=True,
            ),
        }
        for name, fn in checks.items():
            try:
                fn()
                results[name] = "ok"
            except botocore.exceptions.ClientError as exc:
                results[name] = {
                    "code": exc.response["Error"].get("Code"),
                    "message": exc.response["Error"].get("Message"),
                }
            except Exception as exc:
                results[name] = {"error": str(exc)}
        return results

    def create_keypair(self) -> dict[str, Any]:
        key_name = self.config.key_name or f"anyscan-ec2-{self.config.region}"
        private_key = self.config.ssh_private_key_path
        public_key = private_key.with_suffix(private_key.suffix + ".pub")
        private_key.parent.mkdir(parents=True, exist_ok=True)
        if not private_key.exists():
            subprocess.run(
                [
                    "ssh-keygen",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    f"anyscan-ec2-{self.config.region}",
                    "-f",
                    str(private_key),
                ],
                check=True,
            )
        public_material = public_key.read_bytes()
        try:
            response = self.ec2.import_key_pair(
                KeyName=key_name,
                PublicKeyMaterial=public_material,
                TagSpecifications=[
                    {
                        "ResourceType": "key-pair",
                        "Tags": [
                            {"Key": "Name", "Value": key_name},
                            {"Key": "ManagedBy", "Value": "AnyScan"},
                        ],
                    }
                ],
            )
        except botocore.exceptions.ClientError as exc:
            return {
                "created_local_private_key": str(private_key),
                "created_local_public_key": str(public_key),
                "aws_error": {
                    "code": exc.response["Error"].get("Code"),
                    "message": exc.response["Error"].get("Message"),
                },
            }
        return {
            "key_name": key_name,
            "private_key_path": str(private_key),
            "public_key_path": str(public_key),
            "fingerprint": response.get("KeyFingerprint"),
            "key_pair_id": response.get("KeyPairId"),
        }

    def _instance_status(self) -> dict[str, Any] | None:
        instance_id = self.current_instance_id()
        if not instance_id:
            return None
        response = self.ec2.describe_instance_status(
            InstanceIds=[instance_id],
            IncludeAllInstances=True,
        )
        statuses = response.get("InstanceStatuses", [])
        return statuses[0] if statuses else None

    def _instance_launch_time(self) -> float | None:
        launch_time = self.state.get("launched_at_epoch")
        if isinstance(launch_time, (int, float)):
            return float(launch_time)
        instance = self._describe_instance()
        if not instance:
            return None
        value = instance.get("LaunchTime")
        if value is None:
            return None
        try:
            return value.timestamp()
        except Exception:
            return None

    def _describe_instance(self) -> dict[str, Any] | None:
        instance_id = self.current_instance_id()
        if not instance_id:
            return None
        response = self.ec2.describe_instances(InstanceIds=[instance_id])
        reservations = response.get("Reservations", [])
        for reservation in reservations:
            instances = reservation.get("Instances", [])
            if instances:
                return instances[0]
        return None

    def _ssh_google_healthcheck(self, host: str) -> tuple[bool, str]:
        if not self.config.ssh_private_key_path.exists():
            return False, f"missing ssh key at {self.config.ssh_private_key_path}"
        cmd = [
            "ssh",
            "-i",
            str(self.config.ssh_private_key_path),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            f"{self.config.ssh_username}@{host}",
            f"timeout 15 curl -fsSIL {shlex.quote(self.config.google_healthcheck_url)} >/dev/null",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        combined = (proc.stdout + proc.stderr).strip()
        return proc.returncode == 0, combined

    def _current_public_ip_cidr(self) -> str:
        if self.config.ssh_source_cidr:
            return self.config.ssh_source_cidr
        with urlrequest.urlopen("https://checkip.amazonaws.com", timeout=10) as resp:
            address = resp.read().decode().strip()
        return f"{address}/32"

    def ensure_ssh_access(self) -> dict[str, Any] | None:
        if not self.config.auto_authorize_ssh or not self.config.security_group_id:
            return None
        cidr = self._current_public_ip_cidr()
        try:
            self.ec2.authorize_security_group_ingress(
                GroupId=self.config.security_group_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": cidr, "Description": "AnyScan EC2 manager SSH healthcheck"}],
                    }
                ],
            )
            return {"authorized": True, "cidr": cidr}
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"].get("Code")
            if code == "InvalidPermission.Duplicate":
                return {"authorized": False, "cidr": cidr, "already_present": True}
            raise

    def _anyscan_health(self) -> tuple[bool, dict[str, Any] | None, str]:
        instance_for_match = None
        try:
            instance_for_match = self._describe_instance()
        except botocore.exceptions.ClientError:
            instance_for_match = None

        try:
            workers = self.api.list_workers()
        except Exception as exc:
            return False, None, f"AnyScan API error: {exc}"
        matching_workers = [
            worker
            for worker in workers
            if worker.get("display_name") == self.config.worker_name
            or worker.get("worker_id") == self.config.worker_name
        ]
        worker = select_best_matching_worker(matching_workers, instance_for_match)
        if worker is None:
            return False, None, f"worker {self.config.worker_name} not visible in AnyScan"
        now = datetime.now(timezone.utc)
        last_seen_at = parse_iso_datetime(worker.get("last_seen_at"))
        expires_at = parse_iso_datetime(worker.get("expires_at"))
        if expires_at and expires_at <= now:
            return False, worker, "worker lease expired in AnyScan"
        if last_seen_at:
            age_seconds = (now - last_seen_at).total_seconds()
            if age_seconds > self.config.worker_stale_seconds:
                return (
                    False,
                    worker,
                    f"worker heartbeat stale in AnyScan ({int(age_seconds)}s old)",
                )
        if worker.get("control_plane_health_message"):
            return False, worker, worker["control_plane_health_message"]
        return True, worker, ""

    def health_snapshot(self) -> dict[str, Any]:
        snapshot: dict[str, Any] = {}
        anyscan_ok, worker, anyscan_reason = self._anyscan_health()
        snapshot["anyscan_ok"] = anyscan_ok
        snapshot["anyscan_reason"] = anyscan_reason or None
        snapshot["worker"] = worker

        public_ip = None
        if worker:
            public_ip = worker.get("public_ip_address")
        instance = None
        try:
            instance = self._describe_instance()
            snapshot["instance"] = instance
            public_ip = public_ip or (instance or {}).get("PublicIpAddress")
        except botocore.exceptions.ClientError as exc:
            snapshot["instance_error"] = {
                "code": exc.response["Error"].get("Code"),
                "message": exc.response["Error"].get("Message"),
            }
        try:
            status = self._instance_status()
            snapshot["instance_status"] = status
        except botocore.exceptions.ClientError as exc:
            snapshot["instance_status_error"] = {
                "code": exc.response["Error"].get("Code"),
                "message": exc.response["Error"].get("Message"),
            }

        if public_ip:
            ssh_ok, detail = self._ssh_google_healthcheck(public_ip)
            snapshot["ssh_google_ok"] = ssh_ok
            snapshot["ssh_google_detail"] = detail or None
            snapshot["public_ip"] = public_ip
        else:
            snapshot["ssh_google_ok"] = False
            snapshot["ssh_google_detail"] = "no public IP available"

        launched_at = self._instance_launch_time()
        bootstrap_grace_remaining = None
        if launched_at is not None:
            snapshot["launched_at_epoch"] = launched_at
            bootstrap_grace_remaining = max(
                0, int(launched_at + self.config.bootstrap_grace_seconds - time.time())
            )
            snapshot["bootstrap_grace_remaining_seconds"] = bootstrap_grace_remaining

        # Once bootstrap grace is over, a live AnyScan worker heartbeat is required.
        # SSH + outbound curl is useful to distinguish "instance is alive" from
        # "instance is dead", but it should not keep a workerless instance in rotation.
        if snapshot["anyscan_ok"]:
            snapshot["healthy"] = True
        elif bootstrap_grace_remaining is not None and bootstrap_grace_remaining > 0:
            snapshot["healthy"] = bool(snapshot["ssh_google_ok"])
        else:
            snapshot["healthy"] = False

        if snapshot.get("instance_status"):
            instance_status = snapshot["instance_status"]
            system_ok = instance_status.get("SystemStatus", {}).get("Status") == "ok"
            instance_ok = instance_status.get("InstanceStatus", {}).get("Status") == "ok"
            state_name = instance_status.get("InstanceState", {}).get("Name")
            snapshot["healthy"] = bool(snapshot["healthy"] and system_ok and instance_ok and state_name == "running")
        return snapshot

    def build_user_data(self) -> str:
        worker_tags = ",".join(self.config.worker_tags)
        lines = [
            "#!/usr/bin/env bash",
            "set -euxo pipefail",
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y curl ca-certificates",
            f"INSTALL_URL_BASE={shlex.quote(self.config.install_url)}",
            'case "$INSTALL_URL_BASE" in',
            '  *\\?*) INSTALL_URL="${INSTALL_URL_BASE}&v=$(date +%s)" ;;',
            '  *) INSTALL_URL="${INSTALL_URL_BASE}?v=$(date +%s)" ;;',
            'esac',
            'curl -fsSL "$INSTALL_URL" | bash',
            "RUNTIME_ENV=/etc/agentd/runtime.env",
            "if [ -f \"$RUNTIME_ENV\" ]; then",
            f"  grep -q '^AGENT_NAME=' \"$RUNTIME_ENV\" && sed -i 's#^AGENT_NAME=.*#AGENT_NAME={shlex.quote(self.config.worker_name)}#' \"$RUNTIME_ENV\" || echo AGENT_NAME={shlex.quote(self.config.worker_name)} >> \"$RUNTIME_ENV\"",
            f"  grep -q '^AGENT_TAGS=' \"$RUNTIME_ENV\" && sed -i 's#^AGENT_TAGS=.*#AGENT_TAGS={shlex.quote(worker_tags)}#' \"$RUNTIME_ENV\" || echo AGENT_TAGS={shlex.quote(worker_tags)} >> \"$RUNTIME_ENV\"",
        ]
        if self.config.worker_pool:
            lines.append(
                f"  grep -q '^AGENT_POOL=' \"$RUNTIME_ENV\" && sed -i 's#^AGENT_POOL=.*#AGENT_POOL={shlex.quote(self.config.worker_pool)}#' \"$RUNTIME_ENV\" || echo AGENT_POOL={shlex.quote(self.config.worker_pool)} >> \"$RUNTIME_ENV\""
            )
        lines.extend(
            [
                "  systemctl restart agentd.service agentd-tunnel.service || true",
                "fi",
            ]
        )
        return "\n".join(lines) + "\n"

    def _describe_instance_type_network_info(
        self,
    ) -> tuple[int | None, list[dict[str, Any]]]:
        """Look up ENI cap + NetworkCards layout for the configured type.

        Returns (cap, network_cards). `cap` is None on any failure path
        so callers can fall back to a single-NIC launch instead of
        guessing — the cost of guessing too high is a hard RunInstances
        failure that takes the whole worker offline. NetworkCards is a
        list (possibly empty) of {NetworkCardIndex, MaximumNetworkInterfaces}
        dicts copied from the DescribeInstanceTypes payload; consumed by
        `distribute_enis_across_cards` so 15-ENI launches on c6in.metal
        spread correctly across the 4 physical cards.
        """
        try:
            response = self.ec2.describe_instance_types(
                InstanceTypes=[self.config.instance_type]
            )
        except botocore.exceptions.ClientError:
            return None, []
        except Exception:
            return None, []
        return (
            eni_cap_from_describe_response(response),
            network_cards_from_describe_response(response),
        )

    def _resolve_eni_subnet_pool(self) -> list[str]:
        """Return the ordered subnet pool ENI specs round-robin through.

        Defaults to the single primary subnet so single-subnet operators
        get min(N, hw_cap) ENIs in one subnet without extra config. When
        the operator sets ANYSCAN_EC2_ENI_SUBNET_IDS the pool is taken
        from there verbatim; the primary subnet (for legacy single-NIC
        launches) is left as ANYSCAN_EC2_SUBNET_ID and unaffected.
        """
        if self.config.eni_subnet_ids:
            return list(self.config.eni_subnet_ids)
        if self.config.subnet_id:
            return [self.config.subnet_id]
        return []

    def recreate_instance(self) -> dict[str, Any]:
        current_id = self.current_instance_id()
        terminated = None
        if current_id:
            terminated = self.ec2.terminate_instances(InstanceIds=[current_id])
        ssh_rule = self.ensure_ssh_access()
        launch_args: dict[str, Any] = {
            "ImageId": self.config.ami_id,
            "InstanceType": self.config.instance_type,
            "MinCount": 1,
            "MaxCount": 1,
            "UserData": self.build_user_data(),
            "TagSpecifications": [
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": self.config.worker_name},
                        {"Key": "ManagedBy", "Value": "AnyScan"},
                        {"Key": "Role", "Value": "AnyScanWorker"},
                    ],
                }
            ],
        }
        if self.config.key_name:
            launch_args["KeyName"] = self.config.key_name
        if self.config.instance_profile_arn:
            launch_args["IamInstanceProfile"] = {"Arn": self.config.instance_profile_arn}

        # Multi-ENI launch path: only engages when the operator opts in
        # via ANYSCAN_MAX_ENIS. Single-NIC behavior is preserved when the
        # env var is unset so existing fleets are unaffected.
        eni_attach_info: dict[str, Any] = {"requested": self.config.max_enis}
        target_count = 1
        network_cards: list[dict[str, Any]] = []
        if self.config.max_enis is not None:
            hw_cap, network_cards = self._describe_instance_type_network_info()
            eni_attach_info["hardware_cap"] = hw_cap
            eni_attach_info["network_cards"] = network_cards
            if hw_cap is None:
                # Describe failed — fall back to single-NIC rather than
                # guessing 15 and failing RunInstances. The operator can
                # raise the IAM permission and retry; the worker stays
                # up on one NIC in the meantime.
                eni_attach_info["fallback_reason"] = (
                    "DescribeInstanceTypes returned no usable cap; falling back to single-NIC launch"
                )
            else:
                target_count = compute_target_eni_count(hw_cap, self.config.max_enis)

        if target_count > 1:
            subnet_pool = self._resolve_eni_subnet_pool()
            if not subnet_pool:
                eni_attach_info["fallback_reason"] = (
                    "no subnet configured (ANYSCAN_EC2_SUBNET_ID and ANYSCAN_EC2_ENI_SUBNET_IDS both empty); falling back to single-NIC launch"
                )
                target_count = 1
            else:
                security_group_ids = (
                    [self.config.security_group_id] if self.config.security_group_id else []
                )
                launch_args["NetworkInterfaces"] = build_network_interfaces(
                    target_count=target_count,
                    subnet_ids=subnet_pool,
                    security_group_ids=security_group_ids,
                    network_cards=network_cards,
                )
                eni_attach_info["attached"] = target_count
                eni_attach_info["subnet_pool"] = subnet_pool

        if target_count == 1:
            # Legacy single-NIC path: top-level SubnetId/SecurityGroupIds
            # are mutually exclusive with NetworkInterfaces, so we only
            # set them on this branch.
            if self.config.security_group_id:
                launch_args["SecurityGroupIds"] = [self.config.security_group_id]
            if self.config.subnet_id:
                launch_args["SubnetId"] = self.config.subnet_id

        response = self.ec2.run_instances(**launch_args)
        instance = response["Instances"][0]
        self.set_instance_id(instance["InstanceId"])
        self.state["last_launch"] = instance
        launch_time = instance.get("LaunchTime")
        if launch_time is not None:
            try:
                self.state["launched_at_epoch"] = launch_time.timestamp()
            except Exception:
                pass
        self._save_state()
        return {
            "terminated": terminated,
            "launched": instance,
            "ssh_rule": ssh_rule,
            "eni_attach": eni_attach_info,
        }

    def run_once(self) -> dict[str, Any]:
        snapshot = self.health_snapshot()
        grace_remaining = snapshot.get("bootstrap_grace_remaining_seconds")
        instance = snapshot.get("instance") or {}
        instance_status = snapshot.get("instance_status") or {}
        instance_state = (
            instance.get("State", {}).get("Name")
            or instance_status.get("InstanceState", {}).get("Name")
        )
        instance_status_name = instance_status.get("InstanceStatus", {}).get("Status")
        system_status_name = instance_status.get("SystemStatus", {}).get("Status")
        bootstrapping_instance = instance_state in {"pending", "running"} and (
            instance_status_name in {None, "initializing", "ok"}
            and system_status_name in {None, "initializing", "ok"}
        )
        if (
            isinstance(grace_remaining, int)
            and grace_remaining > 0
            and bootstrapping_instance
            and not snapshot["anyscan_ok"]
        ):
            return {"action": "grace_period", "health": snapshot}
        if snapshot["healthy"]:
            return {"action": "noop", "health": snapshot}
        recreated = None
        try:
            recreated = self.recreate_instance()
        except botocore.exceptions.ClientError as exc:
            return {
                "action": "recreate_failed",
                "health": snapshot,
                "aws_error": {
                    "code": exc.response["Error"].get("Code"),
                    "message": exc.response["Error"].get("Message"),
                },
            }
        return {"action": "recreated", "health": snapshot, "result": recreated}

    def daemon(self) -> None:
        while True:
            result = self.run_once()
            print(json.dumps(result, indent=2, default=str), flush=True)
            time.sleep(max(5, self.config.loop_interval_seconds))


class ManagerLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle: Any | None = None

    def __enter__(self) -> "ManagerLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+")
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit(f"EC2 worker manager lock is already held: {self.path}")
        self.handle.seek(0)
        self.handle.truncate()
        self.handle.write(str(os.getpid()))
        self.handle.flush()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.handle is None:
            return
        try:
            self.handle.seek(0)
            self.handle.truncate()
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()
            self.handle = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage and recreate an EC2 AnyScan worker when it stops responding.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("preflight", help="Validate IAM permissions and local configuration.")
    subparsers.add_parser("create-keypair", help="Create a local SSH keypair and attempt to import it into EC2.")
    subparsers.add_parser("once", help="Run one health/recreate cycle.")
    subparsers.add_parser("daemon", help="Run the health/recreate loop continuously.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    config = ManagerConfig.from_env()
    lock_path = config.state_file.with_suffix(".lock")

    with ManagerLock(lock_path):
        manager = Ec2WorkerManager(config)

        if args.command == "preflight":
            print(json.dumps(manager.preflight(), indent=2, default=str))
            return 0
        if args.command == "create-keypair":
            print(json.dumps(manager.create_keypair(), indent=2, default=str))
            return 0
        if args.command == "once":
            print(json.dumps(manager.run_once(), indent=2, default=str))
            return 0
        if args.command == "daemon":
            manager.daemon()
            return 0
        raise SystemExit(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
