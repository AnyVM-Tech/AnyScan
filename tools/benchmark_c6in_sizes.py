#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from http import cookiejar

import boto3


DEFAULT_REGION = "us-east-1"
DEFAULT_AMI = "ami-06e3e2b7faca0265d"
DEFAULT_TYPES = [
    "c6in.large",
    "c6in.xlarge",
    "c6in.2xlarge",
    "c6in.4xlarge",
    "c6in.8xlarge",
]
DEFAULT_CONTROL_PLANE = "http://127.0.0.1:8088"
DEFAULT_INSTALL_URL = "https://scan.anyvm.tech/api/agent/install.sh?rebuild=false"
DEFAULT_KEY_NAME = "anyscan-ec2-us-east-1"
DEFAULT_KEY_PATH = "/root/.ssh/anyscan-ec2-us-east-1"
DEFAULT_SG = "sg-033a89d74c7d2eb57"
DEFAULT_SUBNET = "subnet-0a8e834fdf69c0839"
SCANNER_REPO = "https://github.com/Lorikazzzz/VulnScanner-zmap-alternative-.git"


def env_string(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return default
    value = value.strip()
    return value or default


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AnyScanApiClient:
    def __init__(self, base_url: str, username: str, password: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.cookies = cookiejar.CookieJar()
        self.opener = urlrequest.build_opener(urlrequest.HTTPCookieProcessor(self.cookies))

    def login(self) -> None:
        req = urlrequest.Request(
            f"{self.base_url}/api/session",
            data=json.dumps({"username": self.username, "password": self.password}).encode(),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with self.opener.open(req, timeout=20):
            pass

    def request(self, path: str, method: str = "GET", body: dict[str, Any] | None = None) -> Any:
        data = None
        headers: dict[str, str] = {}
        if body is not None:
            data = json.dumps(body).encode()
            headers["content-type"] = "application/json"
        req = urlrequest.Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        with self.opener.open(req, timeout=30) as response:
            raw = response.read().decode()
        return json.loads(raw) if raw else None

    def find_worker(self, display_name: str) -> dict[str, Any] | None:
        workers = self.request("/api/workers")
        for worker in workers or []:
            if worker.get("display_name") == display_name:
                return worker
        return None

    def queue_remote_command(self, worker_id: str, command: str, timeout_seconds: int) -> dict[str, Any]:
        return self.request(
            f"/api/workers/{worker_id}/remote-commands",
            method="POST",
            body={"command": command, "timeout_seconds": timeout_seconds},
        )

    def wait_remote_command(self, worker_id: str, command_id: int, timeout_seconds: int = 180) -> dict[str, Any]:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            commands = self.request(f"/api/worker-remote-commands?limit=20&worker_id={worker_id}") or []
            for command in commands:
                if command.get("id") == command_id:
                    if command.get("status") in {"completed", "failed"}:
                        return command
            time.sleep(2)
        raise TimeoutError(f"remote command {command_id} on {worker_id} did not finish in time")


@dataclass
class BenchmarkConfig:
    region: str
    ami_id: str
    subnet_id: str
    security_group_id: str
    key_name: str
    key_path: Path
    install_url: str
    control_plane_url: str
    control_plane_username: str
    control_plane_password: str


def build_user_data(worker_name: str) -> str:
    lines = [
        "#!/usr/bin/env bash",
        "set -euxo pipefail",
        "export DEBIAN_FRONTEND=noninteractive",
        "apt-get update",
        "apt-get install -y curl ca-certificates build-essential git",
        f"git clone {SCANNER_REPO} /root/VulnScanner-zmap-alternative-",
        "cd /root/VulnScanner-zmap-alternative-",
        "make",
        "make install",
        f"INSTALL_URL_BASE={json.dumps(env_string('ANYSCAN_EC2_INSTALL_URL', DEFAULT_INSTALL_URL))}",
        'case "$INSTALL_URL_BASE" in',
        '  *\\?*) INSTALL_URL="${INSTALL_URL_BASE}&v=$(date +%s)" ;;',
        '  *) INSTALL_URL="${INSTALL_URL_BASE}?v=$(date +%s)" ;;',
        'esac',
        'curl -fsSL "$INSTALL_URL" | bash',
        'RUNTIME_ENV=/etc/agentd/runtime.env',
        'if [ -f "$RUNTIME_ENV" ]; then',
        f'  grep -q "^AGENT_NAME=" "$RUNTIME_ENV" && sed -i "s#^AGENT_NAME=.*#AGENT_NAME={worker_name}#" "$RUNTIME_ENV" || echo AGENT_NAME={worker_name} >> "$RUNTIME_ENV"',
        f'  grep -q "^AGENT_TAGS=" "$RUNTIME_ENV" && sed -i "s#^AGENT_TAGS=.*#AGENT_TAGS=anyscan-bench,{worker_name}#" "$RUNTIME_ENV" || echo AGENT_TAGS=anyscan-bench,{worker_name} >> "$RUNTIME_ENV"',
        '  grep -q "^SCANNER_BIN=" "$RUNTIME_ENV" && sed -i "s#^SCANNER_BIN=.*#SCANNER_BIN=/usr/bin/scanner#" "$RUNTIME_ENV" || echo SCANNER_BIN=/usr/bin/scanner >> "$RUNTIME_ENV"',
        '  systemctl restart agentd.service agentd-tunnel.service || true',
        'fi',
    ]
    return "\n".join(lines) + "\n"


def get_price_map(region_label: str, instance_types: list[str]) -> dict[str, float | None]:
    pricing = boto3.client("pricing", region_name="us-east-1")
    price_map: dict[str, float | None] = {}
    for instance_type in instance_types:
        price = None
        response = pricing.get_products(
            ServiceCode="AmazonEC2",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
                {"Type": "TERM_MATCH", "Field": "location", "Value": region_label},
                {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
                {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
                {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
                {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
            ],
            MaxResults=20,
        )
        for payload in response.get("PriceList", []):
            document = json.loads(payload)
            for term in document.get("terms", {}).get("OnDemand", {}).values():
                for dim in term.get("priceDimensions", {}).values():
                    usd = dim.get("pricePerUnit", {}).get("USD")
                    if usd not in (None, ""):
                        price = float(usd)
                        break
                if price is not None:
                    break
            if price is not None:
                break
        price_map[instance_type] = price
    return price_map


def wait_for_instance_running(ec2: Any, instance_id: str, timeout_seconds: int = 300) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        instance = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
        if instance["State"]["Name"] == "running" and instance.get("PublicIpAddress"):
            return instance
        time.sleep(5)
    raise TimeoutError(f"instance {instance_id} did not reach running state in time")


def wait_for_worker(api: AnyScanApiClient, display_name: str, timeout_seconds: int = 600) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        worker = api.find_worker(display_name)
        if worker is not None:
            return worker
        time.sleep(5)
    raise TimeoutError(f"worker {display_name} did not register in time")


def benchmark_command() -> str:
    return r'''iface=${SCANNER_INTERFACE:-$(ip route show default | awk '/default/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')}; \
threads=$(nproc); \
bin=/usr/bin/scanner; \
tx1=$(cat /sys/class/net/$iface/statistics/tx_packets); \
rx1=$(cat /sys/class/net/$iface/statistics/rx_packets); \
"$bin" -i "$iface" -p 80 -t 0.0.0.0/0 -T "$threads" -R "$threads" -r 0 -q >/tmp/anyscan-bench.out 2>/tmp/anyscan-bench.err & \
pid=$!; \
sleep 5; \
tx2=$(cat /sys/class/net/$iface/statistics/tx_packets); \
rx2=$(cat /sys/class/net/$iface/statistics/rx_packets); \
kill -INT "$pid" 2>/dev/null || true; sleep 1; kill -KILL "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; \
echo IFACE=$iface; echo THREADS=$threads; echo TX_DELTA=$((tx2-tx1)); echo RX_DELTA=$((rx2-rx1)); echo TX_PPS=$(((tx2-tx1)/5)); echo RX_PPS=$(((rx2-rx1)/5)); echo BENCH_AT=''' + utc_now()


def parse_benchmark_stdout(output: str) -> dict[str, Any]:
    result: dict[str, Any] = {"stdout": output}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key in {"THREADS", "TX_DELTA", "RX_DELTA", "TX_PPS", "RX_PPS"}:
            try:
                result[key.lower()] = int(value)
            except ValueError:
                result[key.lower()] = value
        else:
            result[key.lower()] = value
    return result


def terminate_instance(ec2: Any, instance_id: str) -> None:
    ec2.terminate_instances(InstanceIds=[instance_id])


def benchmark_instance_type(config: BenchmarkConfig, api: AnyScanApiClient, ec2: Any, instance_type: str, price_per_hour: float | None) -> dict[str, Any]:
    worker_name = f"anyscan-bench-{instance_type.replace('.', '-')}-{uuid.uuid4().hex[:8]}"
    launch = ec2.run_instances(
        ImageId=config.ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        KeyName=config.key_name,
        SecurityGroupIds=[config.security_group_id],
        SubnetId=config.subnet_id,
        UserData=build_user_data(worker_name),
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": worker_name},
                    {"Key": "ManagedBy", "Value": "AnyScanBenchmark"},
                    {"Key": "Role", "Value": "AnyScanBenchmark"},
                ],
            }
        ],
    )
    instance_id = launch["Instances"][0]["InstanceId"]
    instance = wait_for_instance_running(ec2, instance_id)
    worker = None
    benchmark_result: dict[str, Any] = {}
    try:
        worker = wait_for_worker(api, worker_name)
        command = api.queue_remote_command(worker["worker_id"], benchmark_command(), 30)
        completed = api.wait_remote_command(worker["worker_id"], command["id"], timeout_seconds=180)
        benchmark_result = parse_benchmark_stdout(completed.get("stdout") or "")
        benchmark_result["remote_command_status"] = completed.get("status")
        benchmark_result["remote_command_exit_code"] = completed.get("exit_code")
        benchmark_result["stderr"] = completed.get("stderr")
    finally:
        terminate_instance(ec2, instance_id)

    tx_pps = benchmark_result.get("tx_pps")
    return {
        "instance_type": instance_type,
        "instance_id": instance_id,
        "public_ip": instance.get("PublicIpAddress"),
        "worker_id": worker.get("worker_id") if worker else None,
        "price_per_hour_usd": price_per_hour,
        "tx_pps": tx_pps,
        "rx_pps": benchmark_result.get("rx_pps"),
        "threads": benchmark_result.get("threads"),
        "iface": benchmark_result.get("iface"),
        "pps_per_dollar_hour": (tx_pps / price_per_hour) if isinstance(tx_pps, int) and price_per_hour else None,
        "details": benchmark_result,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark c6in instance sizes for AnyScan scanner throughput.")
    parser.add_argument("--region", default=env_string("ANYSCAN_EC2_REGION", DEFAULT_REGION) or DEFAULT_REGION)
    parser.add_argument("--ami-id", default=env_string("ANYSCAN_EC2_AMI_ID", DEFAULT_AMI) or DEFAULT_AMI)
    parser.add_argument("--subnet-id", default=env_string("ANYSCAN_EC2_SUBNET_ID", DEFAULT_SUBNET) or DEFAULT_SUBNET)
    parser.add_argument("--security-group-id", default=env_string("ANYSCAN_EC2_SECURITY_GROUP_ID", DEFAULT_SG) or DEFAULT_SG)
    parser.add_argument("--key-name", default=env_string("ANYSCAN_EC2_KEY_NAME", DEFAULT_KEY_NAME) or DEFAULT_KEY_NAME)
    parser.add_argument("--install-url", default=env_string("ANYSCAN_EC2_INSTALL_URL", DEFAULT_INSTALL_URL) or DEFAULT_INSTALL_URL)
    parser.add_argument("--control-plane-url", default=env_string("ANYSCAN_EC2_CONTROL_PLANE_URL", DEFAULT_CONTROL_PLANE) or DEFAULT_CONTROL_PLANE)
    parser.add_argument("--username", default=env_string("ANYSCAN_EC2_CONTROL_PLANE_USERNAME", "admin") or "admin")
    parser.add_argument("--password", default=env_string("ANYSCAN_EC2_CONTROL_PLANE_PASSWORD"))
    parser.add_argument("--types", nargs="*", default=DEFAULT_TYPES)
    args = parser.parse_args()

    if not args.password:
        raise SystemExit("ANYSCAN_EC2_CONTROL_PLANE_PASSWORD is required")

    config = BenchmarkConfig(
        region=args.region,
        ami_id=args.ami_id,
        subnet_id=args.subnet_id,
        security_group_id=args.security_group_id,
        key_name=args.key_name,
        key_path=Path(env_string("ANYSCAN_EC2_SSH_PRIVATE_KEY_PATH", DEFAULT_KEY_PATH) or DEFAULT_KEY_PATH),
        install_url=args.install_url,
        control_plane_url=args.control_plane_url,
        control_plane_username=args.username,
        control_plane_password=args.password,
    )

    api = AnyScanApiClient(config.control_plane_url, config.control_plane_username, config.control_plane_password)
    api.login()
    ec2 = boto3.client(
        "ec2",
        region_name=config.region,
        aws_access_key_id=env_string("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=env_string("AWS_SECRET_ACCESS_KEY"),
        aws_session_token=env_string("AWS_SESSION_TOKEN"),
    )
    prices = get_price_map("US East (N. Virginia)", args.types)

    results = []
    for instance_type in args.types:
        try:
            result = benchmark_instance_type(config, api, ec2, instance_type, prices.get(instance_type))
        except Exception as exc:
            result = {"instance_type": instance_type, "error": str(exc), "price_per_hour_usd": prices.get(instance_type)}
        results.append(result)
        print(json.dumps(result, indent=2, default=str), flush=True)

    valid = [item for item in results if isinstance(item.get("tx_pps"), int)]
    best_absolute = max(valid, key=lambda item: item["tx_pps"]) if valid else None
    best_value = max(
        [item for item in valid if item.get("pps_per_dollar_hour") is not None],
        key=lambda item: item["pps_per_dollar_hour"],
        default=None,
    )

    print(
        json.dumps(
            {
                "benchmarks": results,
                "best_absolute": best_absolute,
                "best_value": best_value,
            },
            indent=2,
            default=str,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
