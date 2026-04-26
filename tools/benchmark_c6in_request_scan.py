#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import random
import socket
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import boto3


DEFAULT_REGION = "us-east-1"
DEFAULT_AMI = "ami-06e3e2b7faca0265d"
DEFAULT_TYPES = [
    "c6in.large",
    "c6in.xlarge",
    "c6in.2xlarge",
    "c6in.4xlarge",
]
DEFAULT_KEY_NAME = "anyscan-ec2-us-east-1"
DEFAULT_KEY_PATH = "/root/.ssh/anyscan-ec2-us-east-1"
DEFAULT_SG = "sg-033a89d74c7d2eb57"
DEFAULT_SUBNET = "subnet-0a8e834fdf69c0839"
DEFAULT_SAMPLE_SIZE = 2000
DEFAULT_TIMEOUT = 3.0
DEFAULT_FALLBACK_SAMPLE_FILE = "portscan51_request_sample.txt"


def env_string(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return default
    value = value.strip()
    return value or default


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class BenchmarkConfig:
    region: str
    ami_id: str
    subnet_id: str
    security_group_id: str
    key_name: str
    key_path: Path
    sample_size: int
    connect_timeout_seconds: float
    timeout_seconds: float


def build_user_data() -> str:
    lines = [
        "#!/usr/bin/env bash",
        "set -euxo pipefail",
        "export DEBIAN_FRONTEND=noninteractive",
        "apt-get update",
        "apt-get install -y curl ca-certificates python3 openssh-client",
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


def wait_for_ssh(public_ip: str, key_path: Path, timeout_seconds: int = 300) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        proc = subprocess.run(
            [
                "ssh",
                "-i",
                str(key_path),
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "ConnectTimeout=10",
                f"admin@{public_ip}",
                "true",
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            return
        time.sleep(5)
    raise TimeoutError(f"instance {public_ip} did not become reachable over SSH in time")


def extract_urls_from_live_port_scan(port_scan_id: int, sample_size: int, seed: int, ports: set[int]) -> list[str]:
    host = os.environ.get("ANYSCAN_RUNTIME_STATE_HOST")
    port_text = os.environ.get("ANYSCAN_RUNTIME_STATE_PORT")
    username = os.environ.get("ANYSCAN_RUNTIME_STATE_USERNAME")
    password = os.environ.get("ANYSCAN_RUNTIME_STATE_PASSWORD")
    key = os.environ.get("ANYSCAN_RUNTIME_STATE_KEY")

    missing = [
        name
        for name, value in [
            ("ANYSCAN_RUNTIME_STATE_HOST", host),
            ("ANYSCAN_RUNTIME_STATE_PORT", port_text),
            ("ANYSCAN_RUNTIME_STATE_USERNAME", username),
            ("ANYSCAN_RUNTIME_STATE_PASSWORD", password),
            ("ANYSCAN_RUNTIME_STATE_KEY", key),
        ]
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Missing required environment variable(s) for live port scan runtime state access: "
            + ", ".join(missing)
        )

    try:
        port = int(port_text)
    except ValueError as exc:
        raise RuntimeError(
            "ANYSCAN_RUNTIME_STATE_PORT must be a valid integer"
        ) from exc

    def send_cmd(sock: socket.socket, *parts: str) -> None:
        out = [f"*{len(parts)}\r\n".encode()]
        for part in parts:
            encoded = part.encode()
            out.append(f"${len(encoded)}\r\n".encode())
            out.append(encoded + b"\r\n")
        sock.sendall(b"".join(out))

    def read_line(sock: socket.socket) -> bytes:
        buf = b""
        while not buf.endswith(b"\r\n"):
            buf += sock.recv(1)
        return buf[:-2]

    def read_resp(sock: socket.socket) -> Any:
        kind = sock.recv(1)
        if not kind:
            raise EOFError("empty response")
        data = read_line(sock)
        if kind == b"+":
            return data.decode()
        if kind == b"-":
            raise RuntimeError(data.decode())
        if kind == b":":
            return int(data)
        if kind == b"$":
            length = int(data)
            if length == -1:
                return None
            payload = b""
            while len(payload) < length + 2:
                payload += sock.recv(length + 2 - len(payload))
            return payload[:-2]
        if kind == b"*":
            return [read_resp(sock) for _ in range(int(data))]
        raise RuntimeError(f"unexpected RESP type {kind!r}")

    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(5)
    send_cmd(sock, "AUTH", username, password)
    read_resp(sock)
    send_cmd(sock, "GET", key)
    raw = read_resp(sock)
    state = json.loads(raw)
    record = next(
        (item for item in state.get("port_scans", []) if item.get("port_scan", {}).get("id") == port_scan_id),
        None,
    )
    if record is None:
        raise RuntimeError(f"port scan {port_scan_id} not found in runtime state")

    urls = []
    seen = set()
    for line in (record.get("resume_state", {}) or {}).get("output_snapshot", "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        host_text, port_text = line.rsplit(":", 1)
        try:
            port_value = int(port_text)
        except ValueError:
            continue
        if port_value not in ports:
            continue
        scheme = "https" if port_value == 443 else "http"
        url = f"{scheme}://{host_text}:{port_value}/"
        if url not in seen:
            seen.add(url)
            urls.append(url)

    if len(urls) > sample_size:
        rng = random.Random(seed)
        urls = rng.sample(urls, sample_size)
    return sorted(urls)


def extract_urls_via_worker_output(
    port_scan_id: int,
    key_path: Path,
    sample_size: int,
    seed: int,
    ports: set[int],
) -> list[str]:
    session = boto3.Session(
        aws_access_key_id=env_string("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=env_string("AWS_SECRET_ACCESS_KEY"),
        aws_session_token=env_string("AWS_SESSION_TOKEN"),
        region_name=env_string("AWS_DEFAULT_REGION", DEFAULT_REGION),
    )
    ec2 = session.client("ec2")
    response = ec2.describe_instances(
        Filters=[
            {"Name": "tag:Name", "Values": ["anyscan-ec2-worker"]},
            {"Name": "instance-state-name", "Values": ["running"]},
        ]
    )
    instances = []
    for reservation in response.get("Reservations", []):
        instances.extend(reservation.get("Instances", []))
    if not instances:
        return []
    instances.sort(key=lambda instance: str(instance.get("LaunchTime")), reverse=True)
    public_ip = instances[0].get("PublicIpAddress")
    if not public_ip:
        return []

    command = (
        "python3 - <<'PY'\n"
        "import glob, json, os\n"
        f"paths=sorted(glob.glob('/tmp/agent-vulnscanner-zmap-{port_scan_id}-*.out'))\n"
        "current=paths[-1] if paths else None\n"
        "lines=[]\n"
        "if current and os.path.exists(current):\n"
        "    with open(current, 'r', errors='ignore') as handle:\n"
        "        for line in handle:\n"
        "            line=line.strip()\n"
        "            if line:\n"
        "                lines.append(line)\n"
        "print(json.dumps({'path': current, 'lines': lines}))\n"
        "PY"
    )
    proc = subprocess.run(
        [
            "ssh",
            "-i",
            str(key_path),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=15",
            f"admin@{public_ip}",
            command,
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return []
    payload = json.loads(proc.stdout or "{}")
    urls = []
    seen = set()
    for line in payload.get("lines", []):
        line = str(line).strip()
        if not line or ":" not in line:
            continue
        host_text, port_text = line.rsplit(":", 1)
        try:
            port_value = int(port_text)
        except ValueError:
            continue
        if port_value not in ports:
            continue
        scheme = "https" if port_value == 443 else "http"
        url = f"{scheme}://{host_text}:{port_value}/"
        if url not in seen:
            seen.add(url)
            urls.append(url)
    if len(urls) > sample_size:
        rng = random.Random(seed)
        urls = rng.sample(urls, sample_size)
    return sorted(urls)


def load_urls_from_file(path: Path) -> list[str]:
    urls = []
    for line in path.read_text().splitlines():
        candidate = line.strip()
        if candidate and not candidate.startswith("#"):
            urls.append(candidate)
    return urls


def copy_inputs(public_ip: str, key_path: Path, local_urls_path: Path, local_script_path: Path) -> None:
    base_cmd = [
        "scp",
        "-i",
        str(key_path),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "ConnectTimeout=15",
    ]
    subprocess.run(
        base_cmd + [str(local_urls_path), f"admin@{public_ip}:/tmp/anyscan-request-targets.txt"],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        base_cmd + [str(local_script_path), f"admin@{public_ip}:/tmp/request_bench_worker.py"],
        check=True,
        capture_output=True,
        text=True,
    )


def run_remote_benchmark(
    public_ip: str,
    key_path: Path,
    mode: str,
    connect_timeout_seconds: float,
    timeout_seconds: float,
    repeat_count: int,
) -> dict[str, Any]:
    command = (
        "python3 /tmp/request_bench_worker.py "
        "--input /tmp/anyscan-request-targets.txt "
        f"--mode {mode} "
        "--concurrency \"$(($(nproc)*64))\" "
        "--validate-concurrency \"$(($(nproc)*32))\" "
        f"--connect-timeout {connect_timeout_seconds} "
        f"--request-timeout {timeout_seconds} "
        "--method HEAD "
        "--path / "
        f"--repeat {max(1, repeat_count)}"
    )
    proc = subprocess.run(
        [
            "ssh",
            "-i",
            str(key_path),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=15",
            f"admin@{public_ip}",
            command,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(proc.stdout)


def terminate_instance(ec2: Any, instance_id: str) -> None:
    ec2.terminate_instances(InstanceIds=[instance_id])


def benchmark_instance_type(
    config: BenchmarkConfig,
    ec2: Any,
    instance_type: str,
    price_per_hour: float | None,
    urls_path: Path,
    worker_script_path: Path,
    repeat_count: int,
    mode: str,
) -> dict[str, Any]:
    suffix = uuid.uuid4().hex[:8]
    instance_name = f"anyscan-req-bench-{instance_type.replace('.', '-')}-{suffix}"
    launch = ec2.run_instances(
        ImageId=config.ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        KeyName=config.key_name,
        SecurityGroupIds=[config.security_group_id],
        SubnetId=config.subnet_id,
        UserData=build_user_data(),
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": instance_name},
                    {"Key": "ManagedBy", "Value": "AnyScanRequestBenchmark"},
                    {"Key": "Role", "Value": "AnyScanRequestBenchmark"},
                ],
            }
        ],
    )
    instance_id = launch["Instances"][0]["InstanceId"]
    instance = wait_for_instance_running(ec2, instance_id)
    benchmark_result: dict[str, Any] = {}
    try:
        wait_for_ssh(instance["PublicIpAddress"], config.key_path)
        copy_inputs(instance["PublicIpAddress"], config.key_path, urls_path, worker_script_path)
        benchmark_result = run_remote_benchmark(
            public_ip=instance["PublicIpAddress"],
            key_path=config.key_path,
            mode=mode,
            connect_timeout_seconds=config.connect_timeout_seconds,
            timeout_seconds=config.timeout_seconds,
            repeat_count=repeat_count,
        )
    finally:
        terminate_instance(ec2, instance_id)

    req_per_second = benchmark_result.get("requests_per_second")
    return {
        "instance_type": instance_type,
        "instance_id": instance_id,
        "public_ip": instance.get("PublicIpAddress"),
        "price_per_hour_usd": price_per_hour,
        "requests_per_second": req_per_second,
        "successful_requests_per_second": benchmark_result.get("successful_requests_per_second"),
        "requests_total": benchmark_result.get("requests_total"),
        "successful_requests": benchmark_result.get("successful_requests"),
        "failed_requests": benchmark_result.get("failed_requests"),
        "targets_total": benchmark_result.get("targets_total"),
        "failure_counts": benchmark_result.get("failure_counts"),
        "requests_per_dollar_hour": (req_per_second / price_per_hour) if isinstance(req_per_second, (int, float)) and price_per_hour else None,
        "details": benchmark_result,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark request throughput across c6in sizes using live port-scan endpoints.")
    parser.add_argument("--port-scan-id", type=int, default=51)
    parser.add_argument("--region", default=env_string("ANYSCAN_EC2_REGION", DEFAULT_REGION) or DEFAULT_REGION)
    parser.add_argument("--ami-id", default=env_string("ANYSCAN_EC2_AMI_ID", DEFAULT_AMI) or DEFAULT_AMI)
    parser.add_argument("--subnet-id", default=env_string("ANYSCAN_EC2_SUBNET_ID", DEFAULT_SUBNET) or DEFAULT_SUBNET)
    parser.add_argument("--security-group-id", default=env_string("ANYSCAN_EC2_SECURITY_GROUP_ID", DEFAULT_SG) or DEFAULT_SG)
    parser.add_argument("--key-name", default=env_string("ANYSCAN_EC2_KEY_NAME", DEFAULT_KEY_NAME) or DEFAULT_KEY_NAME)
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    parser.add_argument("--seed", type=int, default=51)
    parser.add_argument("--mode", choices=["raw", "validated"], default="validated")
    parser.add_argument("--connect-timeout", type=float, default=3.0)
    parser.add_argument("--request-timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--repeat", type=int, default=8)
    parser.add_argument("--ports", default="80,443", help="Comma-separated discovered ports to include.")
    parser.add_argument("--input-file", help="Optional prebuilt URL list file.")
    parser.add_argument("--types", nargs="*", default=DEFAULT_TYPES)
    args = parser.parse_args()

    include_ports = {int(item.strip()) for item in args.ports.split(",") if item.strip()}
    if args.input_file:
        urls = load_urls_from_file(Path(args.input_file))
    else:
        urls = extract_urls_from_live_port_scan(
            port_scan_id=args.port_scan_id,
            sample_size=args.sample_size,
            seed=args.seed,
            ports=include_ports,
        )
        if not urls:
            urls = extract_urls_via_worker_output(
                port_scan_id=args.port_scan_id,
                key_path=Path(env_string("ANYSCAN_EC2_SSH_PRIVATE_KEY_PATH", DEFAULT_KEY_PATH) or DEFAULT_KEY_PATH),
                sample_size=args.sample_size,
                seed=args.seed,
                ports=include_ports,
            )
        if not urls:
            fallback_path = Path(__file__).with_name(DEFAULT_FALLBACK_SAMPLE_FILE)
            if fallback_path.exists():
                urls = load_urls_from_file(fallback_path)
    if not urls:
        raise SystemExit("No benchmark URLs extracted from the live port-scan snapshot")

    config = BenchmarkConfig(
        region=args.region,
        ami_id=args.ami_id,
        subnet_id=args.subnet_id,
        security_group_id=args.security_group_id,
        key_name=args.key_name,
        key_path=Path(env_string("ANYSCAN_EC2_SSH_PRIVATE_KEY_PATH", DEFAULT_KEY_PATH) or DEFAULT_KEY_PATH),
        sample_size=args.sample_size,
        connect_timeout_seconds=args.connect_timeout,
        timeout_seconds=args.request_timeout,
    )

    ec2 = boto3.client(
        "ec2",
        region_name=config.region,
        aws_access_key_id=env_string("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=env_string("AWS_SECRET_ACCESS_KEY"),
        aws_session_token=env_string("AWS_SESSION_TOKEN"),
    )
    prices = get_price_map("US East (N. Virginia)", args.types)

    with tempfile.TemporaryDirectory(prefix="anyscan-request-bench-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        urls_path = tmp_path / "targets.txt"
        urls_path.write_text("\n".join(urls) + "\n")
        worker_script_path = Path(__file__).with_name("request_bench_worker.py")

        results = []
        for instance_type in args.types:
            try:
                result = benchmark_instance_type(
                    config=config,
                    ec2=ec2,
                    instance_type=instance_type,
                    price_per_hour=prices.get(instance_type),
                    urls_path=urls_path,
                    worker_script_path=worker_script_path,
                    repeat_count=args.repeat,
                    mode=args.mode,
                )
            except Exception as exc:  # noqa: BLE001
                result = {
                    "instance_type": instance_type,
                    "error": str(exc),
                    "price_per_hour_usd": prices.get(instance_type),
                }
            results.append(result)
            print(json.dumps(result, indent=2, default=str), flush=True)

    valid = [item for item in results if isinstance(item.get("requests_per_second"), (int, float))]
    best_absolute = max(valid, key=lambda item: item["requests_per_second"]) if valid else None
    best_value = max(
        [item for item in valid if item.get("requests_per_dollar_hour") is not None],
        key=lambda item: item["requests_per_dollar_hour"],
        default=None,
    )
    print(
        json.dumps(
            {
                "source_port_scan_id": args.port_scan_id,
                "sample_size": len(urls),
                "mode": args.mode,
                "ports": sorted(include_ports),
                "benchmarks": results,
                "best_absolute": best_absolute,
                "best_value": best_value,
                "benchmarked_at": utc_now(),
            },
            indent=2,
            default=str,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
