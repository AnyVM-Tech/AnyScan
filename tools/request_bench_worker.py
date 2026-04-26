#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark request throughput against a list of URLs.")
    parser.add_argument("--input", required=True, help="Path to newline-delimited URL list.")
    parser.add_argument("--mode", choices=["raw", "validated"], default="validated")
    parser.add_argument("--concurrency", type=int, default=256, help="Maximum concurrent requests.")
    parser.add_argument("--validate-concurrency", type=int, default=128, help="Maximum concurrent validation requests.")
    parser.add_argument("--connect-timeout", type=float, default=3.0, help="Connection timeout in seconds.")
    parser.add_argument("--request-timeout", type=float, default=3.0, help="Read/request timeout in seconds.")
    parser.add_argument("--path", default="/", help="HTTP path to request.")
    parser.add_argument("--method", default="HEAD", help="HTTP method to use.")
    parser.add_argument("--repeat", type=int, default=1, help="How many times to repeat the input URL list.")
    return parser.parse_args()


def load_urls(path: Path) -> list[str]:
    urls = []
    for line in path.read_text().splitlines():
        candidate = line.strip()
        if candidate and not candidate.startswith("#"):
            urls.append(candidate)
    return urls


async def fetch_url(
    raw_url: str,
    method: str,
    path: str,
    connect_timeout: float,
    request_timeout: float,
) -> dict[str, Any]:
    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"}:
        return {"ok": False, "kind": "unsupported_scheme", "url": raw_url}

    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return {"ok": False, "kind": "invalid_host", "url": raw_url}

    request_path = path or parsed.path or "/"
    if not request_path.startswith("/"):
        request_path = f"/{request_path}"

    ssl_context = None
    if parsed.scheme == "https":
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    reader = writer = None
    started = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_context, server_hostname=host if ssl_context else None),
            timeout=connect_timeout,
        )
        request = (
            f"{method} {request_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: anyscan-request-bench/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await asyncio.wait_for(writer.drain(), timeout=request_timeout)
        status_line = await asyncio.wait_for(reader.readline(), timeout=request_timeout)
        ok = status_line.startswith(b"HTTP/")
        return {
            "ok": ok,
            "kind": "http" if ok else "invalid_response",
            "url": raw_url,
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "status_line": status_line.decode(errors="replace").strip(),
        }
    except asyncio.TimeoutError:
        return {"ok": False, "kind": "timeout", "url": raw_url}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "kind": exc.__class__.__name__, "url": raw_url}
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass


async def run_request_batch(
    urls: list[str],
    concurrency: int,
    connect_timeout: float,
    request_timeout: float,
    method: str,
    path: str,
) -> tuple[list[dict[str, Any]], float]:
    semaphore = asyncio.Semaphore(max(1, concurrency))
    results: list[dict[str, Any]] = []

    async def run_one(url: str) -> None:
        async with semaphore:
            results.append(await fetch_url(url, method, path, connect_timeout, request_timeout))

    started = time.perf_counter()
    await asyncio.gather(*(run_one(url) for url in urls))
    elapsed = time.perf_counter() - started
    return results, elapsed


async def run_benchmark(
    urls: list[str],
    mode: str,
    concurrency: int,
    validate_concurrency: int,
    connect_timeout: float,
    request_timeout: float,
    method: str,
    path: str,
    repeat: int,
) -> dict[str, Any]:
    validation_elapsed = 0.0
    validated_urls = urls
    validation_results: list[dict[str, Any]] = []
    if mode == "validated":
        validation_results, validation_elapsed = await run_request_batch(
            urls=urls,
            concurrency=validate_concurrency,
            connect_timeout=connect_timeout,
            request_timeout=request_timeout,
            method=method,
            path=path,
        )
        validated_urls = [result["url"] for result in validation_results if result.get("ok")]

    benchmark_urls = validated_urls * max(1, repeat)
    benchmark_results, benchmark_elapsed = await run_request_batch(
        urls=benchmark_urls,
        concurrency=concurrency,
        connect_timeout=connect_timeout,
        request_timeout=request_timeout,
        method=method,
        path=path,
    )

    successes = [result for result in benchmark_results if result.get("ok")]
    failures = [result for result in benchmark_results if not result.get("ok")]
    failure_counts: dict[str, int] = {}
    for failure in failures:
        key = str(failure.get("kind") or "unknown")
        failure_counts[key] = failure_counts.get(key, 0) + 1

    return {
        "mode": mode,
        "candidate_targets_total": len(urls),
        "validated_targets_total": len(validated_urls),
        "targets_total": len(benchmark_urls),
        "validation_elapsed_seconds": validation_elapsed,
        "benchmark_elapsed_seconds": benchmark_elapsed,
        "requests_total": len(benchmark_results),
        "successful_requests": len(successes),
        "failed_requests": len(failures),
        "elapsed_seconds": validation_elapsed + benchmark_elapsed,
        "requests_per_second": (len(benchmark_results) / benchmark_elapsed)
        if benchmark_elapsed > 0
        else None,
        "successful_requests_per_second": (len(successes) / benchmark_elapsed)
        if benchmark_elapsed > 0
        else None,
        "failure_counts": failure_counts,
        "sample_successes": successes[:10],
        "sample_failures": failures[:10],
        "validation_sample_failures": [result for result in validation_results if not result.get("ok")][:10],
    }


def main() -> int:
    args = parse_args()
    urls = load_urls(Path(args.input))
    result = asyncio.run(
        run_benchmark(
            urls=urls,
            mode=args.mode,
            concurrency=args.concurrency,
            validate_concurrency=args.validate_concurrency,
            connect_timeout=args.connect_timeout,
            request_timeout=args.request_timeout,
            method=args.method,
            path=args.path,
            repeat=args.repeat,
        )
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
