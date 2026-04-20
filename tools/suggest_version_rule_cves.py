#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import asdict
from dataclasses import dataclass
from functools import lru_cache
from packaging.version import InvalidVersion, Version


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
VULNRICHMENT_RAW_BASE = (
    "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"
)


PLUGIN_PACKAGE_HINTS: dict[str, dict[str, str]] = {
    "FlowiseVersionPlugin": {"ecosystem": "npm", "name": "flowise"},
    "LiteLLMPlugin": {"ecosystem": "PyPI", "name": "litellm"},
    "N8nPlugin": {"ecosystem": "npm", "name": "n8n"},
}


@dataclass
class AdvisoryMatch:
    advisory_id: str
    cve_ids: list[str]
    summary: str | None
    kev_matched: bool
    affected_ranges: list[dict[str, str]]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve CVE IDs and KEV status for a detected product version "
            "using OSV and CISA Vulnrichment feeds."
        )
    )
    parser.add_argument("--plugin", required=True, help="Plugin ID to query")
    parser.add_argument("--version", required=True, help="Detected product version")
    parser.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON output"
    )
    return parser.parse_args()


def request_json(url: str, *, method: str = "GET", body: dict | None = None) -> dict:
    data = None
    headers = {"User-Agent": "Mozilla/5.0"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def try_version(value: str) -> Version | None:
    try:
        return Version(value)
    except InvalidVersion:
        return None


def version_in_osv_ranges(version: str, ranges: list[dict[str, object]]) -> bool:
    target = try_version(version)
    if target is None:
        return False
    for range_block in ranges:
        if range_block.get("type") not in {"SEMVER", "ECOSYSTEM"}:
            continue
        lower: Version | None = None
        active = False
        for event in range_block.get("events", []):
            if "introduced" in event:
                introduced = str(event["introduced"])
                lower = Version("0") if introduced == "0" else try_version(introduced)
                active = lower is not None
            if "fixed" in event:
                fixed = try_version(str(event["fixed"]))
                if active and fixed is not None and lower is not None:
                    if target >= lower and target < fixed:
                        return True
                active = False
            if "last_affected" in event:
                last = try_version(str(event["last_affected"]))
                if active and last is not None and lower is not None:
                    if target >= lower and target <= last:
                        return True
                active = False
    return False


@lru_cache(maxsize=256)
def fetch_vulnrichment(cve_id: str) -> dict | None:
    cve_id = cve_id.strip().upper()
    try:
        year_part = cve_id.split("-")[1]
        number_part = cve_id.split("-")[2]
    except IndexError:
        return None
    bucket = f"{number_part[:-3] or number_part[0]}xxx"
    url = f"{VULNRICHMENT_RAW_BASE}/{year_part}/{bucket}/{cve_id}.json"
    try:
        return request_json(url)
    except urllib.error.HTTPError:
        return None


def vulnrichment_has_kev(record: dict | None) -> bool:
    if not record:
        return False
    for adp in record.get("containers", {}).get("adp", []):
        for metric in adp.get("metrics", []):
            other = metric.get("other")
            if not isinstance(other, dict):
                continue
            if str(other.get("type", "")).lower() == "kev":
                return True
        for timeline in adp.get("timeline", []):
            value = str(timeline.get("value", "")).lower()
            if "kev" in value and "added" in value:
                return True
    return False


def osv_matches_for_plugin(plugin_id: str, version: str) -> list[AdvisoryMatch]:
    advisories = osv_advisories_for_plugin(plugin_id)
    return [
        advisory
        for advisory in advisories
        if version_matches_ranges(version, advisory.affected_ranges)
    ]


def version_matches_ranges(version: str, ranges: list[dict[str, str]]) -> bool:
    target = try_version(version)
    if target is None:
        return False
    for range_entry in ranges:
        introduced = range_entry.get("introduced", "")
        fixed = range_entry.get("fixed", "")
        last_affected = range_entry.get("last_affected", "")
        lower = Version("0") if introduced in {"", "0"} else try_version(introduced)
        if lower is None:
            continue
        if target < lower:
            continue
        if fixed:
            fixed_version = try_version(fixed)
            if fixed_version is not None and target < fixed_version:
                return True
            continue
        if last_affected:
            last_version = try_version(last_affected)
            if last_version is not None and target <= last_version:
                return True
            continue
        return True
    return False


def osv_advisories_for_plugin(plugin_id: str) -> list[AdvisoryMatch]:
    hint = PLUGIN_PACKAGE_HINTS.get(plugin_id)
    if not hint:
        raise SystemExit(
            f"no package hint configured for plugin {plugin_id!r}; "
            "add it to PLUGIN_PACKAGE_HINTS first"
        )
    data = request_json(
        OSV_QUERY_URL,
        method="POST",
        body={"package": {"ecosystem": hint["ecosystem"], "name": hint["name"]}},
    )
    advisories: list[AdvisoryMatch] = []
    for vuln in data.get("vulns", []):
        affected_ranges: list[dict[str, str]] = []
        for affected in vuln.get("affected", []):
            package = affected.get("package", {})
            if (
                str(package.get("ecosystem")) != hint["ecosystem"]
                or str(package.get("name")) != hint["name"]
            ):
                continue
            ranges = affected.get("ranges", [])
            for range_block in ranges:
                if range_block.get("type") not in {"SEMVER", "ECOSYSTEM"}:
                    continue
                current: dict[str, str] = {}
                for event in range_block.get("events", []):
                    for key in ("introduced", "fixed", "last_affected"):
                        if key in event:
                            current[key] = str(event[key])
                if current:
                    affected_ranges.append(current)
        if not affected_ranges:
            continue
        cve_ids = [
            alias.strip().upper()
            for alias in vuln.get("aliases", [])
            if alias.strip().upper().startswith("CVE-")
        ]
        if not cve_ids:
            continue
        kev = any(vulnrichment_has_kev(fetch_vulnrichment(cve)) for cve in cve_ids)
        advisories.append(
            AdvisoryMatch(
                advisory_id=str(vuln.get("id")),
                cve_ids=sorted(dict.fromkeys(cve_ids)),
                summary=vuln.get("summary"),
                kev_matched=kev,
                affected_ranges=affected_ranges,
            )
        )
    advisories.sort(key=lambda advisory: advisory.advisory_id)
    return advisories


def advisory_cache() -> dict[str, list[dict[str, object]]]:
    return {
        plugin_id: [asdict(advisory) for advisory in osv_advisories_for_plugin(plugin_id)]
        for plugin_id in sorted(PLUGIN_PACKAGE_HINTS)
    }


def main() -> int:
    args = parse_args()
    matches = osv_matches_for_plugin(args.plugin, args.version)
    result = {
        "plugin_id": args.plugin,
        "version": args.version,
        "matches": [
            {
                "advisory_id": match.advisory_id,
                "cve_ids": match.cve_ids,
                "kev_matched": match.kev_matched,
                "affected_ranges": match.affected_ranges,
                "summary": match.summary,
            }
            for match in matches
        ],
        "cve_ids": sorted(
            {
                cve
                for match in matches
                for cve in match.cve_ids
            }
        ),
        "kev_matched": any(match.kev_matched for match in matches),
    }
    if args.json:
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    print(f"Plugin: {result['plugin_id']}")
    print(f"Version: {result['version']}")
    print(f"KEV matched: {result['kev_matched']}")
    print("CVEs:")
    for cve_id in result["cve_ids"]:
        print(f"  - {cve_id}")
    if not result["matches"]:
        print("No matching advisories found.")
        return 0
    print("Matched advisories:")
    for match in result["matches"]:
        print(f"  - {match['advisory_id']}: {match['summary'] or ''}")
        if match["cve_ids"]:
            print(f"    CVEs: {', '.join(match['cve_ids'])}")
        print(f"    KEV: {match['kev_matched']}")
        if match["affected_ranges"]:
            print(f"    Ranges: {match['affected_ranges']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
