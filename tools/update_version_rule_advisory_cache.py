#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from suggest_version_rule_cves import advisory_cache


ROOT = Path(__file__).resolve().parents[1]
CACHE_PATH = ROOT / "data" / "version_rule_advisories.json"

MANUAL_VERSION_ADVISORIES: dict[str, list[dict[str, object]]] = {
    "AppsmithPlugin": [
        {
            "advisory_id": "MANUAL-CVE-2024-55965",
            "cve_ids": ["CVE-2024-55965"],
            "kev_matched": False,
            "affected_ranges": [{"introduced": "0", "fixed": "1.51"}],
            "summary": "Appsmith viewers can access workspace development datasource information before 1.51.",
        }
    ],
    "BitbucketPlugin": [
        {
            "advisory_id": "MANUAL-CVE-2022-36804",
            "cve_ids": ["CVE-2022-36804"],
            "kev_matched": True,
            "affected_ranges": [{"introduced": "7.0.0", "last_affected": "8.3.0"}],
            "summary": "Bitbucket Server and Data Center command injection affected the 7.0.0 through 8.3.0 line.",
        }
    ],
    "CalcomPlugin": [
        {
            "advisory_id": "MANUAL-CVE-2025-66489",
            "cve_ids": ["CVE-2025-66489"],
            "kev_matched": False,
            "affected_ranges": [{"introduced": "0", "last_affected": "5.9.7"}],
            "summary": "Cal.com authentication bypass via bad TOTP and password checks prior to 5.9.8.",
        }
    ],
    "ConfluenceVersionIssue": [
        {
            "advisory_id": "MANUAL-CVE-2023-22515",
            "cve_ids": ["CVE-2023-22515"],
            "kev_matched": True,
            "affected_ranges": [
                {"introduced": "8.0.0", "fixed": "8.3.3"},
                {"introduced": "8.4.0", "fixed": "8.4.3"},
                {"introduced": "8.5.0", "fixed": "8.5.2"},
            ],
            "summary": "Confluence admin account creation flaw affecting 8.0.0 through 8.5.1 on the listed branches.",
        }
    ],
    "GitlabPlugin": [
        {
            "advisory_id": "MANUAL-CVE-2023-7028",
            "cve_ids": ["CVE-2023-7028"],
            "kev_matched": True,
            "affected_ranges": [
                {"introduced": "16.1.0", "fixed": "16.1.6"},
                {"introduced": "16.2.0", "fixed": "16.2.9"},
                {"introduced": "16.3.0", "fixed": "16.3.7"},
                {"introduced": "16.4.0", "fixed": "16.4.5"},
                {"introduced": "16.5.0", "fixed": "16.5.6"},
                {"introduced": "16.6.0", "fixed": "16.6.4"},
                {"introduced": "16.7.0", "fixed": "16.7.2"},
            ],
            "summary": "GitLab password reset account takeover issue on 16.1.0 through 16.7.1 across the listed trains.",
        }
    ],
    "JiraPlugin": [
        {
            "advisory_id": "MANUAL-CVE-2021-26086",
            "cve_ids": ["CVE-2021-26086"],
            "kev_matched": True,
            "affected_ranges": [
                {"introduced": "0", "fixed": "8.5.14"},
                {"introduced": "8.6.0", "fixed": "8.13.6"},
                {"introduced": "8.14.0", "fixed": "8.16.1"},
            ],
            "summary": "Jira Server and Data Center path traversal affecting the listed release trains prior to their fixed versions.",
        }
    ],
    "MetabaseHttpPlugin": [
        {
            "advisory_id": "MANUAL-CVE-2026-22805",
            "cve_ids": ["CVE-2026-22805"],
            "kev_matched": False,
            "affected_ranges": [
                {"introduced": "0", "fixed": "0.55.13"},
                {"introduced": "0.56.0", "fixed": "0.56.3"},
                {"introduced": "0.57.0", "fixed": "0.57.1"},
            ],
            "summary": "Metabase SSRF-style issue affecting the listed 55.x, 56.x, and 57.0 builds before their patch levels.",
        }
    ],
    "SharePoint202501": [
        {
            "advisory_id": "MANUAL-SharePoint-2025-01",
            "cve_ids": ["CVE-2025-21344", "CVE-2025-21348", "CVE-2025-21393"],
            "kev_matched": False,
            "affected_ranges": [{"introduced": "0", "fixed": "16.0.17928.20356"}],
            "summary": "SharePoint January 2025 security-update baseline before build 16.0.17928.20356.",
        }
    ],
    "SharePoint202502": [
        {
            "advisory_id": "MANUAL-CVE-2025-21400",
            "cve_ids": ["CVE-2025-21400"],
            "kev_matched": False,
            "affected_ranges": [{"introduced": "0", "fixed": "16.0.17928.20396"}],
            "summary": "SharePoint February 2025 remote code execution issue before build 16.0.17928.20396.",
        }
    ],
    "SharePointPlugin": [
        {
            "advisory_id": "MANUAL-SharePoint-ToolShell",
            "cve_ids": [
                "CVE-2025-49704",
                "CVE-2025-49706",
                "CVE-2025-53770",
                "CVE-2025-53771",
            ],
            "kev_matched": True,
            "affected_ranges": [{"introduced": "0", "fixed": "16.0.18526.20508"}],
            "summary": "SharePoint ToolShell chain and bypasses before the July 21 2025 16.0.18526.20508 security build.",
        }
    ],
    "TeamCityPlugin": [
        {
            "advisory_id": "MANUAL-CVE-2024-27198",
            "cve_ids": ["CVE-2024-27198"],
            "kev_matched": True,
            "affected_ranges": [{"introduced": "0", "fixed": "2023.11.4"}],
            "summary": "TeamCity on-premises authentication bypass affecting all versions through 2023.11.3.",
        }
    ],
    "WazuhPlugin": [
        {
            "advisory_id": "MANUAL-CVE-2025-24016",
            "cve_ids": ["CVE-2025-24016"],
            "kev_matched": False,
            "affected_ranges": [{"introduced": "4.4.0", "fixed": "4.9.1"}],
            "summary": "Wazuh unsafe deserialization remote code execution affecting 4.4.0 through 4.9.0.",
        }
    ],
    "ZoneMinderPlugin": [
        {
            "advisory_id": "MANUAL-ZoneMinder-2023-Batch",
            "cve_ids": [
                "CVE-2023-25825",
                "CVE-2023-26032",
                "CVE-2023-26034",
                "CVE-2023-26035",
                "CVE-2023-26036",
                "CVE-2023-26037",
                "CVE-2023-26039",
            ],
            "kev_matched": False,
            "affected_ranges": [{"introduced": "0", "fixed": "1.36.33"}],
            "summary": "ZoneMinder 2023 vulnerability batch affecting versions before 1.36.33.",
        }
    ],
}


def combined_advisory_cache() -> dict[str, list[dict[str, object]]]:
    merged = advisory_cache()
    for plugin_id, advisories in MANUAL_VERSION_ADVISORIES.items():
        existing = list(merged.get(plugin_id, []))
        existing.extend(advisories)
        merged[plugin_id] = existing
    return merged


def main() -> int:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(combined_advisory_cache(), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
