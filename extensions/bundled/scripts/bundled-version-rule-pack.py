#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "version-plugin-rules.json"
VERSION_RE = re.compile(r"\d+\.\d+\.\d+(?:\.\d+)?")
SUFFIXES = (
    "Plugin",
    "VersionIssue",
    "Version",
    "Http",
    "Open",
    "202501",
    "202502",
)


def load_rules() -> list[dict[str, object]]:
    if not RULES_PATH.exists():
        return []
    return json.loads(RULES_PATH.read_text())


def default_aliases(plugin_id: str) -> list[str]:
    token = plugin_id.strip()
    for suffix in SUFFIXES:
        if token.endswith(suffix):
            token = token[: -len(suffix)]
    if not token:
        return []
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", token)
    normalized = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", normalized)
    words = [word.lower() for word in re.split(r"[\s_/:-]+", normalized) if word]
    if not words:
        return []
    variants = {
        " ".join(words),
        "-".join(words),
        "".join(words),
    }
    return [value for value in variants if value]


def rule_aliases(rule: dict[str, object]) -> list[str]:
    if "aliases" in rule:
        return [
            str(value).strip().lower()
            for value in rule.get("aliases", [])
            if str(value).strip()
        ]
    plugin_id = str(rule.get("plugin_id", "")).strip()
    if not plugin_id:
        return []
    return default_aliases(plugin_id)


def contains_any(container: str, tokens: list[str]) -> bool:
    return any(token in container for token in tokens)


def contains_all(container: str, tokens: list[str]) -> bool:
    return all(token in container for token in tokens)


def render_evidence(
    rule: dict[str, object],
    plugin_id: str,
    version: str,
    path: str,
) -> str:
    template = rule.get("evidence_template")
    if template:
        values = {
            "plugin_id": plugin_id,
            "product_name": str(rule.get("product_name", plugin_id)),
            "product_version": version,
            "path": path,
        }
        rendered = str(template)
        for key, value in values.items():
            rendered = rendered.replace(f"{{{key}}}", value)
        return rendered
    return str(
        rule.get(
            "evidence",
            f"{plugin_id} matched bundled version rule with version {version}",
        )
    )


def collect_matched_signals(
    rule: dict[str, object],
    path: str,
    lowered_body: str,
    headers: dict[str, str],
    header_blob: str,
    aliases: list[str],
    version: str,
) -> list[str]:
    signals: list[str] = []
    if rule.get("path_contains") and contains_all(
        path, [str(value).lower() for value in rule.get("path_contains", [])]
    ):
        signals.append("path_contains")
    if rule.get("any_of_path_contains") and contains_any(
        path,
        [str(value).lower() for value in rule.get("any_of_path_contains", []) if str(value).strip()],
    ):
        signals.append("path_hint")
    if rule.get("body_contains") and contains_all(
        lowered_body, [str(value).lower() for value in rule.get("body_contains", [])]
    ):
        signals.append("body_contains")
    if rule.get("any_of_body_contains") and contains_any(
        lowered_body,
        [str(value).lower() for value in rule.get("any_of_body_contains", []) if str(value).strip()],
    ):
        signals.append("body_hint")
    header_contains = {
        str(name).lower(): str(value).lower()
        for name, value in dict(rule.get("header_contains", {})).items()
    }
    if header_contains and all(
        token in headers.get(name, "").lower() for name, token in header_contains.items()
    ):
        signals.append("header_contains")
    if rule.get("path_regex") and re.search(str(rule.get("path_regex")), path, flags=re.IGNORECASE):
        signals.append("path_regex")
    if rule.get("header_regex") and re.search(
        str(rule.get("header_regex")), header_blob, flags=re.IGNORECASE
    ):
        signals.append("header_regex")
    if aliases and (
        contains_any(path, aliases)
        or contains_any(lowered_body, aliases)
        or contains_any(header_blob, aliases)
    ):
        signals.append("alias")
    if version:
        signals.append("version")
    return signals


def score_value(rule: dict[str, object], field: str, default: int = 1) -> int:
    value = rule.get(field, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def extract_nearby_version(text: str, aliases: list[str]) -> str | None:
    for alias in aliases:
        escaped = re.escape(alias)
        patterns = [
            rf"(?i){escaped}[^\n\r]{{0,80}}?(?P<version>{VERSION_RE.pattern})",
            rf"(?i)(?P<version>{VERSION_RE.pattern})[^\n\r]{{0,60}}?{escaped}",
            rf"(?i){escaped}[^\n\r]{{0,60}}?(?:version|ver|release|build)[^0-9]{{0,12}}(?P<version>{VERSION_RE.pattern})",
            rf"(?i)(?:version|ver|release|build)[^0-9\n\r]{{0,12}}(?P<version>{VERSION_RE.pattern})[^\n\r]{{0,60}}?{escaped}",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group("version")
    return None


def extract_version(
    path: str,
    body: str,
    headers: dict[str, str],
    rule: dict[str, object],
    aliases: list[str],
) -> str | None:
    version_header = str(rule.get("version_header", "") or "").strip().lower()
    if version_header:
        header_value = headers.get(version_header)
        if header_value:
            match = VERSION_RE.search(header_value)
            if match:
                return match.group(0)
    version_headers = [
        str(value).strip().lower() for value in rule.get("version_headers", []) if str(value).strip()
    ]
    for header_name in version_headers:
        header_value = headers.get(header_name)
        if header_value:
            match = VERSION_RE.search(header_value)
            if match:
                return match.group(0)
    pattern = rule.get("version_regex")
    if pattern:
        match = re.search(str(pattern), body, flags=re.IGNORECASE)
        if match:
            return match.group("version") if "version" in match.groupdict() else match.group(0)
    for pattern in rule.get("version_regexes", []):
        match = re.search(str(pattern), body, flags=re.IGNORECASE)
        if match:
            return match.group("version") if "version" in match.groupdict() else match.group(0)
    nearby = extract_nearby_version(body, aliases)
    if nearby:
        return nearby
    nearby = extract_nearby_version("\n".join(headers.values()), aliases)
    if nearby:
        return nearby
    if rule.get("fallback_any_version"):
        match = VERSION_RE.search(body)
        if match:
            return match.group(0)
    match = VERSION_RE.search(path)
    return match.group(0) if match else None


def version_lt(left: str, right: str) -> bool:
    def parts(value: str) -> list[int]:
        found = VERSION_RE.search(value)
        token = found.group(0) if found else value
        return [int(item) for item in token.split(".") if item.isdigit()]

    left_parts = parts(left)
    right_parts = parts(right)
    length = max(len(left_parts), len(right_parts))
    left_parts += [0] * (length - len(left_parts))
    right_parts += [0] * (length - len(right_parts))
    return left_parts < right_parts


def version_le(left: str, right: str) -> bool:
    return left == right or version_lt(left, right)


def version_matches_affected_ranges(version: str, ranges: list[dict[str, object]]) -> bool:
    for range_entry in ranges:
        introduced = str(range_entry.get("introduced", "") or "").strip()
        fixed = str(range_entry.get("fixed", "") or "").strip()
        last_affected = str(range_entry.get("last_affected", "") or "").strip()
        if introduced and version_lt(version, introduced):
            continue
        if fixed and not version_lt(version, fixed):
            continue
        if last_affected and not version_le(version, last_affected):
            continue
        return True
    return False


def advisory_matches_for_version(
    version: str, advisories: list[dict[str, object]]
) -> list[dict[str, object]]:
    return [
        advisory
        for advisory in advisories
        if version_matches_affected_ranges(
            version,
            [value for value in advisory.get("affected_ranges", []) if isinstance(value, dict)],
        )
    ]


def main() -> int:
    try:
        document = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 1

    path = str(document.get("path", "")).lower()
    body = str(document.get("body", ""))
    lowered_body = body.lower()
    headers = {
        str(name).strip().lower(): str(value).strip()
        for name, value in document.get("headers", [])
        if str(name).strip()
    }

    for rule in load_rules():
        path_contains = [str(value).lower() for value in rule.get("path_contains", [])]
        any_of_path_contains = [
            str(value).lower() for value in rule.get("any_of_path_contains", []) if str(value).strip()
        ]
        path_not_contains = [
            str(value).lower() for value in rule.get("path_not_contains", []) if str(value).strip()
        ]
        any_of_path_not_contains = [
            str(value).lower()
            for value in rule.get("any_of_path_not_contains", [])
            if str(value).strip()
        ]
        body_contains = [str(value).lower() for value in rule.get("body_contains", [])]
        any_of_body_contains = [
            str(value).lower() for value in rule.get("any_of_body_contains", []) if str(value).strip()
        ]
        body_not_contains = [
            str(value).lower() for value in rule.get("body_not_contains", []) if str(value).strip()
        ]
        any_of_body_not_contains = [
            str(value).lower()
            for value in rule.get("any_of_body_not_contains", [])
            if str(value).strip()
        ]
        header_contains = {
            str(name).lower(): str(value).lower()
            for name, value in dict(rule.get("header_contains", {})).items()
        }
        header_not_contains = {
            str(name).lower(): str(value).lower()
            for name, value in dict(rule.get("header_not_contains", {})).items()
        }
        path_regex = rule.get("path_regex")
        header_regex = rule.get("header_regex")
        path_not_regex = rule.get("path_not_regex")
        body_not_regex = rule.get("body_not_regex")
        header_not_regex = rule.get("header_not_regex")
        aliases = rule_aliases(rule)
        header_blob = "\n".join(f"{name}: {value}" for name, value in headers.items()).lower()
        min_score = rule.get("min_score")

        positive_matchers = 0
        score = 0
        if path_not_contains and contains_any(path, path_not_contains):
            continue
        if any_of_path_not_contains and contains_any(path, any_of_path_not_contains):
            continue
        if body_not_contains and contains_any(lowered_body, body_not_contains):
            continue
        if any_of_body_not_contains and contains_any(lowered_body, any_of_body_not_contains):
            continue
        if header_not_contains and any(
            token in headers.get(name, "").lower() for name, token in header_not_contains.items()
        ):
            continue
        if path_not_regex and re.search(str(path_not_regex), path, flags=re.IGNORECASE):
            continue
        if body_not_regex and re.search(str(body_not_regex), lowered_body, flags=re.IGNORECASE):
            continue
        if header_not_regex and re.search(str(header_not_regex), header_blob, flags=re.IGNORECASE):
            continue
        if path_contains:
            positive_matchers += 1
            matched = contains_all(path, path_contains)
            if min_score is None and not matched:
                continue
            if matched:
                score += score_value(rule, "path_contains_score")
        if any_of_path_contains:
            positive_matchers += 1
            matched = contains_any(path, any_of_path_contains)
            if min_score is None and not matched:
                continue
            if matched:
                score += score_value(rule, "any_of_path_contains_score")
        if body_contains:
            positive_matchers += 1
            matched = contains_all(lowered_body, body_contains)
            if min_score is None and not matched:
                continue
            if matched:
                score += score_value(rule, "body_contains_score")
        if any_of_body_contains:
            positive_matchers += 1
            matched = contains_any(lowered_body, any_of_body_contains)
            if min_score is None and not matched:
                continue
            if matched:
                score += score_value(rule, "any_of_body_contains_score")
        if header_contains:
            positive_matchers += 1
            matched = all(
                token in headers.get(name, "").lower() for name, token in header_contains.items()
            )
            if min_score is None and not matched:
                continue
            if matched:
                score += score_value(rule, "header_contains_score")
        if path_regex:
            positive_matchers += 1
            matched = bool(re.search(str(path_regex), path, flags=re.IGNORECASE))
            if min_score is None and not matched:
                continue
            if matched:
                score += score_value(rule, "path_regex_score")
        if header_regex:
            positive_matchers += 1
            matched = bool(re.search(str(header_regex), header_blob, flags=re.IGNORECASE))
            if min_score is None and not matched:
                continue
            if matched:
                score += score_value(rule, "header_regex_score")
        if aliases:
            positive_matchers += 1
            matched = (
                contains_any(path, aliases)
                or contains_any(lowered_body, aliases)
                or contains_any(header_blob, aliases)
            )
            if min_score is None and not matched:
                continue
            if matched:
                score += score_value(rule, "aliases_score")
        if positive_matchers == 0:
            continue

        version = extract_version(path, body, headers, rule, aliases)
        threshold = rule.get("vulnerable_below")
        threshold_or_equal = rule.get("vulnerable_at_or_below")
        exact_versions = [str(value) for value in rule.get("exact_versions", [])]
        affected_ranges = [
            value for value in rule.get("affected_ranges", []) if isinstance(value, dict)
        ]
        presence_only = bool(rule.get("presence_only"))
        if not version:
            continue
        if min_score is not None:
            score += score_value(rule, "version_score")
        advisory_matches = advisory_matches_for_version(
            version,
            [value for value in rule.get("advisories", []) if isinstance(value, dict)],
        )
        if advisory_matches:
            pass
        elif rule.get("advisories"):
            continue
        elif threshold:
            if not version_lt(version, str(threshold)):
                continue
        elif threshold_or_equal:
            if version_lt(str(threshold_or_equal), version):
                continue
        elif affected_ranges:
            if not version_matches_affected_ranges(version, affected_ranges):
                continue
        elif exact_versions:
            if version not in exact_versions:
                continue
        elif not presence_only:
            continue
        if min_score is not None:
            try:
                if score < int(min_score):
                    continue
            except (TypeError, ValueError):
                if score <= 0:
                    continue

        plugin_id = str(rule["plugin_id"])
        product_name = rule.get("product_name")
        if not product_name and aliases:
            product_name = aliases[0]
        confidence = rule.get("confidence")
        review_labels = [
            str(value).strip()
            for value in rule.get("review_labels", [])
            if str(value).strip()
        ]
        resolved_cve_ids = list(rule.get("cve_ids", []))
        resolved_kev = rule.get("kev_matched")
        if advisory_matches:
            resolved_cve_ids = sorted(
                {
                    str(cve_id).strip().upper()
                    for advisory in advisory_matches
                    for cve_id in advisory.get("cve_ids", [])
                    if str(cve_id).strip()
                }
            )
            resolved_kev = any(bool(advisory.get("kev_matched")) for advisory in advisory_matches)
        print(
            json.dumps(
                {
                    "detector": str(rule.get("detector", plugin_id)),
                    "severity": str(rule.get("severity", "high")),
                    "path": document.get("path"),
                    "redacted_value": str(rule.get("redacted_value", plugin_id)),
                    "evidence": render_evidence(
                        rule, plugin_id, version, str(document.get("path", ""))
                    ),
                    "fingerprint": f"{plugin_id}:{document.get('path', '')}:{version}",
                    "confidence": confidence,
                    "matched_signals": collect_matched_signals(
                        rule,
                        path,
                        lowered_body,
                        headers,
                        header_blob,
                        aliases,
                        version,
                    ),
                    "review_labels": review_labels,
                    "plugin_id": plugin_id,
                    "product_name": product_name,
                    "product_version": version,
                    "cpe": rule.get("cpe"),
                    "cve_ids": resolved_cve_ids,
                    "kev_matched": resolved_kev,
                }
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
