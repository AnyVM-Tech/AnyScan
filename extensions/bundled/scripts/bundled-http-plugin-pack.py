#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "http-plugin-rules.json"
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


def normalize_headers(document: dict[str, object]) -> dict[str, str]:
    return {
        str(name).strip().lower(): str(value).strip().lower()
        for name, value in document.get("headers", [])
        if str(name).strip()
    }


def contains_any(container: str, tokens: list[str]) -> bool:
    return any(token in container for token in tokens)


def contains_all(container: str, tokens: list[str]) -> bool:
    return all(token in container for token in tokens)


def render_evidence(rule: dict[str, object], summary: str, document: dict[str, object]) -> str:
    template = rule.get("evidence_template")
    if template:
        values = {
            "plugin_id": str(rule.get("plugin_id", "")),
            "product_name": str(rule.get("product_name", rule.get("plugin_id", ""))),
            "product_version": str(rule.get("product_version", "") or ""),
            "path": str(document.get("path", "") or ""),
            "summary": summary,
        }
        rendered = str(template)
        for key, value in values.items():
            rendered = rendered.replace(f"{{{key}}}", value)
        return rendered
    return str(rule.get("evidence", summary))


def collect_matched_signals(
    rule: dict[str, object],
    path: str,
    body: str,
    headers: dict[str, str],
    header_blob: str,
    aliases: list[str],
) -> list[str]:
    signals: list[str] = []
    if rule.get("path_contains") and contains_all(
        path, [str(value).lower() for value in rule.get("path_contains", [])]
    ):
        signals.append("path_contains")
    if rule.get("any_of_path_contains") and contains_any(
        path, [str(value).lower() for value in rule.get("any_of_path_contains", [])]
    ):
        signals.append("path_hint")
    if rule.get("body_contains") and contains_all(
        body, [str(value).lower() for value in rule.get("body_contains", [])]
    ):
        signals.append("body_contains")
    if rule.get("any_of_body_contains") and contains_any(
        body, [str(value).lower() for value in rule.get("any_of_body_contains", [])]
    ):
        signals.append("body_hint")
    if rule.get("path_regex") and re.search(str(rule.get("path_regex")), path, flags=re.IGNORECASE):
        signals.append("path_regex")
    if rule.get("body_regex") and re.search(str(rule.get("body_regex")), body, flags=re.IGNORECASE):
        signals.append("body_regex")
    header_contains = {
        str(name).strip().lower(): str(value).strip().lower()
        for name, value in dict(rule.get("header_contains", {})).items()
        if str(name).strip()
    }
    if header_contains and all(
        token in headers.get(name, "") for name, token in header_contains.items()
    ):
        signals.append("header_contains")
    if rule.get("header_regex") and re.search(
        str(rule.get("header_regex")), header_blob, flags=re.IGNORECASE
    ):
        signals.append("header_regex")
    if aliases and (
        contains_any(path, aliases)
        or contains_any(body, aliases)
        or contains_any(header_blob, aliases)
    ):
        signals.append("alias")
    return signals


def score_value(rule: dict[str, object], field: str, default: int = 1) -> int:
    value = rule.get(field, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def match_rule(document: dict[str, object], rule: dict[str, object]) -> bool:
    path = str(document.get("path", "")).lower()
    body = str(document.get("body", "")).lower()
    status = int(document.get("status", 0) or 0)
    headers = normalize_headers(document)
    header_blob = "\n".join(f"{name}: {value}" for name, value in headers.items())

    path_contains = [str(value).lower() for value in rule.get("path_contains", [])]
    any_of_path_contains = [str(value).lower() for value in rule.get("any_of_path_contains", [])]
    path_not_contains = [str(value).lower() for value in rule.get("path_not_contains", [])]
    any_of_path_not_contains = [
        str(value).lower() for value in rule.get("any_of_path_not_contains", [])
    ]
    body_contains = [str(value).lower() for value in rule.get("body_contains", [])]
    any_of_body_contains = [str(value).lower() for value in rule.get("any_of_body_contains", [])]
    body_not_contains = [str(value).lower() for value in rule.get("body_not_contains", [])]
    any_of_body_not_contains = [
        str(value).lower() for value in rule.get("any_of_body_not_contains", [])
    ]
    status_in = [int(value) for value in rule.get("status_in", [])]
    body_regex = rule.get("body_regex")
    path_regex = rule.get("path_regex")
    body_not_regex = rule.get("body_not_regex")
    path_not_regex = rule.get("path_not_regex")
    header_contains = {
        str(name).strip().lower(): str(value).strip().lower()
        for name, value in dict(rule.get("header_contains", {})).items()
        if str(name).strip()
    }
    header_not_contains = {
        str(name).strip().lower(): str(value).strip().lower()
        for name, value in dict(rule.get("header_not_contains", {})).items()
        if str(name).strip()
    }
    header_regex = rule.get("header_regex")
    header_not_regex = rule.get("header_not_regex")
    aliases = rule_aliases(rule)
    min_score = rule.get("min_score")

    positive_matchers = 0
    score = 0

    if path_not_contains and contains_any(path, path_not_contains):
        return False
    if any_of_path_not_contains and contains_any(path, any_of_path_not_contains):
        return False
    if body_not_contains and contains_any(body, body_not_contains):
        return False
    if any_of_body_not_contains and contains_any(body, any_of_body_not_contains):
        return False
    if header_not_contains and any(
        token in headers.get(name, "") for name, token in header_not_contains.items()
    ):
        return False
    if path_not_regex and re.search(str(path_not_regex), path, flags=re.IGNORECASE):
        return False
    if body_not_regex and re.search(str(body_not_regex), body, flags=re.IGNORECASE):
        return False
    if header_not_regex and re.search(str(header_not_regex), header_blob, flags=re.IGNORECASE):
        return False

    if path_contains:
        positive_matchers += 1
        matched = contains_all(path, path_contains)
        if min_score is None and not matched:
            return False
        if matched:
            score += score_value(rule, "path_contains_score")
    if any_of_path_contains:
        positive_matchers += 1
        matched = contains_any(path, any_of_path_contains)
        if min_score is None and not matched:
            return False
        if matched:
            score += score_value(rule, "any_of_path_contains_score")
    if body_contains:
        positive_matchers += 1
        matched = contains_all(body, body_contains)
        if min_score is None and not matched:
            return False
        if matched:
            score += score_value(rule, "body_contains_score")
    if any_of_body_contains:
        positive_matchers += 1
        matched = contains_any(body, any_of_body_contains)
        if min_score is None and not matched:
            return False
        if matched:
            score += score_value(rule, "any_of_body_contains_score")
    if status_in and status not in status_in:
        return False
    if path_regex:
        positive_matchers += 1
        matched = bool(re.search(str(path_regex), path, flags=re.IGNORECASE))
        if min_score is None and not matched:
            return False
        if matched:
            score += score_value(rule, "path_regex_score")
    if body_regex:
        positive_matchers += 1
        matched = bool(re.search(str(body_regex), body, flags=re.IGNORECASE))
        if min_score is None and not matched:
            return False
        if matched:
            score += score_value(rule, "body_regex_score")
    if header_contains:
        positive_matchers += 1
        matched = all(token in headers.get(name, "") for name, token in header_contains.items())
        if min_score is None and not matched:
            return False
        if matched:
            score += score_value(rule, "header_contains_score")
    if header_regex:
        positive_matchers += 1
        matched = bool(re.search(str(header_regex), header_blob, flags=re.IGNORECASE))
        if min_score is None and not matched:
            return False
        if matched:
            score += score_value(rule, "header_regex_score")
    if aliases:
        positive_matchers += 1
        matched = (
            contains_any(path, aliases)
            or contains_any(body, aliases)
            or contains_any(header_blob, aliases)
        )
        if min_score is None and not matched:
            return False
        if matched:
            score += score_value(rule, "aliases_score")
    if positive_matchers == 0:
        return False
    if min_score is not None:
        try:
            return score >= int(min_score)
        except (TypeError, ValueError):
            return score > 0
    return True


def emit_finding(document: dict[str, object], rule: dict[str, object]) -> dict[str, object]:
    plugin_id = str(rule["plugin_id"])
    detector = str(rule.get("detector", plugin_id))
    summary = str(rule.get("summary", f"{plugin_id} matched bundled HTTP rule"))
    severity = str(rule.get("severity", "medium"))
    product_name = rule.get("product_name")
    product_version = rule.get("product_version")
    cpe = rule.get("cpe")
    cve_ids = list(rule.get("cve_ids", []))
    kev_matched = rule.get("kev_matched")
    confidence = rule.get("confidence")
    review_labels = [
        str(value).strip()
        for value in rule.get("review_labels", [])
        if str(value).strip()
    ]
    path = str(document.get("path", "")).lower()
    body = str(document.get("body", "")).lower()
    headers = normalize_headers(document)
    header_blob = "\n".join(f"{name}: {value}" for name, value in headers.items())
    aliases = rule_aliases(rule)

    redacted_value = str(rule.get("redacted_value", plugin_id))
    evidence = render_evidence(rule, summary, document)

    return {
        "detector": detector,
        "severity": severity,
        "path": document.get("path"),
        "redacted_value": redacted_value,
        "evidence": evidence,
        "fingerprint": f"{plugin_id}:{document.get('path', '')}",
        "confidence": confidence,
        "matched_signals": collect_matched_signals(
            rule, path, body, headers, header_blob, aliases
        ),
        "review_labels": review_labels,
        "plugin_id": plugin_id,
        "product_name": product_name,
        "product_version": product_version,
        "cpe": cpe,
        "cve_ids": cve_ids,
        "kev_matched": kev_matched,
    }


def main() -> int:
    try:
        document = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 1

    for rule in load_rules():
        if match_rule(document, rule):
            print(json.dumps(emit_finding(document, rule)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
