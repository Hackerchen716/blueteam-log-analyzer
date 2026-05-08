"""Allowlist support for reducing expected noise in real environments."""
from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, Dict, Iterable, List, Tuple

from .models import LogEvent, ParseResult
from .parsers.stats import compute_stats


ALLOWLIST_FIELDS = {
    "ips",
    "users",
    "hosts",
    "processes",
    "paths",
    "user_agents",
    "messages",
    "rule_names",
    "event_ids",
    "rule_ids",
    "source_types",
    "tags",
    "trusted_scanners",
    "maintenance_windows",
    "suppressions",
}


def load_allowlist(path: str) -> Dict[str, Any]:
    """Load a JSON allowlist file."""
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, dict):
        raise ValueError("allowlist 必须是 JSON 对象")

    allowlist: Dict[str, List[str]] = {}
    for key, value in raw.items():
        if key not in ALLOWLIST_FIELDS:
            raise ValueError(f"allowlist 不支持字段: {key}")
        if key in {"maintenance_windows", "suppressions"}:
            if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
                raise ValueError(f"allowlist 字段 {key} 必须是对象数组")
            allowlist[key] = value
            continue
        if isinstance(value, str):
            items = [value]
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            items = value
        else:
            raise ValueError(f"allowlist 字段 {key} 必须是字符串或字符串数组")
        allowlist[key] = [item for item in items if item]
    return allowlist


def apply_allowlist(
    parse_results: Iterable[ParseResult],
    allowlist: Dict[str, Any],
) -> Tuple[List[ParseResult], int]:
    """Return parse results with allowlisted events removed plus suppressed count."""
    filtered_results: List[ParseResult] = []
    suppressed = 0

    for result in parse_results:
        kept_events = []
        for event in result.events:
            if is_allowlisted(event, allowlist):
                suppressed += 1
            else:
                kept_events.append(event)
        filtered_results.append(replace(result, events=kept_events, stats=compute_stats(kept_events)))

    return filtered_results, suppressed


def is_allowlisted(event: LogEvent, allowlist: Dict[str, Any]) -> bool:
    if _exact(event.ip, allowlist.get("ips")):
        return True
    if _exact(event.user, allowlist.get("users")):
        return True
    if _exact(event.host, allowlist.get("hosts")):
        return True
    if _exact(event.process, allowlist.get("processes")):
        return True
    if _exact(event.rule_name, allowlist.get("rule_names")):
        return True
    if _exact(event.rule_id, allowlist.get("rule_ids")):
        return True
    if _exact(event.event_id, allowlist.get("event_ids")):
        return True
    if _exact(event.details.get("source_type"), allowlist.get("source_types")):
        return True
    if any(_exact(tag, allowlist.get("tags")) for tag in event.tags):
        return True
    if _exact(event.ip, allowlist.get("trusted_scanners")) and any(
        tag in event.tags for tag in ("scanner", "scanning", "recon", "reconnaissance")
    ):
        return True

    path = str(event.details.get("path") or event.details.get("decoded_path") or "")
    user_agent = str(event.details.get("user_agent") or "")
    if _contains(path, allowlist.get("paths")):
        return True
    if _contains(user_agent, allowlist.get("user_agents")):
        return True
    if _contains(event.message + "\n" + event.raw_line, allowlist.get("messages")):
        return True
    if _in_maintenance_window(event, allowlist.get("maintenance_windows") or []):
        return True
    if any(_suppression_matches(event, item) for item in allowlist.get("suppressions") or []):
        return True
    return False


def _exact(value: Any, allowed: List[str] | None) -> bool:
    if not value or not allowed:
        return False
    return str(value).lower() in {item.lower() for item in allowed}


def _contains(value: str, allowed: List[str] | None) -> bool:
    if not value or not allowed:
        return False
    lower = value.lower()
    return any(item.lower() in lower for item in allowed)


def _in_maintenance_window(event: LogEvent, windows: List[Dict[str, Any]]) -> bool:
    """Match simple ISO string windows: {"start": "...", "end": "...", "hosts": [...]}."""
    ts = event.timestamp or ""
    if not ts:
        return False
    for window in windows:
        start = str(window.get("start") or "")
        end = str(window.get("end") or "")
        if start and ts < start:
            continue
        if end and ts > end:
            continue
        if not _scope_matches(event, window):
            continue
        return True
    return False


def _suppression_matches(event: LogEvent, rule: Dict[str, Any]) -> bool:
    return _scope_matches(event, rule)


def _scope_matches(event: LogEvent, scope: Dict[str, Any]) -> bool:
    checks = {
        "ips": event.ip,
        "users": event.user,
        "hosts": event.host,
        "processes": event.process,
        "rule_names": event.rule_name,
        "rule_ids": event.rule_id,
        "event_ids": event.event_id,
        "source_types": event.details.get("source_type"),
    }
    for key, value in checks.items():
        allowed = scope.get(key)
        if allowed and not _exact(value, _as_list(allowed)):
            return False
    if scope.get("tags") and not any(_exact(tag, _as_list(scope.get("tags"))) for tag in event.tags):
        return False
    if scope.get("messages") and not _contains(event.message + "\n" + event.raw_line, _as_list(scope.get("messages"))):
        return False
    if scope.get("paths"):
        path = str(event.details.get("path") or event.details.get("decoded_path") or event.details.get("url") or "")
        if not _contains(path, _as_list(scope.get("paths"))):
            return False
    return True


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]
