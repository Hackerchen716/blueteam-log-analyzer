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
}


def load_allowlist(path: str) -> Dict[str, List[str]]:
    """Load a JSON allowlist file."""
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, dict):
        raise ValueError("allowlist 必须是 JSON 对象")

    allowlist: Dict[str, List[str]] = {}
    for key, value in raw.items():
        if key not in ALLOWLIST_FIELDS:
            raise ValueError(f"allowlist 不支持字段: {key}")
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
    allowlist: Dict[str, List[str]],
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


def is_allowlisted(event: LogEvent, allowlist: Dict[str, List[str]]) -> bool:
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
    if _exact(event.event_id, allowlist.get("event_ids")):
        return True

    path = str(event.details.get("path") or event.details.get("decoded_path") or "")
    user_agent = str(event.details.get("user_agent") or "")
    if _contains(path, allowlist.get("paths")):
        return True
    if _contains(user_agent, allowlist.get("user_agents")):
        return True
    if _contains(event.message + "\n" + event.raw_line, allowlist.get("messages")):
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
