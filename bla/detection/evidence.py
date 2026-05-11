"""Evidence enrichment for alerts and reports."""
from __future__ import annotations

from typing import Dict, Iterable, List

from ..models import DetectionAlert, LogEvent, ThreatLevel


def enrich_alert_evidence(alerts: Iterable[DetectionAlert], events: Iterable[LogEvent]) -> List[DetectionAlert]:
    """Attach investigation-grade event evidence to high-risk alerts.

    JSON already exports full events, but HTML and terminal alert cards render
    alert.evidence directly. This helper keeps those report surfaces useful by
    adding request fields and raw log lines to high/critical alerts.
    """
    event_by_id: Dict[str, LogEvent] = {event.id: event for event in events}
    enriched = list(alerts)
    for alert in enriched:
        if alert.level.score < ThreatLevel.HIGH.score:
            continue
        existing = set(alert.evidence)
        for event_id in alert.affected_events:
            event = event_by_id.get(event_id)
            if not event:
                continue
            additions = _event_evidence_lines(event)
            for item in additions:
                if item and item not in existing:
                    alert.evidence.append(item)
                    existing.add(item)
    return enriched


def _event_evidence_lines(event: LogEvent) -> List[str]:
    details = event.details or {}
    lines: List[str] = []
    scanner_tool = details.get("scanner_tool", "")
    method = details.get("method", "")
    path = details.get("decoded_path") or details.get("path", "")
    status = details.get("status", "")
    user_agent = details.get("user_agent", "")
    referer = details.get("referer", "")

    prefix = f"事件 {event.id}"
    if scanner_tool:
        lines.append(f"{prefix} 扫描工具: {scanner_tool}")
    if method or path or status:
        lines.append(f"{prefix} 请求: {method} {path} -> {status}".strip())
    if user_agent:
        lines.append(f"{prefix} User-Agent: {user_agent}")
    if referer:
        lines.append(f"{prefix} Referer: {referer}")
    if event.raw_line:
        lines.append(f"{prefix} 原始日志: {event.raw_line}")
    return lines
