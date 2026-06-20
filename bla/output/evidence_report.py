"""Curated incident evidence export.

The full events.csv is useful for deep review, but it is too large for first
response handoff. This module exports only evidence that is referenced by the
incident brief, so each conclusion can be audited without rereading the whole
event stream.
"""

from __future__ import annotations

import csv
import os
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from ..incident_brief import ensure_incident_brief
from ..utils.helpers import safe_print, sanitize_report_text
from .csv_report import _csv_safe


EVIDENCE_COLUMNS = [
    "evidence_id",
    "used_by",
    "confidence",
    "timestamp",
    "timestamp_text",
    "source",
    "source_type",
    "category",
    "actor_ip",
    "method",
    "path",
    "status",
    "raw",
    "note",
]


def generate_incident_evidence_csv(parse_results: Any, summary: Any, output_path: str) -> None:
    """Write a compact CSV containing only incident-brief evidence."""

    brief = ensure_incident_brief(parse_results, summary)
    if not brief:
        brief = getattr(summary, "incident_brief", {}) or {}

    rows = extract_incident_evidence_rows(brief)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=EVIDENCE_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: _csv_safe(_cell(row.get(column))) for column in EVIDENCE_COLUMNS})

    safe_print(f"  [✓] 研判证据包已保存: {sanitize_report_text(output_path)}  ({len(rows)} 条证据)")


def extract_incident_evidence_rows(brief: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract deduplicated evidence rows from a generated incident brief."""

    rows: List[Dict[str, Any]] = []
    seen = set()
    for evidence, used_by, context in _iter_referenced_evidence(brief):
        row = _evidence_to_row(evidence, used_by, context)
        key = (
            row.get("evidence_id"),
            row.get("used_by"),
            row.get("timestamp"),
            row.get("source"),
            row.get("raw"),
            row.get("path"),
        )
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)

    rows.sort(
        key=lambda row: (
            str(row.get("timestamp") or row.get("timestamp_text") or ""),
            str(row.get("source") or ""),
            str(row.get("evidence_id") or ""),
            str(row.get("used_by") or ""),
        )
    )
    return rows


def _iter_referenced_evidence(
    value: Any,
    path: Sequence[str] = (),
) -> Iterable[Tuple[Dict[str, Any], str, Dict[str, Any]]]:
    if isinstance(value, dict):
        title = _node_title(value)
        next_path = tuple(item for item in (*path, title) if item)

        evidence_items = value.get("evidence")
        if isinstance(evidence_items, dict):
            evidence_items = [evidence_items]
        if isinstance(evidence_items, list):
            used_by = " / ".join(next_path) or "incident_brief"
            for item in evidence_items:
                if isinstance(item, dict):
                    yield item, used_by, value
                else:
                    yield {"raw": item}, used_by, value

        for key, child in value.items():
            if key == "evidence":
                continue
            yield from _iter_referenced_evidence(child, next_path)
        return

    if isinstance(value, list):
        for child in value:
            yield from _iter_referenced_evidence(child, path)


def _node_title(node: Dict[str, Any]) -> str:
    for key in ("title", "headline", "name", "summary", "question", "finding", "label"):
        value = node.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    kind = node.get("kind") or node.get("type") or node.get("category")
    if isinstance(kind, str) and kind.strip():
        return kind.strip()
    return ""


def _evidence_to_row(
    evidence: Dict[str, Any],
    used_by: str,
    context: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "evidence_id": _first(evidence, "evidence_id", "event_id", "id", "label"),
        "used_by": used_by,
        "confidence": _first(context, "confidence", "certainty"),
        "timestamp": _first(evidence, "timestamp", "time", "datetime", "ts"),
        "timestamp_text": _first(evidence, "timestamp_text", "time_text", "display_time", "display_ts"),
        "source": _first(evidence, "source", "source_file", "file", "filename", "log_file"),
        "source_type": _first(evidence, "source_type", "log_type", "parser", "type"),
        "category": _first(
            evidence,
            "category",
            "event_type",
            "kind",
            default=_first(context, "category", "kind", "type"),
        ),
        "actor_ip": _first(evidence, "actor_ip", "client_ip", "src_ip", "source_ip", "ip"),
        "method": _first(evidence, "method", "http_method"),
        "path": _first(evidence, "path", "uri", "url", "request_path"),
        "status": _first(evidence, "status", "status_code", "http_status"),
        "raw": _first(evidence, "raw", "raw_line", "message", "description", "context"),
        "note": _first(evidence, "note", "reason", default=_first(context, "note", "reason", "summary")),
    }


def _first(mapping: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return default


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return "; ".join(_cell(item) for item in value if item is not None)
    if isinstance(value, dict):
        return "; ".join(f"{key}={_cell(item)}" for key, item in value.items() if item is not None)
    return str(value)
