"""CSV 报告输出"""
from __future__ import annotations

import csv
from typing import List

from ..models import AnalysisSummary, ParseResult
from ..utils.helpers import safe_print, sanitize_report_text

_FORMULA_PREFIXES = ("=", "+", "-", "@")
RAW_LINE_LIMIT = 200


def _csv_safe(value) -> str:
    """Return a spreadsheet-safe CSV cell value."""
    if value is None:
        return ""
    text = sanitize_report_text(value)
    if text.lstrip(" \t\r\n").startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def generate_csv_report(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    output_path: str,
) -> None:
    """导出所有事件到 CSV（便于 Excel 分析）"""
    fields = [
        "timestamp", "level", "category", "rule_name", "message",
        "source_file", "event_id", "user", "host", "ip", "process",
        "source_type", "src_ip", "dst_ip", "asset", "account", "action",
        "status", "url", "command", "bytes_out", "asset_role", "event_family",
        "mitre_attack", "tags", "raw_line", "raw_line_truncated", "raw_line_length",
    ]

    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()

        all_events = []
        for r in parse_results:
            all_events.extend(r.events)
        all_events.sort(key=lambda e: e.timestamp)

        for ev in all_events:
            raw_line = sanitize_report_text(ev.raw_line)
            writer.writerow({
                "timestamp":   _csv_safe(ev.timestamp),
                "level":       _csv_safe(ev.level.value),
                "category":    _csv_safe(ev.category),
                "rule_name":   _csv_safe(ev.rule_name or ""),
                "message":     _csv_safe(ev.message),
                "source_file": _csv_safe(ev.source_file),
                "event_id":    _csv_safe(ev.event_id or ""),
                "user":        _csv_safe(ev.user or ""),
                "host":        _csv_safe(ev.host or ""),
                "ip":          _csv_safe(ev.ip or ""),
                "process":     _csv_safe(ev.process or ""),
                "source_type":  _csv_safe(ev.details.get("source_type", "")),
                "src_ip":       _csv_safe(ev.details.get("src_ip", "")),
                "dst_ip":       _csv_safe(ev.details.get("dst_ip", "")),
                "asset":        _csv_safe(ev.details.get("asset", "")),
                "account":      _csv_safe(ev.details.get("account", "")),
                "action":       _csv_safe(ev.details.get("action", "")),
                "status":       _csv_safe(ev.details.get("status", "")),
                "url":          _csv_safe(ev.details.get("url", "")),
                "command":      _csv_safe(ev.details.get("command", "")),
                "bytes_out":    _csv_safe(ev.details.get("bytes_out", "")),
                "asset_role":   _csv_safe(ev.details.get("asset_role", "")),
                "event_family": _csv_safe(ev.details.get("event_family", "")),
                "mitre_attack": _csv_safe(ev.mitre_attack or ""),
                "tags":        _csv_safe("|".join(ev.tags)),
                "raw_line":    _csv_safe(raw_line[:RAW_LINE_LIMIT]),
                "raw_line_truncated": "true" if len(raw_line) > RAW_LINE_LIMIT else "false",
                "raw_line_length": str(len(raw_line)),
            })

    safe_print(f"  [✓] CSV 报告已保存: {output_path}  ({len(all_events)} 条事件)")
