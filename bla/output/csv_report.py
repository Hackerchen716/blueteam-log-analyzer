"""CSV 报告输出"""
from __future__ import annotations
import csv
from typing import List
from ..models import ParseResult, AnalysisSummary
from ..utils.helpers import safe_print


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
        "mitre_attack", "tags", "raw_line",
    ]

    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()

        all_events = []
        for r in parse_results:
            all_events.extend(r.events)
        all_events.sort(key=lambda e: e.timestamp)

        for ev in all_events:
            writer.writerow({
                "timestamp":   ev.timestamp,
                "level":       ev.level.value,
                "category":    ev.category,
                "rule_name":   ev.rule_name or "",
                "message":     ev.message,
                "source_file": ev.source_file,
                "event_id":    ev.event_id or "",
                "user":        ev.user or "",
                "host":        ev.host or "",
                "ip":          ev.ip or "",
                "process":     ev.process or "",
                "source_type":  ev.details.get("source_type", ""),
                "src_ip":       ev.details.get("src_ip", ""),
                "dst_ip":       ev.details.get("dst_ip", ""),
                "asset":        ev.details.get("asset", ""),
                "account":      ev.details.get("account", ""),
                "action":       ev.details.get("action", ""),
                "status":       ev.details.get("status", ""),
                "url":          ev.details.get("url", ""),
                "command":      ev.details.get("command", ""),
                "bytes_out":    ev.details.get("bytes_out", ""),
                "asset_role":   ev.details.get("asset_role", ""),
                "event_family": ev.details.get("event_family", ""),
                "mitre_attack":ev.mitre_attack or "",
                "tags":        "|".join(ev.tags),
                "raw_line":    ev.raw_line[:200],
            })

    safe_print(f"  [✓] CSV 报告已保存: {output_path}  ({len(all_events)} 条事件)")
