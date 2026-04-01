"""CSV 报告输出"""
from __future__ import annotations
import csv
from typing import List
from ..models import ParseResult, AnalysisSummary


def generate_csv_report(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    output_path: str,
) -> None:
    """导出所有事件到 CSV（便于 Excel 分析）"""
    fields = [
        "timestamp", "level", "category", "rule_name", "message",
        "source_file", "event_id", "user", "host", "ip", "process",
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
                "mitre_attack":ev.mitre_attack or "",
                "tags":        "|".join(ev.tags),
                "raw_line":    ev.raw_line[:200],
            })

    print(f"  [✓] CSV 报告已保存: {output_path}  ({len(all_events)} 条事件)")
