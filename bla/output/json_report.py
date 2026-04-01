"""JSON 报告输出"""
from __future__ import annotations
import json
import datetime
from typing import List
from ..models import ParseResult, AnalysisSummary


def generate_json_report(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    output_path: str,
) -> None:
    report = {
        "meta": {
            "tool": "BlueTeam Log Analyzer (BLA)",
            "version": "1.0.0",
            "generated_at": datetime.datetime.now().isoformat(),
            "files_analyzed": summary.files_analyzed,
        },
        "risk": {
            "score": summary.risk_score,
            "level": summary.risk_level.value,
        },
        "statistics": {
            "total_events": summary.total_events,
            "alert_count": len(summary.alerts),
            "by_level": {
                "critical": sum(r.stats.critical for r in parse_results),
                "high":     sum(r.stats.high     for r in parse_results),
                "medium":   sum(r.stats.medium   for r in parse_results),
                "low":      sum(r.stats.low      for r in parse_results),
                "info":     sum(r.stats.info     for r in parse_results),
            },
        },
        "files": [
            {
                "name":       r.file_name,
                "type":       r.log_type,
                "size_bytes": r.file_size_bytes,
                "parse_ms":   round(r.parse_time_ms, 1),
                "events":     r.stats.total,
                "time_start": r.stats.time_start,
                "time_end":   r.stats.time_end,
                "top_ips":    r.stats.top_ips[:5],
                "top_users":  r.stats.top_users[:5],
                "categories": r.stats.categories,
                "attack_types": r.stats.attack_types,
            }
            for r in parse_results
        ],
        "alerts": [a.to_dict() for a in summary.alerts],
        "attack_chain": [
            {
                "phase":       c.phase,
                "event_count": c.event_count,
                "level":       c.level.value,
                "techniques":  c.techniques,
            }
            for c in summary.attack_chain
        ],
        "timeline": [
            {
                "timestamp":   t.timestamp,
                "level":       t.level.value,
                "category":    t.category,
                "message":     t.message,
                "source_file": t.source_file,
                "mitre":       t.mitre_attack,
            }
            for t in summary.timeline[:200]
        ],
        "recommendations": summary.recommendations,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"  [✓] JSON 报告已保存: {output_path}")
