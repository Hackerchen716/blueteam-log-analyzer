"""JSON 报告输出"""
from __future__ import annotations
import json
import datetime
from typing import Any, List
from ..__version__ import __version__
from ..ioc import extract_iocs
from ..models import ParseResult, AnalysisSummary
from ..utils.helpers import safe_print, sanitize_report_text


TIMELINE_LIMIT = 200


def generate_json_report(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    output_path: str,
) -> None:
    all_events = []
    for result in parse_results:
        all_events.extend(result.events)

    # 高置信度 IOC：只从触发告警的事件中提取，避免把正常运维流量混进列表
    iocs_high_conf = extract_iocs(all_events, alerts=summary.alerts)
    level_counts = {
        "critical": sum(r.stats.critical for r in parse_results),
        "high": sum(r.stats.high for r in parse_results),
        "medium": sum(r.stats.medium for r in parse_results),
        "low": sum(r.stats.low for r in parse_results),
        "info": sum(r.stats.info for r in parse_results),
    }

    timeline_total = len(summary.timeline)
    timeline_returned = min(timeline_total, TIMELINE_LIMIT)
    report = {
        "meta": {
            "tool": "BlueTeam Log Analyzer (BLA)",
            "version": __version__,
            "generated_at": datetime.datetime.now().isoformat(),
            "files_analyzed": summary.files_analyzed,
        },
        "summary": {
            "risk_score": summary.risk_score,
            "risk_level": summary.risk_level.value,
            "files_analyzed": summary.files_analyzed,
            "total_events": summary.total_events,
            "alert_count": len(summary.alerts),
            "incident_count": len(summary.incidents),
            "timeline_count": len(summary.timeline),
            "timeline_returned": timeline_returned,
            "recommendation_count": len(summary.recommendations),
            "by_level": level_counts,
            "limits": {
                "timeline": {
                    "returned": timeline_returned,
                    "total": timeline_total,
                    "limit": TIMELINE_LIMIT,
                    "truncated": timeline_total > TIMELINE_LIMIT,
                },
            },
        },
        "risk": {
            "score": summary.risk_score,
            "level": summary.risk_level.value,
        },
        "statistics": {
            "total_events": summary.total_events,
            "alert_count": len(summary.alerts),
            "incident_count": len(summary.incidents),
            "timeline_count": len(summary.timeline),
            "timeline_returned": timeline_returned,
            "by_level": level_counts,
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
                "top_local_ips": r.stats.top_local_ips[:5],
                "top_users":  r.stats.top_users[:5],
                "categories": r.stats.categories,
                "attack_types": r.stats.attack_types,
                "windows_logon_stats": r.stats.windows_logon_stats,
                "windows_process_creation_stats": r.stats.windows_process_creation_stats,
            }
            for r in parse_results
        ],
        "events": [event.to_dict() for event in all_events],
        "alerts": [a.to_dict() for a in summary.alerts],
        "incidents": [incident.to_dict() for incident in summary.incidents],
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
            for t in summary.timeline[:TIMELINE_LIMIT]
        ],
        "truncation": {
            "timeline": {
                "returned": timeline_returned,
                "total": timeline_total,
                "limit": TIMELINE_LIMIT,
                "truncated": timeline_total > TIMELINE_LIMIT,
            },
        },
        "iocs": iocs_high_conf,
        "iocs_all_events": extract_iocs(all_events),
        "recommendations": summary.recommendations,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(_sanitize_json_value(report), f, ensure_ascii=False, indent=2)

    safe_print(f"  [✓] JSON 报告已保存: {output_path}")


def _sanitize_json_value(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_report_text(value)
    if isinstance(value, list):
        return [_sanitize_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize_json_value(item) for key, item in value.items()}
    return value
