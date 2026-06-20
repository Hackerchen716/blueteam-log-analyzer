"""Report bundle manifest output."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
from typing import Any, Dict, Iterable, List, Optional

from ..__version__ import __version__
from ..models import AnalysisSummary, ParseResult
from ..utils.helpers import safe_print, sanitize_report_text


MANIFEST_SCHEMA = "bla-report-manifest-v1"
JSON_TIMELINE_LIMIT = 200
HTML_TIMELINE_LIMIT = 100
CSV_RAW_LINE_LIMIT = 200


def generate_manifest(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    output_path: str,
    context: Optional[Dict[str, Any]] = None,
    bundle_files: Optional[Dict[str, str]] = None,
) -> None:
    """Write a provenance manifest for a standard report bundle."""
    context = context or {}
    bundle_files = bundle_files or {}
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "meta": {
            "tool": "BlueTeam Log Analyzer (BLA)",
            "version": __version__,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
        "summary": {
            "risk_score": summary.risk_score,
            "risk_level": summary.risk_level.value,
            "files_analyzed": summary.files_analyzed,
            "total_events": summary.total_events,
            "alert_count": len(summary.alerts),
            "incident_count": len(summary.incidents),
            "incident_brief": bool(getattr(summary, "incident_brief", None)),
            "timeline_count": len(summary.timeline),
        },
        "limits": {
            "json_timeline_limit": JSON_TIMELINE_LIMIT,
            "html_timeline_limit": HTML_TIMELINE_LIMIT,
            "csv_raw_line_limit": CSV_RAW_LINE_LIMIT,
            "timeline_truncated_in_json": len(summary.timeline) > JSON_TIMELINE_LIMIT,
            "timeline_truncated_in_html": len(summary.timeline) > HTML_TIMELINE_LIMIT,
        },
        "inputs": context.get("inputs") or _input_records(parse_results),
        "parsed_files": _parsed_file_records(parse_results),
        "outputs": _output_records(bundle_files.values()),
        "options": context.get("options", {}),
        "remote": context.get("remote", {}),
        "remote_collection": context.get("remote_collection", []),
        "parse_errors": context.get("parse_errors", []),
        "suppressed_events": context.get("suppressed_events", 0),
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(_sanitize_manifest_value(manifest), f, ensure_ascii=False, indent=2)

    safe_print(f"  [✓] 交付清单已保存: {sanitize_report_text(output_path)}")


def _input_records(parse_results: Iterable[ParseResult]) -> List[Dict[str, Any]]:
    return [
        {
            "name": result.file_name,
            "type": result.log_type,
            "size_bytes": result.file_size_bytes,
            "events": result.stats.total,
        }
        for result in parse_results
    ]


def _parsed_file_records(parse_results: Iterable[ParseResult]) -> List[Dict[str, Any]]:
    records = []
    for result in parse_results:
        records.append({
            "name": result.file_name,
            "type": result.log_type,
            "size_bytes": result.file_size_bytes,
            "events": result.stats.total,
            "time_start": result.stats.time_start,
            "time_end": result.stats.time_end,
            "parse_ms": round(result.parse_time_ms, 1),
            "levels": {
                "critical": result.stats.critical,
                "high": result.stats.high,
                "medium": result.stats.medium,
                "low": result.stats.low,
                "info": result.stats.info,
            },
        })
    return records


def _output_records(paths: Iterable[str]) -> List[Dict[str, Any]]:
    records = []
    for path in paths:
        if not path:
            continue
        try:
            stat = os.stat(path)
        except OSError:
            continue
        records.append({
            "name": os.path.basename(path),
            "path": os.path.basename(path),
            "size_bytes": stat.st_size,
            "sha256": _sha256_file(path),
        })
    return records


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sanitize_manifest_value(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_report_text(value)
    if isinstance(value, list):
        return [_sanitize_manifest_value(item) for item in value]
    if isinstance(value, dict):
        return {
            sanitize_report_text(key) if isinstance(key, str) else key: _sanitize_manifest_value(item)
            for key, item in value.items()
        }
    return value
