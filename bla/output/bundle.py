"""标准报告目录输出。"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from ..models import AnalysisSummary, ParseResult
from ..utils.helpers import safe_print, sanitize_report_text
from .csv_report import generate_csv_report
from .html_report import generate_html_report
from .ioc_report import generate_ioc_report
from .json_report import generate_json_report
from .manifest import generate_manifest
from .sarif_report import generate_sarif_report


def generate_report_bundle(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    output_dir: str,
    manifest_context: Optional[Dict[str, Any]] = None,
    geoip_cache_path: Optional[str] = None,
    include_json_events: bool = True,
    json_events_limit: Optional[int] = None,
    json_raw_line_limit: Optional[int] = None,
) -> Dict[str, str]:
    """生成一套标准交付报告文件，并返回各产物路径。"""
    os.makedirs(output_dir, exist_ok=True)
    paths = {
        "html": os.path.join(output_dir, "index.html"),
        "json": os.path.join(output_dir, "report.json"),
        "csv": os.path.join(output_dir, "events.csv"),
        "ioc": os.path.join(output_dir, "iocs.txt"),
        "sarif": os.path.join(output_dir, "report.sarif"),
        "manifest": os.path.join(output_dir, "manifest.json"),
    }

    safe_print(f"  [✓] 报告目录: {sanitize_report_text(output_dir)}")
    generate_html_report(parse_results, summary, paths["html"], geoip_cache_path=geoip_cache_path)
    generate_json_report(
        parse_results,
        summary,
        paths["json"],
        include_events=include_json_events,
        events_limit=json_events_limit,
        raw_line_limit=json_raw_line_limit,
    )
    generate_csv_report(parse_results, summary, paths["csv"])
    generate_ioc_report(parse_results, summary, paths["ioc"])
    generate_sarif_report(parse_results, summary, paths["sarif"])
    generate_manifest(
        parse_results,
        summary,
        paths["manifest"],
        context=manifest_context,
        bundle_files={key: value for key, value in paths.items() if key != "manifest"},
    )
    return paths
