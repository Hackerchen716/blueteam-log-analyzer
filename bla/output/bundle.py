"""标准报告目录输出。"""
from __future__ import annotations

import os
from typing import Dict, List

from ..models import AnalysisSummary, ParseResult
from ..utils.helpers import safe_print
from .csv_report import generate_csv_report
from .html_report import generate_html_report
from .ioc_report import generate_ioc_report
from .json_report import generate_json_report
from .sarif_report import generate_sarif_report


def generate_report_bundle(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    output_dir: str,
) -> Dict[str, str]:
    """生成一套标准交付报告文件，并返回各产物路径。"""
    os.makedirs(output_dir, exist_ok=True)
    paths = {
        "html": os.path.join(output_dir, "index.html"),
        "json": os.path.join(output_dir, "report.json"),
        "csv": os.path.join(output_dir, "events.csv"),
        "ioc": os.path.join(output_dir, "iocs.txt"),
        "sarif": os.path.join(output_dir, "report.sarif"),
    }

    safe_print(f"  [✓] 报告目录: {output_dir}")
    generate_html_report(parse_results, summary, paths["html"])
    generate_json_report(parse_results, summary, paths["json"])
    generate_csv_report(parse_results, summary, paths["csv"])
    generate_ioc_report(parse_results, summary, paths["ioc"])
    generate_sarif_report(parse_results, summary, paths["sarif"])
    return paths
