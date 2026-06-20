"""Standalone investigation brief output."""
from __future__ import annotations

from typing import List

from ..incident_brief import ensure_incident_brief, render_incident_brief_markdown
from ..models import AnalysisSummary, ParseResult
from ..utils.helpers import safe_print, sanitize_report_text


def generate_incident_brief_report(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    output_path: str,
) -> None:
    brief = ensure_incident_brief(parse_results, summary)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(render_incident_brief_markdown(brief))
    safe_print(f"  [✓] 应急研判摘要已保存: {sanitize_report_text(output_path)}")
