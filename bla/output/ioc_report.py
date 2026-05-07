"""IOC 文本导出"""
from __future__ import annotations

from typing import List

from ..ioc import extract_iocs, format_ioc_report
from ..models import ParseResult, AnalysisSummary


def generate_ioc_report(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    output_path: str,
) -> None:
    """导出 IOC 清单，便于封禁、研判和工单流转。"""
    events = []
    for result in parse_results:
        events.extend(result.events)

    # IOC 清单用于封禁/工单流转，必须只包含告警相关的高置信度证据
    iocs = extract_iocs(events, alerts=summary.alerts)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(format_ioc_report(iocs))

    total = sum(len(values) for values in iocs.values())
    print(f"  [✓] IOC 清单已保存: {output_path}  ({total} 项 · 仅含告警涉及的事件)")
