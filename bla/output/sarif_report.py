"""SARIF 2.1.0 输出。

SARIF（Static Analysis Results Interchange Format）是 OASIS 标准，被 GitHub
Code Scanning、Azure Sentinel、SonarQube 等多种工具消费。BLA 把检测告警映射成
SARIF "result"，这样用户可以：

- ``gh code-scanning upload-sarif`` 把蓝队分析结果纳入 GitHub 安全标签页；
- 在 Azure DevOps / Jenkins 等流水线里走标准的安全门禁。

只导出告警（DetectionAlert），不导出原始事件——SARIF 的目标是"可操作的发现"，
事件级数据请用 JSON / CSV 导出。
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from ..__version__ import __version__
from ..models import AnalysisSummary, DetectionAlert, ParseResult, ThreatLevel
from ..utils.helpers import safe_print, sanitize_report_text


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

_LEVEL_MAP = {
    ThreatLevel.CRITICAL: "error",
    ThreatLevel.HIGH:     "error",
    ThreatLevel.MEDIUM:   "warning",
    ThreatLevel.LOW:      "note",
    ThreatLevel.INFO:     "none",
}


def _build_rule(alert: DetectionAlert) -> Dict[str, Any]:
    return {
        "id": sanitize_report_text(alert.rule_id),
        "name": sanitize_report_text(alert.rule_name),
        "shortDescription": {"text": sanitize_report_text(alert.rule_name)},
        "fullDescription": {"text": sanitize_report_text(alert.description)},
        "helpUri": "https://attack.mitre.org/techniques/" + alert.mitre_attack.replace(".", "/")
        if alert.mitre_attack else "",
        "properties": {
            "category": sanitize_report_text(alert.category),
            "mitre_phase": sanitize_report_text(alert.mitre_phase),
            "mitre_attack": sanitize_report_text(alert.mitre_attack),
            "tags": ["security", "blueteam", sanitize_report_text(alert.category)],
        },
    }


def _build_result(alert: DetectionAlert, source_file: str) -> Dict[str, Any]:
    uri = _artifact_uri(source_file)
    return {
        "ruleId": sanitize_report_text(alert.rule_id),
        "level": _LEVEL_MAP.get(alert.level, "warning"),
        "message": {
            "text": sanitize_report_text(f"{alert.description}\n建议: {alert.recommendation}"),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                }
            }
        ],
        "properties": {
            "confidence": sanitize_report_text(alert.confidence),
            "evidence": [sanitize_report_text(item) for item in alert.evidence],
            "affected_events": alert.affected_events,
            "affected_event_count": len(alert.affected_events),
            "timestamp": sanitize_report_text(alert.timestamp),
            "original_source_file": sanitize_report_text(source_file),
        },
    }


def _artifact_uri(source_file: str) -> str:
    source = str(source_file or "<merged>")
    if re.match(r"^[A-Za-z0-9_.-]+:", source) and "://" not in source:
        host, rest = source.split(":", 1)
        host = sanitize_report_text(host)
        rest = rest.replace("\\", "/")
        if rest.startswith("journalctl:"):
            return f"remote/{host}/journalctl/{rest.split(':', 1)[1]}"
        if rest.startswith("/"):
            return f"remote/{host}{rest}"
    return sanitize_report_text(source).replace("\\", "/")


def generate_sarif_report(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    output_path: str,
) -> None:
    """把检测告警导出为 SARIF 2.1.0。"""
    # 每个 rule 只声明一次
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    for alert in summary.alerts:
        if alert.rule_id not in rules_by_id:
            rules_by_id[alert.rule_id] = _build_rule(alert)

    # 把告警归到包含相关事件的源文件下；找不到就退回到 "<merged>"
    file_for_alert: Dict[str, str] = {}
    for result in parse_results:
        ids = {ev.id for ev in result.events}
        for alert in summary.alerts:
            if alert.id in file_for_alert:
                continue
            if any(eid in ids for eid in alert.affected_events):
                file_for_alert[alert.id] = result.file_name

    results = [
        _build_result(alert, file_for_alert.get(alert.id, "<merged>"))
        for alert in summary.alerts
    ]

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "BlueTeam Log Analyzer",
                        "informationUri": "https://github.com/Hackerchen716/blueteam-log-analyzer",
                        "version": __version__,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
                "properties": {
                    "risk_score": summary.risk_score,
                    "risk_level": summary.risk_level.value,
                    "files_analyzed": summary.files_analyzed,
                    "total_events": summary.total_events,
                    "incident_count": len(summary.incidents),
                },
            }
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, ensure_ascii=False, indent=2)

    safe_print(f"  [✓] SARIF 报告已保存: {output_path}  ({len(results)} 个发现)")
