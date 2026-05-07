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
from typing import Any, Dict, List

from ..models import AnalysisSummary, DetectionAlert, ParseResult, ThreatLevel


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
        "id": alert.rule_id,
        "name": alert.rule_name,
        "shortDescription": {"text": alert.rule_name},
        "fullDescription": {"text": alert.description},
        "helpUri": "https://attack.mitre.org/techniques/" + alert.mitre_attack.replace(".", "/")
        if alert.mitre_attack else "",
        "properties": {
            "category": alert.category,
            "mitre_phase": alert.mitre_phase,
            "mitre_attack": alert.mitre_attack,
            "tags": ["security", "blueteam", alert.category],
        },
    }


def _build_result(alert: DetectionAlert, source_file: str) -> Dict[str, Any]:
    return {
        "ruleId": alert.rule_id,
        "level": _LEVEL_MAP.get(alert.level, "warning"),
        "message": {
            "text": f"{alert.description}\n建议: {alert.recommendation}",
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": source_file},
                }
            }
        ],
        "properties": {
            "confidence": alert.confidence,
            "evidence": alert.evidence,
            "affected_event_count": len(alert.affected_events),
            "timestamp": alert.timestamp,
        },
    }


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
            if alert.rule_id in file_for_alert.get(alert.id, ""):
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
                        "version": "1.0.0",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
                "properties": {
                    "risk_score": summary.risk_score,
                    "risk_level": summary.risk_level.value,
                    "files_analyzed": summary.files_analyzed,
                    "total_events": summary.total_events,
                },
            }
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, ensure_ascii=False, indent=2)

    print(f"  [✓] SARIF 报告已保存: {output_path}  ({len(results)} 个发现)")
