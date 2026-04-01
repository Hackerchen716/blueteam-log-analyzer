"""
BlueTeam Log Analyzer - 数据模型定义
所有解析结果、事件、告警的数据结构
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
from enum import Enum


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

    @property
    def score(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    @property
    def color(self) -> str:
        return {
            "critical": "\033[91m",  # bright red
            "high":     "\033[38;5;208m",  # orange
            "medium":   "\033[93m",  # yellow
            "low":      "\033[92m",  # green
            "info":     "\033[94m",  # blue
        }[self.value]

    @property
    def label(self) -> str:
        return {
            "critical": "严重",
            "high":     "高危",
            "medium":   "中危",
            "low":      "低危",
            "info":     "信息",
        }[self.value]


@dataclass
class LogEvent:
    """单条日志事件"""
    id: str
    timestamp: str
    level: ThreatLevel
    category: str          # 分类：认证/进程/网络/Web攻击 等
    source: str            # 来源描述
    source_file: str       # 原始文件名
    message: str           # 人类可读描述
    raw_line: str          # 原始日志行

    event_id: Optional[str] = None      # Windows Event ID
    user: Optional[str] = None
    host: Optional[str] = None
    ip: Optional[str] = None
    process: Optional[str] = None
    port: Optional[int] = None

    details: Dict[str, str] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    mitre_attack: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "level": self.level.value,
            "category": self.category,
            "source": self.source,
            "source_file": self.source_file,
            "message": self.message,
            "event_id": self.event_id,
            "user": self.user,
            "host": self.host,
            "ip": self.ip,
            "process": self.process,
            "tags": self.tags,
            "mitre_attack": self.mitre_attack,
            "rule_name": self.rule_name,
            "details": self.details,
        }


@dataclass
class ParseStats:
    """解析统计信息"""
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    categories: Dict[str, int] = field(default_factory=dict)
    top_ips: List[Dict[str, Any]] = field(default_factory=list)
    top_users: List[Dict[str, Any]] = field(default_factory=list)
    top_event_ids: List[Dict[str, Any]] = field(default_factory=list)
    attack_types: Dict[str, int] = field(default_factory=dict)
    time_start: str = ""
    time_end: str = ""
    parse_errors: int = 0


@dataclass
class ParseResult:
    """单个文件的解析结果"""
    file_name: str
    log_type: str
    events: List[LogEvent]
    stats: ParseStats
    parse_time_ms: float = 0.0
    file_size_bytes: int = 0


@dataclass
class DetectionAlert:
    """威胁检测告警"""
    id: str
    rule_id: str
    rule_name: str
    description: str
    level: ThreatLevel
    category: str
    mitre_attack: str
    mitre_phase: str
    affected_events: List[str]   # LogEvent.id 列表
    evidence: List[str]
    recommendation: str
    timestamp: str
    confidence: str              # high / medium / low

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "level": self.level.value,
            "category": self.category,
            "mitre_attack": self.mitre_attack,
            "mitre_phase": self.mitre_phase,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp,
            "confidence": self.confidence,
            "affected_event_count": len(self.affected_events),
        }


@dataclass
class TimelineEntry:
    """时间线条目"""
    timestamp: str
    level: ThreatLevel
    category: str
    message: str
    event_id: str
    source_file: str
    mitre_attack: Optional[str] = None


@dataclass
class AttackChainEntry:
    """ATT&CK 攻击链阶段"""
    phase: str
    event_count: int
    level: ThreatLevel
    techniques: List[str]


@dataclass
class AnalysisSummary:
    """完整分析汇总"""
    risk_score: int
    risk_level: ThreatLevel
    alerts: List[DetectionAlert]
    timeline: List[TimelineEntry]
    attack_chain: List[AttackChainEntry]
    recommendations: List[str]
    total_events: int
    files_analyzed: int
