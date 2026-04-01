"""
BlueTeam Log Analyzer - 解析器入口
自动检测日志类型并调度到对应解析器
"""

from __future__ import annotations
import os
import re
import time
from typing import List

from ..models import ParseResult, LogEvent, ThreatLevel
from ..utils.helpers import read_file, gen_id
from .windows_evtx import parse_windows_xml, parse_windows_evtx
from .linux_auth import parse_linux_auth
from .web_access import parse_web_access
from .stats import compute_stats


def auto_parse(file_path: str) -> ParseResult:
    """
    自动检测日志类型并解析
    支持:
      - Windows XML (.xml)
      - Windows EVTX (.evtx)
      - Linux Auth (/var/log/auth.log, /var/log/secure)
      - Web Access (Apache/Nginx Combined)
      - 通用文本日志 (fallback)
    """
    fname = os.path.basename(file_path)
    fname_lower = fname.lower()

    # EVTX 二进制
    if fname_lower.endswith(".evtx"):
        return parse_windows_evtx(file_path)

    # 读取文本内容
    content = read_file(file_path)
    sample  = content[:2000].lower()

    # Windows XML
    if "<event" in sample and ("xmlns" in sample or "<eventid>" in sample):
        return parse_windows_xml(content, fname)

    # Linux Auth
    if any(kw in fname_lower for kw in ("auth", "secure")) or \
       any(kw in sample for kw in ("sshd", "sudo:", "pam_unix", "useradd")):
        return parse_linux_auth(content, fname)

    # Web Access
    if _looks_like_web_log(content[:500]):
        return parse_web_access(content, fname)

    # Fallback: 通用日志
    return _parse_generic(content, fname)


def _looks_like_web_log(sample: str) -> bool:
    return bool(re.search(
        r'\d+\.\d+\.\d+\.\d+.*\[.*\].*"(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+/',
        sample, re.I
    ))


def _parse_generic(content: str, source_file: str) -> ParseResult:
    """通用日志解析（fallback）"""
    t0 = time.time()
    lines = content.splitlines()
    events: List[LogEvent] = []

    for line in lines[:10000]:
        if not line.strip() or len(line) < 10:
            continue

        level = ThreatLevel.INFO
        lower = line.lower()
        if any(kw in lower for kw in ("critical", "fatal", "emergency")):
            level = ThreatLevel.CRITICAL
        elif any(kw in lower for kw in ("error", "err", "alert")):
            level = ThreatLevel.HIGH
        elif any(kw in lower for kw in ("warning", "warn")):
            level = ThreatLevel.MEDIUM
        elif any(kw in lower for kw in ("notice", "info")):
            level = ThreatLevel.LOW

        ts_m  = re.search(r'(\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2})', line)
        ip_m  = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)

        events.append(LogEvent(
            id          = gen_id("gen"),
            timestamp   = ts_m.group(1) if ts_m else "",
            level       = level,
            category    = "通用",
            source      = source_file,
            source_file = source_file,
            message     = line[:200],
            raw_line    = line,
            ip          = ip_m.group(1) if ip_m else None,
            details     = {},
            tags        = [],
        ))

    stats = compute_stats(events)
    return ParseResult(
        file_name     = source_file,
        log_type      = "通用日志",
        events        = events,
        stats         = stats,
        parse_time_ms = (time.time() - t0) * 1000,
        file_size_bytes = len(content.encode()),
    )
