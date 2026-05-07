"""
BlueTeam Log Analyzer - 解析器入口
自动检测日志类型并调度到对应解析器
"""

from __future__ import annotations
import os
import re
import sys
import time
from typing import List

from .. import config
from ..models import ParseResult, LogEvent, ThreatLevel
from ..utils.helpers import gen_id, read_file, read_file_sample, safe_write
from .windows_evtx import parse_windows_xml, parse_windows_evtx
from .linux_auth import parse_linux_auth, parse_linux_auth_file
from .web_access import parse_web_access, parse_web_access_file
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

    # 先读取文件开头小样本用于类型识别。Linux/Web 日志会走逐行解析，
    # 避免为了分析大文件把完整内容一次性加载到内存。
    sample_text = read_file_sample(file_path)
    sample  = sample_text[:2000].lower()

    # Windows XML
    if "<event" in sample and ("xmlns" in sample or "<eventid>" in sample):
        content = read_file(file_path)
        return parse_windows_xml(content, fname)

    # Linux Auth
    if any(kw in fname_lower for kw in ("auth", "secure")) or \
       any(kw in sample for kw in ("sshd", "sudo:", "pam_unix", "useradd")):
        return parse_linux_auth_file(file_path, fname)

    # Web Access
    if _looks_like_web_log(sample_text[:500]):
        return parse_web_access_file(file_path, fname)

    # Fallback: 通用日志
    content = read_file(file_path)
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

    line_limit = config.THRESHOLDS.generic_parse_line_limit
    if len(lines) > line_limit:
        safe_write(
            f"⚠️  通用解析器只处理前 {line_limit} 行，"
            f"{source_file} 共 {len(lines)} 行，剩余 {len(lines) - line_limit} 行被截断。\n"
            "    建议显式指定日志类型，或使用更精确的解析器。\n",
            sys.stderr,
        )

    for line in lines[:line_limit]:
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
