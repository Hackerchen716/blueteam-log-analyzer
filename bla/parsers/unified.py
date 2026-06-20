"""Unified multi-source JSONL parser.

许多 SIEM / 应急平台会把多源日志汇成一份"统一事件" JSONL：每行一个 JSON 记录，
带一个 ``source`` 标签（如 ``nginx_access`` / ``linux_auth`` / ``windows_event`` /
``hvv_p0`` / ``edr_alert``），并把原始日志放在 ``raw`` 字段或直接展开为结构化字段。

如果不识别这种格式，单一解析器会只认领其中一种来源、静默丢弃其余记录（且
``parse_errors=0``，使用者毫无察觉）。本解析器按 ``source`` 把每条记录分流到对应
子解析器后合并，确保多源统一文件被完整分析。
"""
from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from typing import Dict, List, Optional

from ..models import LogEvent, ParseResult
from ..utils.helpers import read_file
from .linux_auth import parse_linux_auth
from .p0_security import parse_p0_security_lines
from .shell_history import parse_shell_history
from .stats import compute_stats
from .web_access import parse_web_access
from .windows_json import parse_windows_json

# source 标签 -> 归一化的子解析器路由键
_SOURCE_ROUTES = {
    "nginx_access": "web", "apache_access": "web", "web_access": "web", "web": "web",
    "linux_auth": "linux", "auth": "linux", "secure": "linux", "syslog_auth": "linux",
    "windows_event": "windows", "windows": "windows", "sysmon": "windows", "winlog": "windows",
    "shell_history": "shell", "shell": "shell", "bash_history": "shell", "zsh_history": "shell",
    "hvv_p0": "p0", "edr_alert": "p0", "edr": "p0", "waf": "p0", "vpn": "p0",
    "firewall": "p0", "proxy": "p0", "dns": "p0", "dlp": "p0", "siem": "p0", "p0": "p0",
}

_UNIFIED_SOURCES = set(_SOURCE_ROUTES)


def looks_like_unified_jsonl(sample: str) -> bool:
    """统一多源 JSONL 的精确识别：前几条 JSON 记录带 ``source`` 标签且取值为已知
    多源标签，并出现至少两种不同来源（单一来源的文件交给对应专用解析器即可）。"""
    sources = set()
    checked = 0
    for line in sample.splitlines():
        line = line.strip()
        if not line:
            continue
        if not line.startswith("{"):
            return False
        try:
            record = json.loads(line)
        except Exception:
            continue
        src = str(record.get("source") or "").lower()
        if src in _UNIFIED_SOURCES:
            sources.add(_SOURCE_ROUTES[src])
        checked += 1
        if len(sources) >= 2:
            return True
        if checked >= 30:
            break
    return False


def parse_unified_jsonl(content: str, source_file: str) -> ParseResult:
    t0 = time.time()
    grouped: Dict[str, List[dict]] = defaultdict(list)
    parse_errors = 0
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except Exception:
            parse_errors += 1
            continue
        if not isinstance(record, dict):
            parse_errors += 1
            continue
        route = _SOURCE_ROUTES.get(str(record.get("source") or "").lower(), "p0")
        grouped[route].append(record)

    events: List[LogEvent] = []
    events += _route_text(grouped.get("web", []), source_file, parse_web_access)
    events += _route_text(grouped.get("linux", []), source_file, parse_linux_auth)
    events += _route_text(grouped.get("shell", []), source_file, parse_shell_history)
    events += _route_json(grouped.get("windows", []), source_file, parse_windows_json)
    events += _route_p0(grouped.get("p0", []), source_file)

    events.sort(key=lambda e: e.timestamp or "")
    stats = compute_stats(events)
    stats.parse_errors += parse_errors
    return ParseResult(
        file_name=source_file,
        log_type="Unified Multi-Source (JSONL)",
        events=events,
        stats=stats,
        parse_time_ms=(time.time() - t0) * 1000,
        file_size_bytes=len(content.encode()),
    )


def parse_unified_jsonl_file(path: str, source_file: Optional[str] = None) -> ParseResult:
    return parse_unified_jsonl(read_file(path), source_file or os.path.basename(path))


def _route_text(records: List[dict], source_file: str, parser) -> List[LogEvent]:
    """对 ``raw`` 是标准日志行的来源（web/linux），抽取 raw 行喂给行级解析器。"""
    lines = [str(record.get("raw") or "").rstrip("\n") for record in records]
    lines = [line for line in lines if line]
    if not lines:
        return []
    return parser("\n".join(lines), source_file).events


def _route_json(records: List[dict], source_file: str, parser) -> List[LogEvent]:
    """对接受内容字符串的结构化来源（windows-json），重新序列化为 JSONL 喂入。"""
    if not records:
        return []
    payload = "\n".join(json.dumps(record, ensure_ascii=False) for record in records)
    return parser(payload, source_file).events


def _route_p0(records: List[dict], source_file: str) -> List[LogEvent]:
    """P0/EDR 等结构化来源走 p0 的逐行解析（按行支持 JSONL + EDR technique 提取）。"""
    if not records:
        return []
    lines = [json.dumps(record, ensure_ascii=False) for record in records]
    return parse_p0_security_lines(lines, source_file).events
