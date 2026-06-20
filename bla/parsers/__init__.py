"""
BlueTeam Log Analyzer parser entrypoints.

The public API keeps ``auto_parse(path)`` compatible while routing through a
small registry. New log sources should register a parser instead of extending a
central if/elif chain.
"""

from __future__ import annotations

import os
import re
import sys
import time
from typing import Iterable, List, Optional

from .. import config
from ..models import LogEvent, ParseResult, ThreatLevel
from ..utils.helpers import (
    file_size,
    gen_id,
    iter_file_lines,
    read_file,  # noqa: F401  流式解析回归测试通过 patch ``bla.parsers.read_file`` 断言不整文件读入，需保留此命名空间锚点
    read_file_sample,
    safe_write,
    sanitize_report_text,
)
from .linux_auth import parse_linux_auth, parse_linux_auth_file
from .p0_security import (
    looks_like_p0_security_log,
    parse_p0_security_file,
    parse_p0_security_json,
    parse_p0_security_lines,
)
from .edr_xlsx import looks_like_edr_xlsx, parse_edr_xlsx_content, parse_edr_xlsx_file
from .registry import ParserContext, ParserRegistry, ParserSpec, normalize_aliases
from .shell_history import parse_shell_history, parse_shell_history_file
from .stats import compute_stats
from .unified import looks_like_unified_jsonl, parse_unified_jsonl, parse_unified_jsonl_file
from .web_access import parse_web_access, parse_web_access_file
from .windows_evtx import parse_windows_evtx, parse_windows_xml, parse_windows_xml_file
from .windows_json import looks_like_windows_event_json, parse_windows_json, parse_windows_json_file

_DEFAULT_REGISTRY = ParserRegistry()
_DEFAULTS_REGISTERED = False


def auto_parse(file_path: str, parser_name: Optional[str] = None) -> ParseResult:
    """Automatically detect and parse a log file.

    ``parser_name`` can force a parser (for example ``"web-access"`` or
    ``"p0-security"``), which is useful for ambiguous filenames and future
    collector-fed inputs.
    """
    context = _file_context(file_path)
    return get_parser_registry().parse_file(context, parser_name)


def parse_content(content: str, source_name: str, parser_name: Optional[str] = None) -> ParseResult:
    """Parse an in-memory log chunk.

    This is the bridge that Remote Collector / Host Triage can use later
    without having to write temporary files just to reuse the analysis pipeline.
    """
    context = ParserContext(
        source_name=source_name,
        sample_text=content[:8192],
        content=content,
        file_size_bytes=len(content.encode()),
    )
    return get_parser_registry().parse_content(context, parser_name)


def register_parser(spec: ParserSpec) -> None:
    get_parser_registry().register(spec)


def get_parser_registry() -> ParserRegistry:
    _ensure_default_parsers()
    return _DEFAULT_REGISTRY


def list_parser_names() -> List[str]:
    return get_parser_registry().names()


def _file_context(file_path: str) -> ParserContext:
    return ParserContext(
        source_name=os.path.basename(file_path),
        file_path=file_path,
        sample_text=read_file_sample(file_path),
        file_size_bytes=file_size(file_path),
    )


def _ensure_default_parsers() -> None:
    global _DEFAULTS_REGISTERED
    if _DEFAULTS_REGISTERED:
        return
    for spec in (
        ParserSpec(
            name="windows-evtx",
            aliases=normalize_aliases(("evtx", "windows-binary")),
            can_parse=lambda ctx: bool(ctx.file_path and ctx.name_lower.endswith(".evtx")),
            parse_file=lambda ctx: parse_windows_evtx(ctx.file_path or ""),
            description="Windows binary EVTX logs",
        ),
        ParserSpec(
            name="windows-xml",
            aliases=normalize_aliases(("xml", "windows", "winxml")),
            can_parse=_can_parse_windows_xml,
            parse_file=lambda ctx: parse_windows_xml_file(ctx.file_path or "", ctx.source_name),
            parse_content=lambda ctx: parse_windows_xml(ctx.content or "", ctx.source_name),
            description="Windows Event XML exports",
        ),
        # unified 必须排在 windows-json / p0 之前：统一多源 JSONL 里混有 windows/p0
        # 记录，否则会被单一解析器认领、其余来源被静默丢弃。其识别要求带已知 source
        # 标签且出现 >=2 种不同来源，单源文件不会被误抢。
        ParserSpec(
            name="unified-jsonl",
            aliases=normalize_aliases(("unified", "multi-source", "siem-jsonl")),
            can_parse=_can_parse_unified,
            parse_file=lambda ctx: parse_unified_jsonl_file(ctx.file_path or "", ctx.source_name),
            parse_content=lambda ctx: parse_unified_jsonl(ctx.content or "", ctx.source_name),
            description="Unified multi-source SIEM JSONL exports",
        ),
        ParserSpec(
            name="windows-json",
            aliases=normalize_aliases(("winjson", "windows-eventlog-json", "otrf-windows")),
            can_parse=_can_parse_windows_json,
            parse_file=lambda ctx: parse_windows_json_file(ctx.file_path or "", ctx.source_name),
            parse_content=lambda ctx: parse_windows_json(ctx.content or "", ctx.source_name),
            description="Windows EventLog JSON/JSONL exports",
        ),
        ParserSpec(
            name="edr-xlsx",
            aliases=normalize_aliases(("edr-excel", "xlsx", "p0-xlsx", "endpoint-xlsx")),
            can_parse=_can_parse_edr_xlsx,
            parse_file=lambda ctx: parse_edr_xlsx_file(ctx.file_path or "", ctx.source_name),
            parse_content=lambda ctx: parse_edr_xlsx_content(ctx.content or "", ctx.source_name),
            description="EDR/XDR Excel process telemetry exports",
        ),
        ParserSpec(
            name="linux-auth",
            aliases=normalize_aliases(("auth", "secure", "linux")),
            can_parse=_can_parse_linux_auth,
            parse_file=lambda ctx: parse_linux_auth_file(ctx.file_path or "", ctx.source_name),
            parse_content=lambda ctx: parse_linux_auth(ctx.content or "", ctx.source_name),
            description="Linux auth.log / secure logs",
        ),
        ParserSpec(
            name="web-access",
            aliases=normalize_aliases(("web", "access", "nginx", "apache")),
            can_parse=_can_parse_web_access,
            parse_file=lambda ctx: parse_web_access_file(ctx.file_path or "", ctx.source_name),
            parse_content=lambda ctx: parse_web_access(ctx.content or "", ctx.source_name),
            description="Apache/Nginx access logs",
        ),
        # shell-history 必须排在 p0-security 之前：真实 shell history 导出常带
        # ``# host=... user=... source=....bash_history`` 这类元数据头，其 key=value
        # 会被 p0 的结构化启发式抢先匹配，导致整份文件被当 P0 解析出 0 事件。
        # shell-history 的文件名信号（含 *shell_history* / *.bash_history）是高置信度
        # 精确匹配，优先它不会误抢真正的 P0 结构化日志。
        ParserSpec(
            name="shell-history",
            aliases=normalize_aliases(("bash-history", "bash", "zsh", "history", "shell")),
            can_parse=_can_parse_shell_history,
            parse_file=lambda ctx: parse_shell_history_file(ctx.file_path or "", ctx.source_name),
            parse_content=lambda ctx: parse_shell_history(ctx.content or "", ctx.source_name),
            description="Bash/Zsh shell history command traces",
        ),
        ParserSpec(
            name="p0-security",
            aliases=normalize_aliases(("p0", "hvv", "security", "structured")),
            can_parse=_can_parse_p0_security,
            parse_file=lambda ctx: parse_p0_security_file(ctx.file_path or "", ctx.source_name),
            parse_content=_parse_p0_content,
            description="HVV/重保 structured security logs",
        ),
        ParserSpec(
            name="generic",
            aliases=normalize_aliases(("text", "fallback")),
            can_parse=lambda _ctx: True,
            parse_file=lambda ctx: _parse_generic_file(ctx.file_path or "", ctx.source_name),
            parse_content=lambda ctx: _parse_generic(ctx.content or "", ctx.source_name),
            description="Generic text fallback",
        ),
    ):
        _DEFAULT_REGISTRY.register(spec)
    _DEFAULTS_REGISTERED = True


def _can_parse_windows_xml(context: ParserContext) -> bool:
    sample = context.sample_text[:2000].lower()
    return "<event" in sample and ("xmlns" in sample or "<eventid>" in sample)


def _can_parse_unified(context: ParserContext) -> bool:
    return looks_like_unified_jsonl(context.sample_text)


def _can_parse_windows_json(context: ParserContext) -> bool:
    return looks_like_windows_event_json(context.file_path or context.source_name, context.sample_text)


def _can_parse_edr_xlsx(context: ParserContext) -> bool:
    return bool(context.file_path and looks_like_edr_xlsx(context.file_path, context.sample_text))


def _can_parse_linux_auth(context: ParserContext) -> bool:
    sample = context.sample_text[:2000].lower()
    return (
        any(kw in context.name_lower for kw in ("auth", "secure")) or
        any(kw in sample for kw in ("sshd", "sudo:", "pam_unix", "useradd"))
    )


def _can_parse_web_access(context: ParserContext) -> bool:
    return _looks_like_web_log(context.sample_text[:500])


def _can_parse_p0_security(context: ParserContext) -> bool:
    return looks_like_p0_security_log(context.file_path or context.source_name, context.sample_text)


def _can_parse_shell_history(context: ParserContext) -> bool:
    name = context.name_lower
    if any(item in name for item in ("bash_history", ".bash_history", "zsh_history", ".zsh_history", "shell_history")):
        return True
    if name.endswith("history") or name.endswith(".history"):
        return _looks_like_shell_history(context.sample_text)
    return False


def _parse_p0_content(context: ParserContext) -> ParseResult:
    content = context.content or ""
    stripped = content.lstrip()
    if stripped.startswith("["):
        return parse_p0_security_json(content, context.source_name, context.file_size_bytes)
    if stripped.startswith("{"):
        parsed = parse_p0_security_json(content, context.source_name, context.file_size_bytes)
        if parsed.stats.parse_errors == 0:
            return parsed
        fallback = parse_p0_security_lines(
            content.splitlines(),
            context.source_name,
            file_size_bytes=context.file_size_bytes,
        )
        return fallback if fallback.events else parsed
    return parse_p0_security_lines(
        content.splitlines(),
        context.source_name,
        file_size_bytes=context.file_size_bytes,
    )


def _looks_like_web_log(sample: str) -> bool:
    return bool(re.search(
        r'^\s*\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+/',
        sample, re.I | re.M
    ))


def _looks_like_shell_history(sample: str) -> bool:
    hits = 0
    for raw in sample.splitlines()[:40]:
        line = raw.strip()
        if not line:
            continue
        if re.match(r"^:\s*\d{9,}:\d+;", line):
            hits += 1
        elif re.search(r"\b(?:sudo\s+-l|whoami|id|wget\s+https?://|curl\s+https?://|cat\s+/etc/(?:passwd|shadow)|find\s+/|history\s+-c)\b", line, re.I):
            hits += 1
        if hits >= 2:
            return True
    return False


def _parse_generic(content: str, source_file: str) -> ParseResult:
    """通用日志解析（fallback）"""
    return _parse_generic_lines(
        content.splitlines(),
        source_file,
        file_size_bytes=len(content.encode()),
    )


def _parse_generic_file(path: str, source_file: str) -> ParseResult:
    """Stream fallback parsing from disk without loading the whole file."""
    return _parse_generic_lines(
        iter_file_lines(path),
        source_file,
        file_size_bytes=file_size(path),
    )


def _parse_generic_lines(
    lines: Iterable[str],
    source_file: str,
    file_size_bytes: int = 0,
) -> ParseResult:
    """通用日志解析（fallback）"""
    t0 = time.time()
    events: List[LogEvent] = []
    line_limit = config.THRESHOLDS.generic_parse_line_limit
    total_lines = 0
    current_timestamp = ""
    web_forensics = {"requests": [], "homepage_requests": []}
    for total_lines, line in enumerate(lines, start=1):
        if total_lines > line_limit:
            continue
        current_timestamp = observe_error_line(
            web_forensics,
            line,
            source_file=source_file,
            current_timestamp=current_timestamp,
        )
        event = _generic_line_to_event(line, source_file, fallback_timestamp=current_timestamp)
        if event:
            events.append(event)

    if total_lines > line_limit:
        safe_write(
            f"⚠️  通用解析器只处理前 {line_limit} 行，"
            f"{sanitize_report_text(source_file)} 共 {total_lines} 行，剩余 {total_lines - line_limit} 行被截断。\n"
            "    建议显式指定日志类型，或使用更精确的解析器。\n",
            sys.stderr,
        )

    stats = compute_stats(events)
    stats.web_forensics = web_forensics
    return ParseResult(
        file_name=source_file,
        log_type="通用日志",
        events=events,
        stats=stats,
        parse_time_ms=(time.time() - t0) * 1000,
        file_size_bytes=file_size_bytes,
    )


def observe_error_line(
    web_forensics: dict,
    line: str,
    source_file: str,
    current_timestamp: str = "",
) -> str:
    """Observe web-style request evidence inside generic error logs.

    Nginx/FastCGI/PHP error logs often split one application error over several
    physical lines: the timestamp is on the first line, while the later line
    contains ``client: ... request: "GET / HTTP/1.1"``.  Keep the timestamp
    context so the investigation layer can report the real first homepage hit
    instead of only the first access.log event.
    """
    ts_m = re.search(r'(\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2})', line)
    if ts_m:
        current_timestamp = ts_m.group(1)

    request_m = re.search(
        r'client:\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?request:\s*"(?P<method>[A-Z]+)\s+(?P<path>\S+)',
        line,
        re.I,
    )
    if request_m:
        item = {
            "timestamp": current_timestamp,
            "source_file": source_file,
            "ip": request_m.group("ip"),
            "method": request_m.group("method").upper(),
            "path": request_m.group("path"),
            "raw_line": line[:500],
        }
        web_forensics.setdefault("requests", []).append(item)
        if item["method"] in {"GET", "HEAD"} and item["path"].split("?", 1)[0] == "/":
            web_forensics.setdefault("homepage_requests", []).append(item)
    return current_timestamp


def _generic_line_to_event(
    line: str,
    source_file: str,
    fallback_timestamp: str = "",
) -> Optional[LogEvent]:
    if not line.strip() or len(line) < 10:
        return None

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

    ts_m = re.search(r'(\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2})', line)
    ip_m = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
    request_m = re.search(r'request:\s*"(?P<method>[A-Z]+)\s+(?P<path>\S+)', line, re.I)
    details = {}
    if request_m:
        details["method"] = request_m.group("method").upper()
        details["path"] = request_m.group("path")
        details["decoded_path"] = request_m.group("path")
        details["source_type"] = "generic"

    return LogEvent(
        id=gen_id("gen"),
        timestamp=ts_m.group(1) if ts_m else (fallback_timestamp if request_m else ""),
        level=level,
        category="通用",
        source=source_file,
        source_file=source_file,
        message=line[:200],
        raw_line=line,
        ip=ip_m.group(1) if ip_m else None,
        details=details,
        tags=[],
    )


__all__ = [
    "ParserContext",
    "ParserRegistry",
    "ParserSpec",
    "auto_parse",
    "get_parser_registry",
    "list_parser_names",
    "parse_content",
    "register_parser",
    "_parse_generic",
]
