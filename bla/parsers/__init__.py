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
from typing import List, Optional

from .. import config
from ..models import LogEvent, ParseResult, ThreatLevel
from ..utils.helpers import file_size, gen_id, read_file, read_file_sample, safe_write
from .linux_auth import parse_linux_auth, parse_linux_auth_file
from .p0_security import (
    looks_like_p0_security_log,
    parse_p0_security_file,
    parse_p0_security_json,
    parse_p0_security_lines,
)
from .registry import ParserContext, ParserRegistry, ParserSpec, normalize_aliases
from .stats import compute_stats
from .web_access import parse_web_access, parse_web_access_file
from .windows_evtx import parse_windows_evtx, parse_windows_xml, parse_windows_xml_file

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
            parse_file=lambda ctx: _parse_generic(read_file(ctx.file_path or ""), ctx.source_name),
            parse_content=lambda ctx: _parse_generic(ctx.content or "", ctx.source_name),
            description="Generic text fallback",
        ),
    ):
        _DEFAULT_REGISTRY.register(spec)
    _DEFAULTS_REGISTERED = True


def _can_parse_windows_xml(context: ParserContext) -> bool:
    sample = context.sample_text[:2000].lower()
    return "<event" in sample and ("xmlns" in sample or "<eventid>" in sample)


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

        ts_m = re.search(r'(\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2})', line)
        ip_m = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)

        events.append(LogEvent(
            id=gen_id("gen"),
            timestamp=ts_m.group(1) if ts_m else "",
            level=level,
            category="通用",
            source=source_file,
            source_file=source_file,
            message=line[:200],
            raw_line=line,
            ip=ip_m.group(1) if ip_m else None,
            details={},
            tags=[],
        ))

    stats = compute_stats(events)
    return ParseResult(
        file_name=source_file,
        log_type="通用日志",
        events=events,
        stats=stats,
        parse_time_ms=(time.time() - t0) * 1000,
        file_size_bytes=len(content.encode()),
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
