"""IOC 提取工具"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

from .models import DetectionAlert, LogEvent


IOC_TYPES = ("ips", "domains", "urls", "file_paths", "hashes", "users", "processes", "commands")

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
_HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.I)
_WIN_PATH_RE = re.compile(r"\b[a-zA-Z]:\\[^\s\"'<>|]+")
_UNIX_PATH_RE = re.compile(r"(?<!\w)/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+")
_FILE_EXTENSIONS_AS_TLD = {
    "php", "jsp", "jspx", "asp", "aspx", "ashx", "html", "htm", "js", "css",
    "png", "jpg", "jpeg", "gif", "svg", "ico", "txt", "log", "sql", "env",
    "conf", "config", "bak", "zip", "tar", "gz", "xml", "json", "yml", "yaml",
}
# 公共路径前缀，单纯访问这些不算"可操作 IOC"，过滤掉避免污染封禁清单
_BORING_PATH_PREFIXES = (
    "/", "/index", "/login", "/health", "/healthz", "/ping", "/favicon.ico",
    "/robots.txt", "/static", "/public", "/assets",
)
# 匹配这些前缀的私有 / 系统路径才视为有意义的 IOC
_INTERESTING_PATH_HINTS = (
    "/etc/", "/var/", "/proc/", "/root/", "/home/", "/tmp/", "/dev/shm",
    "/upload", "/admin", "/config", "/backup", "/wp-", "..", "passwd", "shadow",
    "shell", "/.git", "/.env", "/.svn", "/system32",
)
# 看起来像域名但其实是日志文本噪音的常见关键词
_DOMAIN_BLOCKLIST = {"example.com", "localhost", "localdomain"}


def extract_iocs(
    events: Iterable[LogEvent],
    alerts: Optional[Iterable[DetectionAlert]] = None,
) -> Dict[str, List[str]]:
    """从解析事件中提取 IOC。

    ``alerts`` 提供时，只从命中告警的事件中提取——这样得到的 IOC 是高置信度
    的（攻击源 IP、攻击 payload 中的路径/域名/Hash），可以直接拿去封禁、加
    入 IDS 规则。否则从全部事件中提取（兼容旧调用，但会包含运维流量等噪音）。
    """
    if alerts is not None:
        wanted_ids: Set[str] = set()
        for alert in alerts:
            wanted_ids.update(alert.affected_events)
        events = [ev for ev in events if ev.id in wanted_ids]

    found: Dict[str, Set[str]] = {key: set() for key in IOC_TYPES}

    for ev in events:
        if ev.ip:
            found["ips"].add(ev.ip)
        if ev.user:
            found["users"].add(ev.user)
        if ev.process:
            found["processes"].add(ev.process)

        for value in ev.details.values():
            _extract_from_text(str(value), found)
        _extract_from_text(ev.message, found)
        _extract_from_text(ev.raw_line, found)

        command = _extract_command(ev)
        if command:
            found["commands"].add(command)

    return {key: sorted(values) for key, values in found.items()}


def format_ioc_report(iocs: Dict[str, List[str]]) -> str:
    labels = {
        "ips": "IP",
        "domains": "Domains",
        "urls": "URLs",
        "file_paths": "File Paths",
        "hashes": "Hashes",
        "users": "Users",
        "processes": "Processes",
        "commands": "Commands",
    }
    lines = ["# BlueTeam Log Analyzer IOC Export", ""]
    for key in IOC_TYPES:
        values = iocs.get(key, [])
        lines.append(f"## {labels[key]} ({len(values)})")
        if values:
            lines.extend(values)
        else:
            lines.append("(none)")
        lines.append("")
    return "\n".join(lines)


def _extract_from_text(text: str, found: Dict[str, Set[str]]) -> None:
    if not text:
        return

    for url in _URL_RE.findall(text):
        clean = url.rstrip("),.;")
        found["urls"].add(clean)
        host = urlparse(clean).hostname
        if host and not _looks_like_ip(host) and host not in _DOMAIN_BLOCKLIST:
            found["domains"].add(host.lower())

    for domain in _DOMAIN_RE.findall(text):
        if _looks_like_domain(domain) and domain.lower() not in _DOMAIN_BLOCKLIST:
            found["domains"].add(domain.lower().rstrip("."))

    for ip in _IP_RE.findall(text):
        found["ips"].add(ip)

    for value in _HASH_RE.findall(text):
        found["hashes"].add(value.lower())

    for value in _WIN_PATH_RE.findall(text):
        found["file_paths"].add(value.rstrip("),.;"))
    for value in _UNIX_PATH_RE.findall(text):
        cleaned = value.rstrip("),.;")
        if _is_interesting_path(cleaned):
            found["file_paths"].add(cleaned)


def _is_interesting_path(path: str) -> bool:
    """过滤掉首页 / 静态资源等无操作价值的路径。

    优先放行包含可疑关键字的路径（``/etc/passwd``、``/.git/``、``..`` 等），
    再剔除显式 boring 前缀，剩余路径仍然保留，让蓝队在 IOC 列表里看到上下文
    但不被噪音淹没。
    """
    if len(path) <= 1:
        return False
    lower = path.lower()
    if any(hint in lower for hint in _INTERESTING_PATH_HINTS):
        return True
    if lower in _BORING_PATH_PREFIXES:
        return False
    return True


def _extract_command(ev: LogEvent) -> str:
    for key in ("CommandLine", "COMMAND", "cmd", "command", "Payload", "ScriptBlockText"):
        value = ev.details.get(key)
        if value:
            return str(value)[:500]
    if any(tag in ev.tags for tag in ("sudo-command", "sudo-shell", "command-injection", "rce")):
        return ev.message[:500]
    return ""


def _looks_like_ip(value: str) -> bool:
    return bool(_IP_RE.fullmatch(value))


def _looks_like_domain(value: str) -> bool:
    value = value.lower().rstrip(".")
    if _looks_like_ip(value):
        return False
    if "/" in value or "\\" in value:
        return False
    tld = value.rsplit(".", 1)[-1]
    return tld not in _FILE_EXTENSIONS_AS_TLD
