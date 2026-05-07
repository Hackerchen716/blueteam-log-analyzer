"""IOC 提取工具"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Set
from urllib.parse import urlparse

from .models import LogEvent


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


def extract_iocs(events: Iterable[LogEvent]) -> Dict[str, List[str]]:
    """Extract practical IOCs from parsed events."""
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
        if host and not _looks_like_ip(host):
            found["domains"].add(host.lower())

    for domain in _DOMAIN_RE.findall(text):
        if _looks_like_domain(domain):
            found["domains"].add(domain.lower().rstrip("."))

    for ip in _IP_RE.findall(text):
        found["ips"].add(ip)

    for value in _HASH_RE.findall(text):
        found["hashes"].add(value.lower())

    for value in _WIN_PATH_RE.findall(text):
        found["file_paths"].add(value.rstrip("),.;"))
    for value in _UNIX_PATH_RE.findall(text):
        if len(value) > 1:
            found["file_paths"].add(value.rstrip("),.;"))


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
