"""Scanner/User-Agent enrichment helpers."""
from __future__ import annotations

import re
from collections import Counter
from typing import Iterable, List, Tuple

from ..models import LogEvent


SCANNER_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("dirbuster", re.compile(r"\bdirbuster\b", re.I)),
    ("gobuster", re.compile(r"\bgobuster\b", re.I)),
    ("dirsearch", re.compile(r"\bdirsearch\b", re.I)),
    ("ffuf", re.compile(r"\bffuf\b", re.I)),
    ("feroxbuster", re.compile(r"\bferoxbuster\b", re.I)),
    ("nikto", re.compile(r"\bnikto\b", re.I)),
    ("sqlmap", re.compile(r"\bsqlmap\b", re.I)),
    ("nmap", re.compile(r"\bnmap\b|nmap scripting engine", re.I)),
    ("masscan", re.compile(r"\bmasscan\b", re.I)),
    ("curl", re.compile(r"\bcurl/|\bcurl\b", re.I)),
    ("wget", re.compile(r"\bwget/|\bwget\b", re.I)),
    ("python-requests", re.compile(r"python-requests", re.I)),
]


def detect_scanner_tool(user_agent: str) -> str:
    """Return a normalized scanner/tool name from a User-Agent string."""
    ua = user_agent or ""
    for name, pattern in SCANNER_PATTERNS:
        if pattern.search(ua):
            return name
    return ""


def summarize_scanner_events(events: Iterable[LogEvent], max_paths: int = 5) -> List[str]:
    """Build human-readable scanner evidence lines from event details."""
    evts = list(events)
    tools = [e.details.get("scanner_tool", "") for e in evts if e.details.get("scanner_tool")]
    user_agents = [e.details.get("user_agent", "") for e in evts if e.details.get("user_agent")]
    methods = [e.details.get("method", "") for e in evts if e.details.get("method")]
    paths = [
        e.details.get("decoded_path") or e.details.get("path") or e.details.get("sample") or ""
        for e in evts
    ]

    evidence: List[str] = []
    if tools:
        evidence.append(f"扫描工具: {Counter(tools).most_common(1)[0][0]}")
    if user_agents:
        evidence.append(f"User-Agent: {Counter(user_agents).most_common(1)[0][0]}")
    if methods:
        evidence.append(f"请求方法: {Counter(methods).most_common(1)[0][0]}")

    clean_paths = []
    for path in paths:
        if not path or path in clean_paths:
            continue
        clean_paths.append(path)
        if len(clean_paths) >= max_paths:
            break
    if clean_paths:
        evidence.append("典型路径: " + ", ".join(clean_paths))
    return evidence
