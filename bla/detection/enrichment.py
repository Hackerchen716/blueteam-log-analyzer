"""Event normalization and enrichment before detection/correlation."""
from __future__ import annotations

import re
from collections import Counter
from functools import lru_cache
from typing import Dict, Iterable, List
from urllib.parse import urlparse

from ..models import LogEvent
from ..utils.helpers import is_private_ip
from .scanners import detect_scanner_tool


SENSITIVE_PORTS = {
    22, 23, 3389, 445, 135, 139, 1433, 1521, 3306, 5432, 6379,
    9200, 9300, 11211, 27017,
}

P0_NORMALIZED_FIELDS = (
    "source_type", "src_ip", "dst_ip", "asset", "account", "action",
    "status", "url", "command", "process", "bytes_out", "session_id",
    "trace_id",
)

_WINDOWS_ACCOUNT_EVENTS = {
    "4720", "4722", "4723", "4724", "4725", "4726", "4738",
}
_WINDOWS_GROUP_EVENTS = {"4728", "4729", "4732", "4756"}
_SOURCE_TYPE_CHECKS = [
    (label, re.compile(pattern, re.I))
    for label, pattern in (
        ("waf", r"\bwaf\b|web security|modsecurity"),
        ("vpn", r"\bvpn\b|ztna|ssl vpn"),
        ("bastion", r"bastion|堡垒|jump"),
        ("dns", r"\bdns\b"),
        ("proxy", r"proxy|swg|上网行为"),
        ("firewall", r"firewall|\bfw\b|\bnat\b"),
        ("edr", r"\bedr\b|\bxdr\b|sysmon|endpoint"),
        ("application", r"application|应用|tomcat|spring"),
        ("web", r"\bweb\b|access"),
        ("linux-auth", r"linux auth|auth\.log|secure|ssh|sudo"),
        ("windows-event", r"windows|security|event log"),
    )
]
_DOMAIN_CALLBACK_RE = re.compile(r"dnslog|ceye|burpcollaborator|interactsh|jndi|ldap|rmi")
_DOMAIN_SUSPICIOUS_RE = re.compile(r"c2|beacon|malware|evil|shell")
_ASSET_ROLE_PATTERNS = (
    ("domain-controller", re.compile(r"dc|domain.?controller|kerberos|域控")),
    ("database", re.compile(r"mysql|postgres|oracle|sqlserver|redis|mongo|database|数据库")),
    ("web-server", re.compile(r"nginx|apache|tomcat|iis|web|http")),
)


def enrich_events(events: Iterable[LogEvent]) -> List[LogEvent]:
    """Add stable normalized/enriched fields to each event in-place."""
    enriched = list(events)
    normalized_by_id = {event.id: _normalize_event(event) for event in enriched}
    ip_counts = Counter(item.get("src_ip") for item in normalized_by_id.values() if item.get("src_ip"))
    account_counts = Counter(item.get("account") for item in normalized_by_id.values() if item.get("account"))
    asset_counts = Counter(item.get("asset") for item in normalized_by_id.values() if item.get("asset"))

    for event in enriched:
        normalized = normalized_by_id[event.id]
        user_agent = str(event.details.get("user_agent") or "")
        scanner_tool = detect_scanner_tool(user_agent)
        event.details.update(normalized)
        event.details.update({
            "src_ip_scope": _ip_scope(normalized.get("src_ip", "")),
            "dst_ip_scope": _ip_scope(normalized.get("dst_ip", "")),
            "asset_role": _asset_role(event, normalized),
            "domain_type": _domain_type(normalized.get("url", "") or normalized.get("asset", "")),
            "auth_result": _auth_result(event),
            "event_family": _event_family(event, normalized),
            "same_src_ip_event_count": str(ip_counts.get(normalized.get("src_ip"), 0)),
            "same_account_event_count": str(account_counts.get(normalized.get("account"), 0)),
            "same_asset_event_count": str(asset_counts.get(normalized.get("asset"), 0)),
            "sensitive_port": "true" if event.port in SENSITIVE_PORTS else "false",
        })
        if scanner_tool:
            event.details["scanner_tool"] = scanner_tool
            if "scanner" not in event.tags:
                event.tags.append("scanner")
            if "reconnaissance" not in event.tags:
                event.tags.append("reconnaissance")
            if "扫描工具:" not in event.message:
                method = event.details.get("method", "")
                path = event.details.get("decoded_path") or event.details.get("path") or event.details.get("sample") or ""
                parts = [f"扫描工具: {scanner_tool}"]
                if user_agent:
                    parts.append(f"User-Agent: {user_agent}")
                if method:
                    parts.append(f"请求方法: {method}")
                if path:
                    parts.append(f"典型路径: {path}")
                event.message = f"{event.message} ({'; '.join(parts)})"
    return enriched


def _normalize_event(event: LogEvent) -> Dict[str, str]:
    details = event.details
    normalized_details = _normalized_details(details)
    source_type = _source_type(event)
    src_ip = event.ip or _first_normalized(
        normalized_details,
        "src_ip", "srcip", "sourceip", "clientip", "remoteaddr", "xff", "source_ip",
    )
    dst_ip = _first_normalized(
        normalized_details,
        "dst_ip", "dstip", "destip", "destinationip", "serverip", "targetip",
    )
    asset = event.host or dst_ip or _first_normalized(
        normalized_details,
        "asset", "target", "targethost", "host", "hostname", "server", "endpoint",
    )
    account = _normalized_account(event, normalized_details, source_type)
    action = _first_normalized(normalized_details, "action", "result", "status", "outcome", "policyaction")
    status = _first_normalized(normalized_details, "status", "statuscode", "responsecode", "result", "outcome")
    url = _first_normalized(normalized_details, "url", "uri", "path", "decoded_path", "request", "fullurl")
    command = _first_normalized(normalized_details, "command", "cmd", "commandline", "COMMAND", "ScriptBlockText", "Payload")
    process = event.process or _first_normalized(normalized_details, "process", "processname", "image", "filename", "NewProcessName")
    bytes_out = _first_normalized(normalized_details, "bytes_out", "bytesout", "sentbytes", "uploadbytes", "outbytes", "bytes")
    session_id = _first_normalized(normalized_details, "session_id", "sessionid", "sid", "session")
    trace_id = _first_normalized(normalized_details, "trace_id", "traceid", "requestid", "request_id")
    return {
        "source_type": source_type,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "asset": asset,
        "account": account,
        "action": action,
        "status": status,
        "url": url,
        "command": command,
        "process": process,
        "bytes_out": bytes_out,
        "session_id": session_id,
        "trace_id": trace_id,
    }


def _normalized_account(event: LogEvent, normalized_details: Dict[str, object], source_type: str) -> str:
    if source_type == "windows-event":
        if event.event_id in _WINDOWS_ACCOUNT_EVENTS:
            return _first_normalized(normalized_details, "target_account", "target_user") or event.user or ""
        if event.event_id in _WINDOWS_GROUP_EVENTS:
            return _first_normalized(normalized_details, "member_account", "member_name", "member_sid", "target_sid") or event.user or ""
        if event.event_id in {"4624", "4625", "4776"}:
            account = _first_normalized(normalized_details, "account_name", "TargetUserName", "SubjectUserName")
            domain = _first_normalized(normalized_details, "account_domain", "TargetDomainName", "SubjectDomainName")
            return f"{domain}\\{account}" if domain and account else account
    return event.user or _first_normalized(normalized_details, "account", "user", "username", "operator", "actor", "principal")


def _source_type(event: LogEvent) -> str:
    kind = str(event.details.get("p0_kind") or "").lower()
    if kind:
        return kind
    hay = " ".join([event.source, event.category, event.source_file]).lower()
    for label, pattern in _SOURCE_TYPE_CHECKS:
        if pattern.search(hay):
            return label
    return "generic"


def _first(details: Dict[str, object], *names: str) -> str:
    return _first_normalized(_normalized_details(details), *names)


def _normalized_details(details: Dict[str, object]) -> Dict[str, object]:
    return {_norm_key(str(key)): value for key, value in details.items()}


def _first_normalized(normalized: Dict[str, object], *names: str) -> str:
    for name in names:
        value = normalized.get(_norm_key(name))
        if value not in (None, "", "-", "null", "None"):
            return str(value)
    return ""


@lru_cache(maxsize=4096)
def _norm_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _ip_scope(value: str) -> str:
    if not value:
        return "unknown"
    return "private" if is_private_ip(value) else "public"


def _asset_role(event: LogEvent, normalized: Dict[str, str]) -> str:
    source_type = normalized.get("source_type", "")
    if source_type in {"waf", "vpn", "bastion", "dns", "proxy", "firewall", "edr"}:
        return source_type
    text = " ".join([event.category, event.source, normalized.get("asset", ""), normalized.get("process", "")]).lower()
    for role, pattern in _ASSET_ROLE_PATTERNS:
        if pattern.search(text):
            return role
    if source_type in {"linux-auth", "windows-event"}:
        return "server"
    return "unknown"


def _domain_type(value: str) -> str:
    if not value:
        return "unknown"
    host = urlparse(value if "://" in value else "http://" + value).hostname or value
    host = host.lower().strip(".")
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        return _ip_scope(host)
    if _DOMAIN_CALLBACK_RE.search(host):
        return "callback"
    if host.endswith((".local", ".lan", ".internal")):
        return "internal"
    if _DOMAIN_SUSPICIOUS_RE.search(host):
        return "suspicious"
    return "external" if "." in host else "unknown"


def _auth_result(event: LogEvent) -> str:
    if any(tag in event.tags for tag in ("failed-login", "failed-logon", "pam-failure")):
        return "failed"
    if "successful-login" in event.tags or "auth-success" in event.tags or "logon" in event.tags:
        return "success"
    return "unknown"


def _event_family(event: LogEvent, normalized: Dict[str, str]) -> str:
    tags = set(event.tags)
    if tags & {"scanning", "scanner", "recon", "reconnaissance", "ddos", "post-error"}:
        return "reconnaissance"
    if tags & {"malware-indicator", "lsass-dump", "webshell"}:
        return "compromise"
    if tags & {"web-attack", "exploit"}:
        return "initial-access"
    if tags & {"c2", "dns-tunnel", "malicious-domain"}:
        return "command-control"
    if tags & {"exfiltration"}:
        return "exfiltration"
    if tags & {"account-creation", "account-enabled", "account-deletion", "account-disabled", "service-install", "scheduled-task", "persistence"}:
        return "persistence"
    if tags & {"group-add", "password-reset", "account-modified", "privilege-escalation", "sensitive-call"}:
        return "privilege-escalation"
    if tags & {"bastion-command", "lolbin"}:
        return "execution"
    if tags & {"remote-access", "remote-logon"} or ("credential-validation" in tags and "auth-success" in tags):
        return "remote-access"
    if tags & {"lateral-movement", "explicit-creds", "rdp", "smb", "exposed-service"}:
        return "lateral-movement"
    if tags & {"failed-login", "failed-logon", "successful-login", "authentication"}:
        return "identity"
    mitre_family = _event_family_from_mitre(event.mitre_attack or "")
    if mitre_family:
        return mitre_family
    if normalized.get("source_type") in {"proxy", "dns"}:
        return "network"
    return "other"


def _event_family_from_mitre(mitre: str) -> str:
    prefix = mitre.split(".")[0]
    return {
        "T1595": "reconnaissance",
        "T1083": "reconnaissance",
        "T1190": "initial-access",
        "T1078": "identity",
        "T1110": "identity",
        "T1059": "execution",
        "T1218": "execution",
        "T1543": "persistence",
        "T1053": "persistence",
        "T1136": "persistence",
        "T1547": "persistence",
        "T1548": "privilege-escalation",
        "T1098": "privilege-escalation",
        "T1070": "defense-evasion",
        "T1562": "defense-evasion",
        "T1140": "defense-evasion",
        "T1003": "credential-access",
        "T1558": "credential-access",
        "T1021": "lateral-movement",
        "T1550": "lateral-movement",
        "T1071": "command-control",
        "T1105": "command-control",
        "T1505": "compromise",
        "T1041": "exfiltration",
    }.get(prefix, "")
