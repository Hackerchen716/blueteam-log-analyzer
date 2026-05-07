"""Event normalization and enrichment before detection/correlation."""
from __future__ import annotations

import re
from collections import Counter
from typing import Dict, Iterable, List
from urllib.parse import urlparse

from ..models import LogEvent
from ..utils.helpers import is_private_ip


SENSITIVE_PORTS = {
    22, 23, 3389, 445, 135, 139, 1433, 1521, 3306, 5432, 6379,
    9200, 9300, 11211, 27017,
}

P0_NORMALIZED_FIELDS = (
    "source_type", "src_ip", "dst_ip", "asset", "account", "action",
    "status", "url", "command", "process", "bytes_out", "session_id",
    "trace_id",
)


def enrich_events(events: Iterable[LogEvent]) -> List[LogEvent]:
    """Add stable normalized/enriched fields to each event in-place."""
    enriched = list(events)
    ip_counts = Counter(e.ip for e in enriched if e.ip)
    account_counts = Counter(e.user for e in enriched if e.user)
    asset_counts = Counter(e.host for e in enriched if e.host)

    for event in enriched:
        normalized = _normalize_event(event)
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
    return enriched


def _normalize_event(event: LogEvent) -> Dict[str, str]:
    details = event.details
    source_type = _source_type(event)
    src_ip = event.ip or _first(details, "src_ip", "srcip", "sourceip", "clientip", "remoteaddr", "xff")
    dst_ip = _first(details, "dst_ip", "dstip", "destip", "destinationip", "serverip", "targetip")
    asset = event.host or dst_ip or _first(details, "asset", "target", "targethost", "host", "hostname", "server", "endpoint")
    account = event.user or _first(details, "account", "user", "username", "operator", "actor", "principal")
    action = _first(details, "action", "result", "status", "outcome", "policyaction")
    status = _first(details, "status", "statuscode", "responsecode", "result", "outcome")
    url = _first(details, "url", "uri", "path", "decoded_path", "request", "fullurl")
    command = _first(details, "command", "cmd", "commandline", "COMMAND", "ScriptBlockText", "Payload")
    process = event.process or _first(details, "process", "processname", "image", "filename", "NewProcessName")
    bytes_out = _first(details, "bytes_out", "bytesout", "sentbytes", "uploadbytes", "outbytes", "bytes")
    session_id = _first(details, "session_id", "sessionid", "sid", "session")
    trace_id = _first(details, "trace_id", "traceid", "requestid", "request_id")
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


def _source_type(event: LogEvent) -> str:
    kind = str(event.details.get("p0_kind") or "").lower()
    if kind:
        return kind
    hay = " ".join([event.source, event.category, event.source_file]).lower()
    checks = [
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
    ]
    for label, pattern in checks:
        if re.search(pattern, hay, re.I):
            return label
    return "generic"


def _first(details: Dict[str, object], *names: str) -> str:
    normalized = {_norm_key(key): value for key, value in details.items()}
    for name in names:
        value = normalized.get(_norm_key(name))
        if value not in (None, "", "-", "null", "None"):
            return str(value)
    return ""


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
    if re.search(r"dc|domain.?controller|kerberos|域控", text):
        return "domain-controller"
    if re.search(r"mysql|postgres|oracle|sqlserver|redis|mongo|database|数据库", text):
        return "database"
    if re.search(r"nginx|apache|tomcat|iis|web|http", text):
        return "web-server"
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
    if re.search(r"dnslog|ceye|burpcollaborator|interactsh|jndi|ldap|rmi", host):
        return "callback"
    if host.endswith((".local", ".lan", ".internal")):
        return "internal"
    if re.search(r"c2|beacon|malware|evil|shell", host):
        return "suspicious"
    return "external" if "." in host else "unknown"


def _auth_result(event: LogEvent) -> str:
    if any(tag in event.tags for tag in ("failed-login", "failed-logon", "pam-failure")):
        return "failed"
    if "successful-login" in event.tags or "logon" in event.tags:
        return "success"
    return "unknown"


def _event_family(event: LogEvent, normalized: Dict[str, str]) -> str:
    tags = set(event.tags)
    if tags & {"web-attack", "exploit"}:
        return "initial-access"
    if tags & {"malware-indicator", "lsass-dump", "webshell"}:
        return "compromise"
    if tags & {"c2", "dns-tunnel", "malicious-domain"}:
        return "command-control"
    if tags & {"exfiltration"}:
        return "exfiltration"
    if tags & {"bastion-command", "lolbin", "sudo-shell", "sudo-command"}:
        return "execution"
    if tags & {"lateral-movement", "explicit-creds", "rdp", "smb", "exposed-service"}:
        return "lateral-movement"
    if tags & {"failed-login", "failed-logon", "successful-login", "authentication"}:
        return "identity"
    if tags & {"scanning", "scanner", "recon"}:
        return "reconnaissance"
    if normalized.get("source_type") in {"proxy", "dns"}:
        return "network"
    return "other"
