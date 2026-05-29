"""HVV / 重保 P0 安全日志解析器。

面向 WAF、VPN、堡垒机、DNS、代理/NAT、防火墙、EDR 和应用日志的常见
CSV / JSONL / JSON 数组 / key=value 导出格式。解析器只做字段归一和基础
高价值事件识别，跨事件聚合仍交给 detection 层。
"""

from __future__ import annotations

import csv
import datetime
import json
import os
import re
import time
from dataclasses import dataclass
from functools import lru_cache
from itertools import chain, islice
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple
from urllib.parse import urlparse

from ..models import LogEvent, ParseResult, ParseStats, ThreatLevel
from ..rules import get_web_attack_rules
from ..utils.helpers import (
    file_size,
    gen_id,
    iter_file_chunks,
    iter_file_lines,
    normalize_timestamp,
    read_file_sample,
    truncate,
)
from .stats import compute_stats
from .web_access import _ATTACK_PATTERNS, _decode_url

_P0_FILENAME_HINTS = (
    "waf", "webfirewall", "modsecurity", "vpn", "sslvpn", "ztna",
    "bastion", "jumpserver", "jump", "堡垒", "dns", "proxy", "swg",
    "firewall", "fw", "nat", "session", "edr", "xdr", "hids",
    "antivirus", "av", "application", "app", "spring", "tomcat",
)

_P0_FIELD_HINTS = (
    "src_ip", "source_ip", "client_ip", "remote_addr", "xff",
    "dst_ip", "dest_ip", "destination_ip", "user", "username", "account",
    "action", "result", "uri", "url", "query", "domain", "rule_id",
    "signature", "command", "cmd", "process", "severity", "alert",
    "threat", "event_type", "log_type",
)

_KV_RE = re.compile(r'([A-Za-z_][\w.\-]*)=(?:"([^"]*)"|\'([^\']*)\'|(\S+))')
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_SENSITIVE_PORTS = {22, 23, 3389, 445, 135, 139, 1433, 1521, 3306, 5432, 6379, 9200, 9300, 11211, 27017}
_PUBLIC_DOWNLOAD_RE = re.compile(r'\.(?:exe|dll|ps1|bat|cmd|vbs|js|jar|sh|elf|bin)(?:$|[?#])', re.I)
_DANGEROUS_COMMAND_RE = re.compile(
    r'(?:mimikatz|sekurlsa|lsadump|procdump|lsass|powershell|certutil|bitsadmin|'
    r'mshta|regsvr32|rundll32|wmic|psexec|curl|wget|nc\s|ncat|bash\s+-i|'
    r'/dev/tcp|chmod\s+\+x|crontab|authorized_keys|history\s+-c|iptables\s+-F|'
    r'net\s+user|net\s+localgroup|whoami|id\s*$|uname\s+-a)',
    re.I,
)
_APP_SECURITY_RE = re.compile(
    r'(?:jndi:|log4shell|fastjson|autoType|shiro|rememberme|struts2|ognl|'
    r'thinkphp|weblogic|spring4shell|classLoader|webshell|behinder|godzilla|'
    r'cmd=|exec=|shell_exec|Runtime\.getRuntime|ProcessBuilder|反序列化|越权)',
    re.I,
)
_MALWARE_RE = re.compile(
    r'(?:mimikatz|lsass|credential|dump|ransom|勒索|trojan|virus|malware|'
    r'webshell|backdoor|木马|后门|cobalt|beacon|cs\b|哥斯拉|冰蝎|蚁剑)',
    re.I,
)
_KIND_FAST_ALIASES = {
    "waf": "waf",
    "webfirewall": "waf",
    "modsecurity": "waf",
    "websecurity": "waf",
    "vpn": "vpn",
    "sslvpn": "vpn",
    "openvpn": "vpn",
    "ztna": "vpn",
    "bastion": "bastion",
    "jumpserver": "bastion",
    "jumphost": "bastion",
    "dns": "dns",
    "proxy": "proxy",
    "swg": "proxy",
    "firewall": "firewall",
    "fw": "firewall",
    "nat": "firewall",
    "edr": "edr",
    "xdr": "edr",
    "hids": "edr",
    "application": "app",
    "app": "app",
}

P0Builder = Callable[[Dict[str, str], str, str], Optional[LogEvent]]


@dataclass(frozen=True)
class P0Adapter:
    """P0 source adapter metadata used for routing structured records."""

    kind: str
    source_label: str
    build: P0Builder
    aliases: Tuple[str, ...]
    infer_pattern: str


def looks_like_p0_security_log(file_path: str, sample_text: str) -> bool:
    """判断是否适合走 P0 结构化安全日志解析器。"""
    fname = os.path.basename(file_path).lower()
    if any(hint in fname for hint in _P0_FILENAME_HINTS):
        return True

    sample = sample_text[:4096].lower()
    if _looks_like_json_record(sample_text) or _looks_like_csv_header(sample_text):
        hits = sum(1 for hint in _P0_FIELD_HINTS if hint in sample)
        return hits >= 2
    if _KV_RE.search(sample_text):
        hits = sum(1 for hint in _P0_FIELD_HINTS if hint in sample)
        return hits >= 2
    return False


def parse_p0_security_file(path: str, source_file: Optional[str] = None) -> ParseResult:
    sample = read_file_sample(path)
    source_name = source_file or os.path.basename(path)
    if _looks_like_csv_header(sample):
        return parse_p0_security_lines(
            iter_file_lines(path),
            source_name,
            file_size_bytes=file_size(path),
            parser_hint="csv",
        )
    stripped = sample.lstrip()
    if stripped.startswith("{"):
        parsed = parse_p0_security_json_file(path, source_name)
        if parsed.stats.parse_errors == 0:
            return parsed
        fallback = parse_p0_security_lines(iter_file_lines(path), source_name, file_size_bytes=file_size(path))
        return fallback if fallback.events else parsed
    if stripped.startswith("["):
        return parse_p0_security_json_file(path, source_name)
    return parse_p0_security_lines(
        iter_file_lines(path),
        source_name,
        file_size_bytes=file_size(path),
    )


def parse_p0_security_json(content: str, source_file: str, file_size_bytes: int = 0) -> ParseResult:
    t0 = time.time()
    events: List[LogEvent] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return _result(source_file, events, t0, file_size_bytes, parse_errors=1)
    if not isinstance(data, (list, dict)):
        return _result(source_file, events, t0, file_size_bytes, parse_errors=1)
    rows = data if isinstance(data, list) else [data]
    for row in rows:
        if not isinstance(row, dict):
            continue
        ev = _event_from_record(row, json.dumps(row, ensure_ascii=False), source_file)
        if ev:
            events.append(ev)
    return _result(source_file, events, t0, file_size_bytes)


def parse_p0_security_json_file(path: str, source_file: Optional[str] = None) -> ParseResult:
    """Stream JSON object/array/JSONL P0 exports from disk.

    JSON arrays are decoded one record at a time so large vendor exports do not
    need to be materialized as a single Python list before event normalization.
    """
    t0 = time.time()
    source_name = source_file or os.path.basename(path)
    events: List[LogEvent] = []
    parse_errors = 0
    try:
        for row in _iter_json_records_from_chunks(iter_file_chunks(path)):
            ev = _event_from_record(row, json.dumps(row, ensure_ascii=False), source_name)
            if ev:
                events.append(ev)
    except json.JSONDecodeError:
        parse_errors += 1
    return _result(source_name, events, t0, file_size(path), parse_errors=parse_errors)


def _iter_json_records_from_chunks(chunks: Iterable[str]) -> Iterator[Dict[str, Any]]:
    decoder = json.JSONDecoder()
    iterator = iter(chunks)
    buffer = ""
    pos = 0
    eof = False
    mode = ""

    def fill() -> bool:
        nonlocal buffer, eof
        if eof:
            return False
        try:
            buffer += next(iterator)
            return True
        except StopIteration:
            eof = True
            return False

    def skip_ws() -> bool:
        nonlocal buffer, pos
        while True:
            while pos < len(buffer) and buffer[pos].isspace():
                pos += 1
            if pos < len(buffer):
                return True
            if not fill():
                return False
            if pos > 1024 * 1024:
                buffer = buffer[pos:]
                pos = 0

    def decode_value() -> Any:
        nonlocal buffer, pos
        while True:
            try:
                value, end = decoder.raw_decode(buffer, pos)
                pos = end
                if pos > 1024 * 1024:
                    buffer = buffer[pos:]
                    pos = 0
                return value
            except json.JSONDecodeError:
                if not fill():
                    raise

    while True:
        if not skip_ws():
            return
        if not mode:
            if buffer[pos] == "[":
                mode = "array"
                pos += 1
                continue
            mode = "sequence"

        if mode == "array":
            if not skip_ws():
                raise json.JSONDecodeError("unterminated JSON array", buffer, pos)
            if buffer[pos] == "]":
                return
            if buffer[pos] == ",":
                pos += 1
                continue
            yield from _json_value_records(decode_value())
            continue

        yield from _json_value_records(decode_value())


def _json_value_records(value: Any) -> Iterator[Dict[str, Any]]:
    if isinstance(value, dict):
        for key in ("events", "records", "logs", "items", "data"):
            nested = value.get(key)
            if isinstance(nested, list) and all(isinstance(item, dict) for item in nested):
                yield from nested
                return
        yield value
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                yield item


def parse_p0_security_lines(
    lines: Iterable[str],
    source_file: str,
    file_size_bytes: int = 0,
    parser_hint: str = "",
) -> ParseResult:
    t0 = time.time()
    events: List[LogEvent] = []
    if parser_hint == "csv":
        reader = csv.DictReader(lines)
        for row in reader:
            ev = _event_from_record(row, json.dumps(row, ensure_ascii=False), source_file)
            if ev:
                events.append(ev)
        return _result(source_file, events, t0, file_size_bytes)

    iterator = iter(lines)
    head = list(islice(iterator, 3))
    stream = chain(head, iterator)
    if head and _looks_like_csv_header("\n".join(head)):
        reader = csv.DictReader(stream)
        for row in reader:
            ev = _event_from_record(row, json.dumps(row, ensure_ascii=False), source_file)
            if ev:
                events.append(ev)
        return _result(source_file, events, t0, file_size_bytes)

    for line in stream:
        if not line.strip():
            continue
        record = _parse_structured_line(line)
        if record:
            ev = _event_from_record(record, line, source_file)
        else:
            ev = _event_from_text(line, source_file)
        if ev:
            events.append(ev)
    return _result(source_file, events, t0, file_size_bytes)


def _result(
    source_file: str,
    events: List[LogEvent],
    t0: float,
    file_size_bytes: int,
    parse_errors: int = 0,
) -> ParseResult:
    stats = compute_stats(events) if events else ParseStats(total=0)
    stats.parse_errors += parse_errors
    return ParseResult(
        file_name=source_file,
        log_type="P0 Security Log (HVV/重保)",
        events=events,
        stats=stats,
        parse_time_ms=(time.time() - t0) * 1000,
        file_size_bytes=file_size_bytes,
    )


def _parse_structured_line(line: str) -> Optional[Dict[str, Any]]:
    stripped = line.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            obj = json.loads(stripped)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None
    pairs = _KV_RE.findall(line)
    if pairs:
        return {key: (v1 or v2 or v3) for key, v1, v2, v3 in pairs}
    return None


def _event_from_record(record: Dict[str, Any], raw_line: str, source_file: str) -> Optional[LogEvent]:
    fields = _normalize_record(record)
    kind = _infer_kind(fields, source_file)
    builder = _P0_ADAPTER_BUILDERS.get(kind)
    if builder:
        return builder(fields, raw_line, source_file)
    return _build_generic_security_event(fields, raw_line, source_file)


def _build_waf_event(fields: Dict[str, str], raw_line: str, source_file: str) -> Optional[LogEvent]:
    text = _join_values(fields, (
        "url", "uri", "path", "request", "request_uri", "requesturi",
        "request_url", "requesturl", "full_url", "fullurl", "query",
        "payload", "body", "rule", "rule_name", "rulename", "ruleid",
        "attacktype", "attack_type", "attackname", "attack_name", "threat",
        "signature", "signature_name", "signaturename", "message",
        "useragent", "user_agent", "referer",
    ))
    rule_name, level, tags, mitre = _classify_web_text(text)
    action = _field(fields, "action", "disposition", "policyaction")
    blocked = _is_block_action(action)
    attack_label = _field(
        fields,
        "attacktype", "attack_type", "attackname", "attack_name", "threat",
        "signature", "signature_name", "signaturename", "rulename",
        "rule_name", "rule",
    )
    if not rule_name and attack_label:
        rule_name = truncate(attack_label, 60)
        level = ThreatLevel.HIGH
        tags = ["web-attack", "waf"]
        mitre = "T1190"
    if not rule_name and not blocked:
        return None
    if not rule_name:
        rule_name = "WAF 拦截/告警"
        level = ThreatLevel.MEDIUM
        tags = ["waf", "blocked"]
        mitre = "T1190"
    if blocked and level == ThreatLevel.CRITICAL:
        level = ThreatLevel.HIGH
    if blocked:
        tags = list(dict.fromkeys(tags + ["blocked"]))

    method = _field(fields, "method", "requestmethod")
    path = _field(fields, "uri", "url", "path", "request_uri", "requesturi", "request_url", "requesturl", "full_url", "fullurl", "request")
    src_ip = _src_ip(fields)
    status = _field(fields, "status", "statuscode", "responsecode")
    message = f"WAF {action or '告警'}: {rule_name}"
    if method or path:
        message += f" {method} {truncate(_decode_url(path), 120)}".rstrip()
    if status:
        message += f" -> {status}"
    return _make_event(
        prefix="p0",
        timestamp=_timestamp(fields),
        level=level,
        category="Web攻击",
        source="WAF",
        source_file=source_file,
        message=message,
        raw_line=raw_line,
        ip=src_ip,
        user=_user(fields),
        host=_field(fields, "host", "hostname", "domain", "server"),
        details=_details(fields, kind="waf"),
        tags=list(dict.fromkeys(tags + ["waf"])),
        mitre_attack=mitre,
        rule_name=rule_name,
        rule_id=_field(fields, "ruleid", "rule_id", "signatureid"),
    )


def _build_vpn_event(fields: Dict[str, str], raw_line: str, source_file: str) -> Optional[LogEvent]:
    result = _field(
        fields,
        "result", "status", "outcome", "auth_result", "authresult",
        "login_result", "loginresult", "auth_status", "authstatus",
        "login_status", "loginstatus", "action", "event",
    )
    message_text = _join_values(fields, (
        "message", "reason", "auth_reason", "authreason",
        "failure_reason", "failurereason", "eventname", "eventtype",
        "event_action", "eventaction", "operation", "activity",
    ))
    failed = _is_failed(result + " " + message_text)
    success = _is_success(result + " " + message_text)
    if not failed and not success and not re.search(r'login|auth|mfa|认证|登录', message_text, re.I):
        return None
    auth_observed = not failed and not success
    level = ThreatLevel.MEDIUM if failed else ThreatLevel.INFO
    if failed:
        tags = ["failed-login", "authentication", "vpn"]
        status_label = "登录失败"
        mitre = "T1110.001"
        rule_name = "VPN 登录失败"
    elif success:
        tags = ["successful-login", "authentication", "vpn"]
        status_label = "登录成功"
        mitre = "T1078"
        rule_name = "VPN 登录成功"
    else:
        tags = ["authentication", "vpn", "auth-observed"]
        status_label = "认证事件"
        mitre = None
        rule_name = "VPN 认证事件"
    user = _user(fields)
    ip = _src_ip(fields)
    reason = _field(fields, "reason", "auth_reason", "failure_reason", "message", "error")
    msg = f"VPN {status_label}: 用户={user or '?'} 来源={ip or '?'}"
    if auth_observed and result:
        msg += f" 状态={truncate(result, 40)}"
    if reason:
        msg += f" 原因={truncate(reason, 80)}"
    return _make_event(
        prefix="p0",
        timestamp=_timestamp(fields),
        level=level,
        category="VPN",
        source="VPN",
        source_file=source_file,
        message=msg,
        raw_line=raw_line,
        ip=ip,
        user=user,
        host=_field(fields, "device", "gateway", "host", "hostname"),
        details=_details(fields, kind="vpn"),
        tags=tags,
        mitre_attack=mitre,
        rule_name=rule_name,
    )


def _build_bastion_event(fields: Dict[str, str], raw_line: str, source_file: str) -> Optional[LogEvent]:
    action = _field(
        fields,
        "action", "action_type", "actiontype", "event", "eventtype",
        "event_action", "eventaction", "operation", "operation_type",
        "operationtype", "activity",
    )
    command = _field(fields, "command", "cmd", "commandline", "input")
    result = _field(fields, "result", "status", "outcome")
    text = " ".join([action, command, result, _field(fields, "message")])
    user = _user(fields)
    src_ip = _src_ip(fields)
    target = _field(
        fields,
        "target", "target_host", "targethost", "target_asset",
        "targetasset", "asset_name", "assetname", "dst_host", "dsthost",
        "server", "asset", "dst_ip", "dstip", "dest_ip", "destip",
    )
    file_path = _field(
        fields,
        "file", "filename", "file_name", "path", "file_path", "filepath",
        "src_file", "srcfile", "dst_file", "dstfile", "source_file",
        "sourcefile", "target_file", "targetfile",
    )

    if _is_failed(text) and re.search(r'login|auth|ssh|rdp|登录|认证', text, re.I):
        return _make_event(
            prefix="p0", timestamp=_timestamp(fields), level=ThreatLevel.MEDIUM,
            category="堡垒机", source="Bastion", source_file=source_file,
            message=f"堡垒机登录失败: 用户={user or '?'} 来源={src_ip or '?'} 目标={target or '?'}",
            raw_line=raw_line, ip=src_ip, user=user, host=target,
            details=_details(fields, kind="bastion"),
            tags=["failed-login", "authentication", "bastion"],
            mitre_attack="T1110.001", rule_name="堡垒机登录失败",
        )

    if not command and _is_bastion_file_transfer(" ".join([text, file_path])):
        msg = f"堡垒机文件传输: 用户={user or '?'} 目标={target or '?'}"
        if file_path:
            msg += f" 文件={truncate(file_path, 120)}"
        if action:
            msg += f" 动作={truncate(action, 40)}"
        return _make_event(
            prefix="p0", timestamp=_timestamp(fields), level=ThreatLevel.MEDIUM,
            category="堡垒机", source="Bastion", source_file=source_file,
            message=msg, raw_line=raw_line, ip=src_ip, user=user, host=target,
            process=_field(fields, "process", "program"),
            details=_details(fields, kind="bastion"),
            tags=["bastion-command", "file-transfer", "bastion"],
            mitre_attack="T1105", rule_name="堡垒机文件传输",
        )

    if command:
        dangerous = _DANGEROUS_COMMAND_RE.search(command)
        file_transfer = re.search(r'upload|download|scp|sftp|文件|传输', text, re.I)
        if not dangerous and not file_transfer:
            return None
        level = ThreatLevel.HIGH if dangerous else ThreatLevel.MEDIUM
        tags = ["bastion-command"]
        mitre = "T1059"
        rule_name = "堡垒机高危命令" if dangerous else "堡垒机文件传输"
        if re.search(r'\b(?:ssh|scp|psexec|wmic|rdp)\b', command, re.I):
            tags.append("lateral-movement")
            mitre = "T1021"
        return _make_event(
            prefix="p0", timestamp=_timestamp(fields), level=level,
            category="堡垒机", source="Bastion", source_file=source_file,
            message=f"{rule_name}: 用户={user or '?'} 目标={target or '?'} 命令={truncate(command, 120)}",
            raw_line=raw_line, ip=src_ip, user=user, host=target,
            process=_field(fields, "process", "program"),
            details=_details(fields, kind="bastion"),
            tags=tags, mitre_attack=mitre, rule_name=rule_name,
        )

    if _is_success(text) and re.search(r'login|auth|ssh|rdp|登录|认证', text, re.I):
        return _make_event(
            prefix="p0", timestamp=_timestamp(fields), level=ThreatLevel.INFO,
            category="堡垒机", source="Bastion", source_file=source_file,
            message=f"堡垒机登录成功: 用户={user or '?'} 来源={src_ip or '?'} 目标={target or '?'}",
            raw_line=raw_line, ip=src_ip, user=user, host=target,
            details=_details(fields, kind="bastion"),
            tags=["successful-login", "authentication", "bastion"],
            mitre_attack="T1078", rule_name="堡垒机登录成功",
        )
    return None


def _build_dns_event(fields: Dict[str, str], raw_line: str, source_file: str) -> Optional[LogEvent]:
    query = _field(fields, "query", "queryname", "dns_query", "dnsquery", "question", "rrname", "domain", "fqdn", "qname", "hostname")
    if not query:
        return None
    query_l = query.lower().strip(".")
    category = _field(
        fields,
        "category", "threat", "classification", "security_category",
        "securitycategory", "threat_category", "threatcategory",
        "domain_category", "domaincategory", "query_category", "querycategory",
        "dns_category", "dnscategory", "verdict", "disposition", "policy",
        "policy_action", "policyaction", "rule", "signature",
    )
    rcode = _field(fields, "rcode", "response_code", "responsecode", "result", "status")
    suspicious = _dns_suspicion(query_l, category, rcode)
    if not suspicious:
        return None
    rule_name, level, tags, mitre = suspicious
    src_ip = _src_ip(fields)
    answer = _field(fields, "answer", "answers", "response", "resolved_ip", "resolvedip", "response_ip", "responseip")
    msg = f"DNS 可疑查询: {query_l}"
    if answer:
        msg += f" -> {truncate(answer, 80)}"
    return _make_event(
        prefix="p0", timestamp=_timestamp(fields), level=level,
        category="DNS", source="DNS", source_file=source_file,
        message=msg, raw_line=raw_line, ip=src_ip, user=_user(fields),
        host=_field(fields, "host", "clienthost", "hostname"),
        details=_details(fields, kind="dns"),
        tags=tags, mitre_attack=mitre, rule_name=rule_name,
    )


def _build_proxy_event(fields: Dict[str, str], raw_line: str, source_file: str) -> Optional[LogEvent]:
    url = _field(fields, "url", "uri", "request_url", "requesturl", "request_uri", "requesturi", "full_url", "fullurl", "request")
    domain = _field(fields, "domain", "host", "dsthost", "desthost", "dst_domain", "dest_domain", "destination_host")
    text = _join_values(fields, (
        "url", "uri", "request_url", "requesturl", "request_uri",
        "requesturi", "full_url", "fullurl", "domain", "category",
        "url_category", "threat_category", "risk_category",
        "security_category", "classification", "threat", "verdict",
        "disposition", "policy", "policy_action", "rule", "signature",
        "action", "message", "useragent",
    ))
    action = _field(fields, "action", "result", "outcome")
    bytes_out = _bytes_out(fields, extra_names=_PROXY_BYTES_OUT_NAMES, generic_names=("bytes",))
    src_ip = _src_ip(fields)
    category = "代理/上网行为"

    rule_name, level, tags, mitre = _classify_web_text(text)
    if rule_name:
        rule_name = f"代理访问可疑 URL: {rule_name}"
        category = "命令控制"
    elif re.search(r'c2|command.?control|malware|phishing|botnet|恶意|木马|钓鱼', text, re.I):
        rule_name = "代理命中恶意分类"
        level = ThreatLevel.HIGH
        tags = ["c2", "malicious-url", "proxy"]
        mitre = "T1071"
    elif bytes_out >= 100 * 1024 * 1024:
        rule_name = "代理大流量外发"
        level = ThreatLevel.HIGH
        tags = ["exfiltration", "proxy"]
        mitre = "T1041"
        category = "数据外传"
    elif _PUBLIC_DOWNLOAD_RE.search(url or ""):
        rule_name = "代理下载可执行/脚本文件"
        level = ThreatLevel.MEDIUM
        tags = ["suspicious-download", "proxy"]
        mitre = "T1105"
    elif _is_block_action(action):
        return None
    else:
        return None

    target = domain or _domain_from_url(url)
    msg = f"{rule_name}: 用户={_user(fields) or '?'} 来源={src_ip or '?'} 目标={target or truncate(url, 80)}"
    return _make_event(
        prefix="p0", timestamp=_timestamp(fields), level=level,
        category=category, source="Proxy/SWG", source_file=source_file,
        message=msg, raw_line=raw_line, ip=src_ip, user=_user(fields),
        host=target, details=_details(fields, kind="proxy"),
        tags=list(dict.fromkeys(tags + ["proxy"])), mitre_attack=mitre,
        rule_name=rule_name,
    )


def _build_firewall_event(fields: Dict[str, str], raw_line: str, source_file: str) -> Optional[LogEvent]:
    action = _field(
        fields,
        "action", "result", "disposition", "policy_action", "policyaction",
        "event_action", "eventaction", "rule_action", "ruleaction",
        "session_action", "sessionaction",
    )
    src_ip = _src_ip(fields)
    dst_ip = _dst_ip(fields)
    dst_port = _int_field(fields, "dstport", "destport", "destinationport", "dport", "port")
    bytes_out = _bytes_out(fields, generic_names=("bytes",))
    proto = _field(fields, "protocol", "proto")

    if _is_block_action(action) and dst_port in _SENSITIVE_PORTS:
        level = ThreatLevel.MEDIUM
        rule_name = "防火墙阻断敏感端口访问"
        tags = ["scanning", "firewall", "blocked"]
        mitre = "T1595"
    elif _is_allow_action(action) and dst_port in _SENSITIVE_PORTS:
        level = ThreatLevel.HIGH
        rule_name = "防火墙放行敏感端口访问"
        tags = ["exposed-service", "firewall"]
        mitre = "T1021" if dst_port in {22, 3389, 445} else "T1190"
    elif dst_port in _SENSITIVE_PORTS:
        level = ThreatLevel.MEDIUM
        rule_name = "防火墙敏感端口访问（动作未知）"
        tags = ["scanning", "firewall", "unknown-action"]
        mitre = "T1021" if dst_port in {22, 3389, 445} else "T1190"
    elif bytes_out >= 100 * 1024 * 1024:
        level = ThreatLevel.HIGH
        rule_name = "防火墙大流量外联"
        tags = ["exfiltration", "firewall"]
        mitre = "T1041"
    else:
        return None

    msg = f"{rule_name}: {src_ip or '?'} -> {dst_ip or '?'}:{dst_port or '?'} {proto or ''} action={action or '?'}"
    return _make_event(
        prefix="p0", timestamp=_timestamp(fields), level=level,
        category="防火墙/NAT", source="Firewall/NAT", source_file=source_file,
        message=msg, raw_line=raw_line, ip=src_ip, port=dst_port or None,
        user=_user(fields), host=dst_ip, details=_details(fields, kind="firewall"),
        tags=tags, mitre_attack=mitre, rule_name=rule_name,
    )


def _build_edr_event(fields: Dict[str, str], raw_line: str, source_file: str) -> Optional[LogEvent]:
    title = _field(
        fields,
        "alert", "alert_name", "alertname", "detection", "detection_name",
        "detectionname", "threat", "threat_name", "threatname", "event_name",
        "eventname", "signature", "rule", "rule_name", "rulename",
    )
    severity = _field(fields, "severity", "level", "risk", "risk_level", "risklevel", "priority")
    text = _join_values(fields, (
        "alert", "alert_name", "detection", "detection_name", "threat",
        "threat_name", "event_name", "message", "description", "process",
        "process_name", "process_path", "image", "image_path", "commandline",
        "command_line", "cmdline", "file", "file_path", "path", "signature",
        "rule", "rule_name", "technique", "technique_id", "mitre", "mitre_id",
    ))
    if not title and not severity and not _MALWARE_RE.search(text):
        return None
    level = _severity_to_level(severity, default=ThreatLevel.MEDIUM)
    tags = ["edr"]
    mitre = _field(fields, "mitre", "technique", "technique_id", "techniqueid", "mitre_id", "mitreid") or None
    if _MALWARE_RE.search(text):
        tags.append("malware-indicator")
        if level.score < ThreatLevel.HIGH.score:
            level = ThreatLevel.HIGH
    if re.search(r'lsass|credential|mimikatz|dump', text, re.I):
        tags.append("lsass-dump")
        mitre = mitre or "T1003.001"
        level = ThreatLevel.CRITICAL
    if re.search(r'webshell|behinder|godzilla|冰蝎|哥斯拉|蚁剑', text, re.I):
        tags.extend(["webshell", "cn-hvv"])
        mitre = mitre or "T1505.003"
    if re.search(r'powershell|certutil|mshta|regsvr32|rundll32|bitsadmin', text, re.I):
        tags.append("lolbin")
        mitre = mitre or "T1218"
    process = _field(fields, "process", "process_name", "processname", "process_path", "processpath", "image", "image_path", "imagepath", "filename")
    cmd = _field(fields, "commandline", "command_line", "cmdline", "cmd", "command", "process_command_line", "processcommandline")
    msg = f"EDR 告警: {title or truncate(text, 80)}"
    if process:
        msg += f" 进程={truncate(process, 80)}"
    if cmd:
        msg += f" 命令={truncate(cmd, 100)}"
    return _make_event(
        prefix="p0", timestamp=_timestamp(fields), level=level,
        category="EDR", source="EDR/XDR", source_file=source_file,
        message=msg, raw_line=raw_line, ip=_src_ip(fields), user=_user(fields),
        host=_field(fields, "host", "hostname", "endpoint", "device", "asset"),
        process=process, details=_details(fields, kind="edr"),
        tags=list(dict.fromkeys(tags)), mitre_attack=mitre,
        rule_name=title or "EDR 告警",
    )


def _build_app_event(fields: Dict[str, str], raw_line: str, source_file: str) -> Optional[LogEvent]:
    text = _join_values(fields, (
        "message", "msg", "exception", "stacktrace", "url", "uri", "path",
        "action", "event", "event_type", "eventtype", "event_name", "eventname",
        "operation", "activity", "auth_result", "authresult", "login_result",
        "loginresult", "auth_status", "authstatus", "login_status",
        "loginstatus", "reason", "auth_reason", "authreason",
        "failure_reason", "failurereason",
    ))
    result = _field(
        fields,
        "result", "status", "outcome", "auth_result", "authresult",
        "login_result", "loginresult", "auth_status", "authstatus",
        "login_status", "loginstatus",
    )
    user = _user(fields)
    ip = _src_ip(fields)
    app_host = _field(
        fields,
        "host", "hostname", "app", "app_name", "appname", "service",
        "service_name", "servicename", "application", "application_name",
        "applicationname",
    )
    if re.search(r'login|auth|认证|登录', text + " " + result, re.I):
        if _is_failed(text + " " + result):
            return _make_event(
                prefix="p0", timestamp=_timestamp(fields), level=ThreatLevel.MEDIUM,
                category="应用认证", source="Application", source_file=source_file,
                message=f"应用登录失败: 用户={user or '?'} 来源={ip or '?'}",
                raw_line=raw_line, ip=ip, user=user,
                host=app_host,
                details=_details(fields, kind="application"),
                tags=["failed-login", "authentication", "application"],
                mitre_attack="T1110.001", rule_name="应用登录失败",
            )
        if _is_success(text + " " + result):
            return _make_event(
                prefix="p0", timestamp=_timestamp(fields), level=ThreatLevel.INFO,
                category="应用认证", source="Application", source_file=source_file,
                message=f"应用登录成功: 用户={user or '?'} 来源={ip or '?'}",
                raw_line=raw_line, ip=ip, user=user,
                host=app_host,
                details=_details(fields, kind="application"),
                tags=["successful-login", "authentication", "application"],
                mitre_attack="T1078", rule_name="应用登录成功",
            )

    rule_name, level, tags, mitre = _classify_web_text(text)
    if rule_name or _APP_SECURITY_RE.search(text):
        rule_name = rule_name or "应用安全异常"
        if level.score < ThreatLevel.HIGH.score:
            level = ThreatLevel.HIGH
        return _make_event(
            prefix="p0", timestamp=_timestamp(fields), level=level,
            category="应用安全", source="Application", source_file=source_file,
            message=f"{rule_name}: {truncate(text, 160)}",
            raw_line=raw_line, ip=ip, user=user,
            host=app_host,
            details=_details(fields, kind="application"),
            tags=list(dict.fromkeys(tags + ["application", "web-attack"])),
            mitre_attack=mitre or "T1190", rule_name=rule_name,
        )

    level_name = _field(fields, "level", "severity")
    if re.search(r'error|fatal|exception|warn|warning|错误|异常', level_name + " " + text, re.I):
        return _make_event(
            prefix="p0", timestamp=_timestamp(fields),
            level=_severity_to_level(level_name, default=ThreatLevel.MEDIUM),
            category="应用异常", source="Application", source_file=source_file,
            message=f"应用异常: {truncate(text, 160)}",
            raw_line=raw_line, ip=ip, user=user,
            host=app_host,
            details=_details(fields, kind="application"),
            tags=["application-error"], rule_name="应用异常",
        )
    return None


def _build_generic_security_event(fields: Dict[str, str], raw_line: str, source_file: str) -> Optional[LogEvent]:
    text = _join_values(fields, tuple(fields.keys()))
    if _MALWARE_RE.search(text):
        return _build_edr_event(fields, raw_line, source_file)
    if _APP_SECURITY_RE.search(text):
        return _build_app_event(fields, raw_line, source_file)
    if _is_failed(text) and re.search(r'login|auth|登录|认证', text, re.I):
        return _build_vpn_event(fields, raw_line, source_file)
    return None


def _event_from_text(line: str, source_file: str) -> Optional[LogEvent]:
    fields: Dict[str, str] = {"message": line}
    ip_m = _IP_RE.search(line)
    if ip_m:
        fields["srcip"] = ip_m.group(0)
    if re.search(r'exception|error|warn|jndi|fastjson|shiro|webshell|登录|认证|login|auth', line, re.I):
        return _build_app_event(fields, line, source_file)
    return None


def _classify_web_text(text: str) -> Tuple[Optional[str], ThreatLevel, List[str], Optional[str]]:
    decoded = _decode_url(text or "")
    check = " ".join([text or "", decoded])
    for rule in get_web_attack_rules():
        if rule.pattern.search(check):
            return rule.name, rule.level, list(dict.fromkeys(rule.tags + ["web-attack"])), rule.mitre
    for pattern, lvl, _category, name, mitre, tags in _ATTACK_PATTERNS:
        if pattern.search(check):
            return name, lvl, list(dict.fromkeys(tags + ["web-attack"])), mitre
    return None, ThreatLevel.INFO, [], None


def _dns_suspicion(query: str, category: str, rcode: str) -> Optional[Tuple[str, ThreatLevel, List[str], str]]:
    if re.search(r'jndi|ldap|rmi|dnslog|ceye|burpcollaborator|interactsh', query, re.I):
        return "DNS Log4Shell/回连探测", ThreatLevel.HIGH, ["dns", "c2", "cn-hvv"], "T1071.004"
    if re.search(r'c2|malware|botnet|dga|tunnel|恶意|木马|僵尸', category, re.I):
        return "DNS 恶意域名/威胁分类", ThreatLevel.HIGH, ["dns", "c2", "malicious-domain"], "T1071.004"
    labels = query.split(".")
    longest = max((len(label) for label in labels), default=0)
    entropyish = sum(1 for label in labels if len(label) >= 16 and re.fullmatch(r'[a-z0-9_-]+', label or ""))
    if longest >= 50 or (len(labels) >= 5 and entropyish >= 2):
        return "DNS 隧道/高熵域名", ThreatLevel.HIGH, ["dns", "dns-tunnel", "c2"], "T1071.004"
    if "nxdomain" in rcode.lower() and longest >= 24:
        return "疑似 DGA/NXDOMAIN", ThreatLevel.MEDIUM, ["dns", "dga", "recon"], "T1071.004"
    return None


def _infer_kind(fields: Dict[str, str], source_file: str) -> str:
    explicit = _explicit_kind(fields)
    if explicit:
        return explicit

    hay = " ".join([source_file.lower(), *fields.keys(), *list(fields.values())[:20]])
    for kind, pattern in _P0_ADAPTER_INFER_PATTERNS:
        if re.search(pattern, hay, re.I):
            return kind
    return ""


def _explicit_kind(fields: Dict[str, str]) -> str:
    """Use normalized product/source fields before falling back to broad regex."""
    for key in ("p0kind", "logtype", "sourcetype", "source", "type", "product", "category"):
        value = fields.get(key, "").strip().lower()
        if not value:
            continue
        compact = _norm_key(value)
        if compact and compact in _P0_ADAPTER_ALIAS_MAP:
            return _P0_ADAPTER_ALIAS_MAP[compact]
        for alias, kind in _P0_ADAPTER_ALIAS_MAP.items():
            if alias and alias in compact:
                return kind
    return ""


def _normalize_record(record: Dict[str, Any]) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for key, value in record.items():
        norm = _norm_key(str(key))
        if not norm:
            continue
        if isinstance(value, (dict, list)):
            text = json.dumps(value, ensure_ascii=False)
        elif value is None:
            text = ""
        else:
            text = str(value)
        fields[norm] = text.strip()
    return fields


@lru_cache(maxsize=4096)
def _norm_key(key: str) -> str:
    return re.sub(r'[^a-z0-9]', '', key.lower())


def _field(fields: Dict[str, str], *names: str) -> str:
    for name in names:
        key = _norm_key(name)
        if key in fields and fields[key] not in ("", "-", "null", "None"):
            return fields[key]
    return ""


def _src_ip(fields: Dict[str, str]) -> str:
    value = _field(
        fields, "src_ip", "source_ip", "client_ip", "remote_addr", "real_ip",
        "xff", "x_forwarded_for", "src", "src_addr", "source_addr",
        "client_addr", "sip", "srcip", "sourceaddress",
        "ip", "client", "remoteip",
    )
    return _first_ip(value)


def _dst_ip(fields: Dict[str, str]) -> str:
    value = _field(
        fields, "dst_ip", "dest_ip", "destination_ip", "dst", "dip", "dstip",
        "destinationaddress", "server_ip", "target_ip", "target",
    )
    return _first_ip(value)


def _first_ip(value: str) -> str:
    m = _IP_RE.search(value or "")
    return m.group(0) if m else ""


def _user(fields: Dict[str, str]) -> str:
    return _field(fields, "user", "username", "user_name", "account", "login_user", "uid", "operator", "actor", "principal")


def _timestamp(fields: Dict[str, str]) -> str:
    value = _field(fields, "timestamp", "time", "event_time", "eventtime", "log_time", "logtime", "datetime", "date", "start_time", "starttime", "@timestamp", "occur_time")
    if not value:
        return ""
    if re.fullmatch(r'\d{13}', value):
        return datetime.datetime.fromtimestamp(int(value) / 1000).isoformat(timespec="seconds")
    if re.fullmatch(r'\d{10}', value):
        return datetime.datetime.fromtimestamp(int(value)).isoformat(timespec="seconds")
    return normalize_timestamp(value)


def _details(fields: Dict[str, str], kind: str) -> Dict[str, str]:
    details = {
        "p0_kind": kind,
        "source_type": kind,
        "src_ip": _src_ip(fields),
        "dst_ip": _dst_ip(fields),
        "asset": _field(fields, "asset", "target", "target_host", "targethost", "dst_host", "dsthost", "server", "host", "hostname", "endpoint", "device"),
        "account": _user(fields),
        "action": _field(fields, "action", "disposition", "policy_action", "policyaction", "event", "operation"),
        "status": _field(fields, "status", "status_code", "statuscode", "response_code", "responsecode", "result", "outcome"),
        "url": _field(fields, "url", "uri", "path", "request_url", "requesturl", "request_uri", "requesturi", "request", "full_url", "fullurl"),
        "command": _field(fields, "command", "cmd", "command_line", "commandline", "input"),
        "process": _field(fields, "process", "process_name", "processname", "image", "filename", "program"),
        "bytes_out": str(_bytes_out(
            fields,
            extra_names=_PROXY_BYTES_OUT_NAMES if kind == "proxy" else (),
            generic_names=("bytes",),
        )),
        "direction": _direction(fields),
        "session_id": _field(fields, "session_id", "sessionid", "sid", "session"),
        "trace_id": _field(fields, "trace_id", "traceid", "request_id", "requestid"),
    }
    for key, value in list(fields.items())[:40]:
        if value:
            details[key] = truncate(value, 500)
    return details


def _make_event(
    prefix: str,
    timestamp: str,
    level: ThreatLevel,
    category: str,
    source: str,
    source_file: str,
    message: str,
    raw_line: str,
    ip: str = "",
    user: str = "",
    host: str = "",
    process: str = "",
    port: Optional[int] = None,
    details: Optional[Dict[str, str]] = None,
    tags: Optional[List[str]] = None,
    mitre_attack: Optional[str] = None,
    rule_name: Optional[str] = None,
    rule_id: Optional[str] = None,
) -> LogEvent:
    return LogEvent(
        id=gen_id(prefix),
        timestamp=timestamp,
        level=level,
        category=category,
        source=source,
        source_file=source_file,
        message=message,
        raw_line=raw_line,
        ip=ip or None,
        user=user or None,
        host=host or None,
        process=process or None,
        port=port,
        details=details or {},
        tags=tags or [],
        mitre_attack=mitre_attack,
        rule_name=rule_name,
        rule_id=rule_id,
    )


def _join_values(fields: Dict[str, str], keys: Tuple[str, ...]) -> str:
    values = []
    for key in keys:
        val = _field(fields, key)
        if val:
            values.append(val)
    return " ".join(values)


def _severity_to_level(value: str, default: ThreatLevel = ThreatLevel.INFO) -> ThreatLevel:
    val = (value or "").lower()
    if val in ("critical", "crit", "fatal", "严重", "紧急") or val == "5":
        return ThreatLevel.CRITICAL
    if val in ("high", "error", "高危", "高") or val == "4":
        return ThreatLevel.HIGH
    if val in ("medium", "warn", "warning", "中危", "中") or val == "3":
        return ThreatLevel.MEDIUM
    if val in ("low", "notice", "低危", "低") or val == "2":
        return ThreatLevel.LOW
    if val in ("info", "informational", "信息") or val == "1":
        return ThreatLevel.INFO
    return default


def _is_failed(text: str) -> bool:
    return bool(re.search(r'fail|failed|failure|deny|denied|invalid|locked|error|失败|拒绝|无效|锁定', text or "", re.I))


def _is_success(text: str) -> bool:
    return bool(re.search(r'success|successful|accept|allow|passed|ok|成功|允许|通过', text or "", re.I))


def _is_block_action(text: str) -> bool:
    return bool(re.search(r'block|deny|drop|reject|reset|拦截|阻断|拒绝|丢弃', text or "", re.I))


def _is_allow_action(text: str) -> bool:
    return bool(re.search(r'allow|accept|permit|pass|forward|success|允许|放行|通过', text or "", re.I))


def _is_bastion_file_transfer(text: str) -> bool:
    return bool(re.search(
        r'\b(?:file[_ -]?(?:upload|download|transfer)|upload|download|scp|sftp)\b|文件|传输|上传|下载',
        text or "",
        re.I,
    ))


def _int_field(fields: Dict[str, str], *names: str) -> int:
    value = _field(fields, *names)
    if not value:
        return 0
    m = re.search(r'\d+', value.replace(",", ""))
    return int(m.group(0)) if m else 0


_COMMON_BYTES_OUT_NAMES = (
    "bytes_out", "bytesout",
    "sent_bytes", "sentbytes", "bytes_sent", "bytessent",
    "upload_bytes", "uploadbytes", "bytes_uploaded", "bytesuploaded",
    "out_bytes", "outbytes", "tx_bytes", "txbytes",
    "request_bytes", "requestbytes",
)
_PROXY_BYTES_OUT_NAMES = (
    "cs_bytes", "csbytes",
    "client_bytes", "clientbytes",
    "client_to_server_bytes", "clienttoserverbytes",
    "c2s_bytes", "c2sbytes",
    "request_body_bytes", "requestbodybytes",
    "req_body_bytes", "reqbodybytes",
)
_DIRECTIONAL_BYTES_OUT_NAMES = (
    "orig_bytes", "origbytes",
    "origin_bytes", "originbytes",
    "originator_bytes", "originatorbytes",
)


def _bytes_out(
    fields: Dict[str, str],
    extra_names: Tuple[str, ...] = (),
    generic_names: Tuple[str, ...] = (),
) -> int:
    direction = _direction(fields)
    if direction and _is_inbound_direction(direction):
        return 0
    explicit = _int_field(
        fields,
        *(_COMMON_BYTES_OUT_NAMES + extra_names),
    )
    if explicit:
        return explicit
    if direction and _is_outbound_direction(direction):
        return _int_field(fields, *(_DIRECTIONAL_BYTES_OUT_NAMES + generic_names))
    return 0


def _direction(fields: Dict[str, str]) -> str:
    return _field(
        fields,
        "direction", "dir", "flow_direction", "flowdirection",
        "traffic_direction", "trafficdirection",
        "session_direction", "sessiondirection",
    )


def _is_outbound_direction(value: str) -> bool:
    return bool(re.search(
        r'\b(?:out|outbound|egress|upload|client[_ -]?to[_ -]?server|c2s)\b|出站|出向|外联|上行|上传|流出',
        value or "",
        re.I,
    ))


def _is_inbound_direction(value: str) -> bool:
    return bool(re.search(
        r'\b(?:in|inbound|ingress|download|server[_ -]?to[_ -]?client|s2c)\b|入站|入向|下行|下载|流入',
        value or "",
        re.I,
    ))


def _domain_from_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url if "://" in url else "http://" + url)
    return parsed.hostname or ""


def _looks_like_json_record(sample: str) -> bool:
    stripped = sample.lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


def _looks_like_csv_header(sample: str) -> bool:
    first = sample.splitlines()[0] if sample.splitlines() else ""
    if first.lstrip().startswith(("{", "[")):
        return False
    if "," not in first:
        return False
    lower = first.lower()
    return sum(1 for hint in _P0_FIELD_HINTS if hint in lower) >= 2


_P0_ADAPTERS: Tuple[P0Adapter, ...] = (
    P0Adapter(
        kind="waf",
        source_label="WAF",
        build=_build_waf_event,
        aliases=("waf", "webfirewall", "websecurity", "modsecurity", "web firewall"),
        infer_pattern=r'\bwaf\b|web.?security|modsecurity|web.?firewall|attacktype|ruleid|rulename',
    ),
    P0Adapter(
        kind="vpn",
        source_label="VPN",
        build=_build_vpn_event,
        aliases=("vpn", "sslvpn", "openvpn", "forticlient", "zero trust", "ztna"),
        infer_pattern=r'\bvpn\b|sslvpn|openvpn|forticlient|zero.?trust|ztna|mfa',
    ),
    P0Adapter(
        kind="edr",
        source_label="EDR/XDR",
        build=_build_edr_event,
        aliases=("edr", "xdr", "hids", "antivirus", "endpoint"),
        infer_pattern=r'\bedr\b|\bxdr\b|hids|antivirus|endpoint|threatname|alertname|processname',
    ),
    P0Adapter(
        kind="dns",
        source_label="DNS",
        build=_build_dns_event,
        aliases=("dns",),
        infer_pattern=r'\bdns\b|queryname|qname|fqdn|rcode',
    ),
    P0Adapter(
        kind="proxy",
        source_label="Proxy/SWG",
        build=_build_proxy_event,
        aliases=("proxy", "swg", "web gateway", "上网行为"),
        infer_pattern=r'\bproxy\b|swg|上网行为|\burl\b|fullurl|web.?gateway',
    ),
    P0Adapter(
        kind="firewall",
        source_label="Firewall/NAT",
        build=_build_firewall_event,
        aliases=("firewall", "fw", "nat", "session"),
        infer_pattern=r'firewall|\bfw\b|\bnat\b|session|srcport|dstport|dport|destinationport',
    ),
    P0Adapter(
        kind="bastion",
        source_label="Bastion",
        build=_build_bastion_event,
        aliases=("bastion", "jumpserver", "jumphost", "jump host", "堡垒"),
        infer_pattern=r'bastion|jumpserver|jump.?host|堡垒|command.?audit|session.?audit',
    ),
    P0Adapter(
        kind="app",
        source_label="Application",
        build=_build_app_event,
        aliases=("application", "app", "spring", "tomcat"),
        infer_pattern=r'application|spring|tomcat|appname|exception|stacktrace|traceid',
    ),
)
_P0_ADAPTER_BUILDERS: Dict[str, P0Builder] = {adapter.kind: adapter.build for adapter in _P0_ADAPTERS}
_P0_ADAPTER_ALIAS_MAP: Dict[str, str] = {
    _norm_key(alias): adapter.kind
    for adapter in _P0_ADAPTERS
    for alias in adapter.aliases
    if _norm_key(alias)
}
_P0_ADAPTER_ALIAS_MAP.update(_KIND_FAST_ALIASES)
_P0_ADAPTER_INFER_PATTERNS: Tuple[Tuple[str, str], ...] = tuple(
    (adapter.kind, adapter.infer_pattern) for adapter in _P0_ADAPTERS
)


def list_p0_adapter_kinds() -> List[str]:
    """Return registered P0 adapter kinds for tests, docs, and future CLI surfacing."""
    return [adapter.kind for adapter in _P0_ADAPTERS]
