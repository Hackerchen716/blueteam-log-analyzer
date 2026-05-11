"""
Web 访问日志解析器
支持格式:
  - Apache/Nginx Combined Log Format
  - Common Log Format

检测能力:
  - SQL 注入 / XSS / LFI/RFI / 命令注入
  - Webshell 特征
  - 安全扫描器识别
  - 敏感文件探测
  - DDoS / 自动化扫描
"""

from __future__ import annotations
import re
import time
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote_plus

from .. import config
from ..models import LogEvent, ParseResult, ParseStats, ThreatLevel
from ..rules import get_web_attack_rules
from ..utils.helpers import file_size, gen_id, iter_file_lines, normalize_timestamp, truncate
from .stats import compute_stats

# Combined Log Format
_COMBINED_RE = re.compile(
    r'^([0-9a-fA-F:.]+)\s+'              # IP (IPv4/IPv6)
    r'\S+\s+'                            # ident
    r'(\S+)\s+'                          # user
    r'\[([^\]]+)\]\s+'                   # timestamp
    r'"([^"]*)"\s+'                      # request
    r'(\d+)\s+'                          # status
    r'(\d+|-)\s*'                        # bytes
    r'(?:"([^"]*)")?\s*'                 # referer
    r'(?:"([^"]*)")?'                    # user-agent
)

_SUSPICIOUS_GENERIC = re.compile(
    r'(\.\./|%2e%2e|%252e|%2f%2e%2e|%5c%2e%2e|'
    r'\bwhoami\b|\bid\b|\buname\b|\bcat\b|/etc/passwd|'
    r'\b(select|union)\b.{0,40}\b(select|from)\b|'
    r'(\bor\b|\band\b)\s+\d+\s*=\s*\d+|'
    r'1\s*=\s*1|'
    r'(\bexec\b|\bxp_cmdshell\b)|'
    r'(;|%3b|\|\||%7c%7c|&&|%26%26))',
    re.I
)

# 攻击模式库（参考 OSTE-WLA / ModSecurity）
_ATTACK_PATTERNS: List[Tuple[re.Pattern, ThreatLevel, str, str, str, List[str]]] = [
    # (pattern, level, category, name, mitre, tags)
    (re.compile(r'(\.\.|%2e%2e|%252e|\.\.%2f|\.\.%5c)', re.I),
     ThreatLevel.HIGH, "Web攻击", "路径遍历", "T1083", ["path-traversal", "lfi"]),

    (re.compile(r'(union.{1,20}select|select.{1,50}from|insert.{1,20}into|'
                r'drop.{1,20}table|exec\s*\(|xp_cmdshell|'
                r';\s*drop|;\s*delete|;\s*update|'
                r'(\bor\b|\band\b)\s+\d+\s*=\s*\d+|'
                r'1\s*=\s*1)', re.I),
     ThreatLevel.CRITICAL, "Web攻击", "SQL注入", "T1190", ["sqli", "injection"]),

    (re.compile(r'(<script|javascript:|onerror\s*=|onload\s*=|'
                r'alert\s*\(|document\.cookie|<iframe)', re.I),
     ThreatLevel.HIGH, "Web攻击", "XSS攻击", "T1059.007", ["xss", "injection"]),

    (re.compile(r'(\/etc\/passwd|\/etc\/shadow|\/proc\/self|'
                r'\/windows\/system32|c:\\windows)', re.I),
     ThreatLevel.CRITICAL, "Web攻击", "LFI/RFI", "T1083", ["lfi", "rfi", "path-traversal"]),

    (re.compile(r'(cmd=|exec=|system\s*\(|passthru|shell_exec|'
                r'phpinfo\s*\(|eval\s*\(|assert\s*\(|'
                r'\bwhoami\b|\bid\b|\buname\b)', re.I),
     ThreatLevel.CRITICAL, "Web攻击", "命令注入/代码执行", "T1059", ["rce", "command-injection"]),

    (re.compile(r'(\.php\?.*=http|\.php\?.*=ftp|include\s*\(|require\s*\()', re.I),
     ThreatLevel.HIGH, "Web攻击", "RFI攻击", "T1190", ["rfi", "injection"]),

    (re.compile(r'(\bsleep\s*\(\d+\)|\bwaitfor\s+delay\b|'
                r'benchmark\s*\(|pg_sleep)', re.I),
     ThreatLevel.CRITICAL, "Web攻击", "时间盲注", "T1190", ["sqli", "blind-injection"]),

    (re.compile(r'(base64_decode|gzinflate|str_rot13|'
                r'eval\s*\(.*base64|chr\s*\(.*\.\s*chr)', re.I),
     ThreatLevel.HIGH, "Web攻击", "Webshell特征", "T1505.003", ["webshell", "backdoor"]),

    (re.compile(r'((?:/|%2f)(?:upload|uploads|static|assets|cache|tmp|data|images?)/[^?\s"]+\.(?:php|jsp|jspx|asp|aspx|ashx)|'
                r'(?:cmd|exec|pass|pwd|shell|command)=|'
                r'(?:behinder|冰蝎|godzilla|哥斯拉|antsword|蚁剑|caidao|菜刀))', re.I),
     ThreatLevel.CRITICAL, "Web攻击", "Webshell访问/管理工具", "T1505.003",
     ["webshell", "backdoor", "cn-hvv", "web-attack"]),

    (re.compile(r'(rememberme=|deleteMe|shiro|jndi:ldap|jndi:rmi|jndi:dns|'
                r'fastjson|@type=|autoType|struts2|ognl|memberAccess|'
                r'thinkphp|invokefunction|call_user_func|weblogic|wls-wsat|'
                r'/_async/|/console/login/LoginForm.jsp|spring4shell|class\.module\.classLoader|'
                r'actuator/(?:env|heapdump|jolokia|gateway))', re.I),
     ThreatLevel.CRITICAL, "Web攻击", "国内高频漏洞利用", "T1190",
     ["cn-hvv", "exploit", "web-attack"]),

    (re.compile(r'(\.\.;\/|%00|null.?byte|%0d%0a|crlf)', re.I),
     ThreatLevel.MEDIUM, "Web攻击", "路径/编码绕过", "T1140", ["bypass", "encoding"]),

    (re.compile(r'(wp-admin|wp-login|phpmyadmin|\.env|\.git\/|\.svn\/|'
                r'backup\.sql|config\.php|web\.config|\.htaccess)', re.I),
     ThreatLevel.MEDIUM, "信息收集", "敏感文件探测", "T1083", ["recon", "sensitive-file"]),

    (re.compile(r'(nikto|sqlmap|nmap|masscan|nessus|openvas|acunetix|'
                r'burp.?suite|dirbuster|gobuster|dirsearch|ffuf|feroxbuster|wfuzz|hydra|medusa|'
                r'metasploit|w3af|python-requests|curl/|\bcurl\b|wget/|\bwget\b)', re.I),
     ThreatLevel.HIGH, "扫描器", "安全扫描器", "T1595", ["scanner", "reconnaissance"]),
]


def parse_web_access(content: str, source_file: str) -> ParseResult:
    return parse_web_access_lines(
        content.splitlines(),
        source_file,
        file_size_bytes=len(content.encode()),
    )


def parse_web_access_file(path: str, source_file: Optional[str] = None) -> ParseResult:
    """从文件逐行解析 Web access log，适配较大的访问日志。"""
    return parse_web_access_lines(
        iter_file_lines(path),
        source_file or path,
        file_size_bytes=file_size(path),
    )


def parse_web_access_lines(
    lines: Iterable[str],
    source_file: str,
    file_size_bytes: int = 0,
) -> ParseResult:
    t0 = time.time()
    events: List[LogEvent] = []

    # 第一遍：解析所有请求。
    # minute_buckets 用来支持基于时间窗口的 DDoS / 扫描判定，避免把"日累计
    # 几千次但分散一整天"的合法 CDN/健康检查误报为 DDoS。
    ip_stats: Dict[str, Dict] = defaultdict(lambda: {
        "count": 0, "errors": 0, "events": [], "first_ts": "",
        "last_ts": "", "sample": "", "user_agent": "",
        "minute_buckets": defaultdict(int),
    })

    for line in lines:
        if not line.strip():
            continue
        ev = _parse_access_line(line, source_file, ip_stats)
        if ev:
            events.append(ev)
            if ev.ip:
                ip_stats[ev.ip]["events"].append(ev)

    # 第二遍：基于时间窗口的 DDoS / 扫描标记。
    # 这里只追加一个独立的 volume 事件（category="流量异常"），不再回头修改
    # 已有的攻击事件——告警阶段统一由 :func:`bla.detection.engine.detect_reconnaissance`
    # 基于 volume 事件出 RECON-003/004 告警，避免规则在解析层和告警层各算一遍。
    for ip, data in ip_stats.items():
        count = data["count"]
        evts  = data["events"]
        buckets = data["minute_buckets"]
        peak_per_minute = max(buckets.values()) if buckets else 0
        # 该 IP 已经被识别为 Web 攻击（SQLi/XSS/LFI 等），让攻击告警走专门的
        # detect_web_attacks 路径，不再叠加 volume 噪音事件。
        if any("web-attack" in e.tags for e in evts):
            continue
        if peak_per_minute >= config.THRESHOLDS.ddos_peak_per_minute and count >= config.THRESHOLDS.ddos_min_total:
            events.append(_make_volume_event(
                ip, data, source_file, ThreatLevel.CRITICAL,
                "DDoS/高频请求", "ddos", peak_per_minute,
            ))
        elif peak_per_minute >= config.THRESHOLDS.scanning_peak_per_minute or count >= config.THRESHOLDS.scanning_min_total:
            events.append(_make_volume_event(
                ip, data, source_file, ThreatLevel.MEDIUM,
                "自动化扫描/高频访问", "scanning", peak_per_minute,
            ))

    stats = compute_stats(events)
    return ParseResult(
        file_name     = source_file,
        log_type      = "Web Access Log (Apache/Nginx)",
        events        = events,
        stats         = stats,
        parse_time_ms = (time.time() - t0) * 1000,
        file_size_bytes = file_size_bytes,
    )


def _parse_access_line(line: str, source_file: str, ip_stats: Dict) -> Optional[LogEvent]:
    m = _COMBINED_RE.match(line)
    if not m:
        return None

    ip, user, ts_raw, request, status_str, size_str, referer, ua = m.groups()
    status = int(status_str) if status_str.isdigit() else 0
    ts     = normalize_timestamp(ts_raw)

    # 解析请求。攻击 payload 里经常有空格，不能简单 split 后只取第二段。
    method, path = _split_request(request)
    decoded_path = _decode_url(path)

    # 统计
    ip_stats[ip]["count"] += 1
    if status >= 400:
        ip_stats[ip]["errors"] += 1
    if not ip_stats[ip]["first_ts"]:
        ip_stats[ip]["first_ts"] = ts
    ip_stats[ip]["last_ts"] = ts
    if not ip_stats[ip]["sample"]:
        ip_stats[ip]["sample"] = f"{method} {path} -> {status}"
    if ua and not ip_stats[ip]["user_agent"]:
        ip_stats[ip]["user_agent"] = ua
    # 分钟桶：取 ISO 时间戳前 16 位 "YYYY-MM-DDTHH:MM" 作为 key
    if ts and len(ts) >= 16:
        ip_stats[ip]["minute_buckets"][ts[:16]] += 1

    # 默认级别
    level     = ThreatLevel.INFO
    cat       = "Web"
    tags: List[str] = []
    mitre: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    rule_metadata: Dict[str, str] = {}
    display_path = decoded_path or path
    event_msg = f"{method} {display_path} -> {status}"

    # 攻击模式检测
    check_str = " ".join([
        request or "",
        path or "",
        decoded_path or "",
        _decode_url(ua or ""),
        _decode_url(referer or ""),
    ])
    attack_detected = False

    for rule in get_web_attack_rules():
        if rule.pattern.search(check_str):
            level     = rule.level
            cat       = rule.category
            tags      = list(dict.fromkeys(rule.tags + ["web-attack"]))
            mitre     = rule.mitre
            rule_id   = rule.rule_id
            rule_name = rule.name
            rule_metadata = {
                "rule_confidence": rule.confidence,
                "rule_remediation": rule.remediation,
                "rule_false_positive_hints": "|".join(rule.false_positive_hints or []),
                "rule_evidence_fields": "|".join(rule.evidence_fields or []),
            }
            event_msg = f"{rule.name}: {method} {display_path} -> {status}"
            attack_detected = True
            break

    for pattern, lvl, category, name, attack_id, attack_tags in _ATTACK_PATTERNS:
        if attack_detected:
            break
        if pattern.search(check_str):
            level     = lvl
            cat       = category
            tags      = list(dict.fromkeys(attack_tags + ["web-attack"]))
            mitre     = attack_id
            rule_name = name
            event_msg = f"{name}: {method} {display_path} -> {status}"
            attack_detected = True
            break

    if not attack_detected:
        if method.upper() == "POST":
            if _SUSPICIOUS_GENERIC.search(check_str) or "?" in path:
                level     = ThreatLevel.HIGH if _SUSPICIOUS_GENERIC.search(check_str) else ThreatLevel.MEDIUM
                cat       = "Web攻击"
                tags      = ["suspicious-post", "web-attack"]
                mitre     = "T1190"
                rule_name = "可疑 POST 请求"
                event_msg = f"可疑POST: {display_path} -> {status}"
            elif status >= 400:
                level     = ThreatLevel.MEDIUM
                cat       = "Web"
                tags      = ["post-error"]
                rule_name = f"POST 异常响应 {status}"
                event_msg = f"POST {status}: {display_path}"
            else:
                return None

        if _SUSPICIOUS_GENERIC.search(check_str):
            level     = ThreatLevel.HIGH
            cat       = "Web攻击"
            tags      = ["suspicious-params", "web-attack"]
            mitre     = "T1190"
            rule_name = "可疑参数/命令特征"
            event_msg = f"可疑参数: {method} {display_path} -> {status}"

        # HTTP 错误码
        if not tags and (status == 401 or status == 403):
            level     = ThreatLevel.MEDIUM
            cat       = "访问控制"
            tags      = ["access-denied", "authentication"]
            rule_name = f"HTTP {status} 访问拒绝"
            event_msg = f"访问拒绝 {status}: {display_path}"

        elif not tags and status == 404:
            # 只标记可疑 404
            if re.search(r'\.(php|asp|aspx|jsp|cgi|sh|py|rb|pl)\b', display_path, re.I):
                level     = ThreatLevel.LOW
                cat       = "信息收集"
                tags      = ["recon", "404"]
                rule_name = "脚本文件探测"
                event_msg = f"404 探测: {display_path}"
            else:
                return None  # 过滤普通 404

        elif not tags and status >= 500:
            level     = ThreatLevel.MEDIUM
            cat       = "服务器错误"
            tags      = ["server-error"]
            rule_name = f"HTTP {status} 服务器错误"
            event_msg = f"服务器错误 {status}: {display_path}"

        elif not tags and 200 <= status < 300:
            return None  # 过滤正常成功请求

    return LogEvent(
        id          = gen_id("web"),
        timestamp   = ts,
        level       = level,
        category    = cat,
        source      = f"Web ({method} {status})",
        source_file = source_file,
        message     = event_msg,
        raw_line    = line,
        user        = user if user != "-" else None,
        ip          = ip,
        details     = {
            "method":     method,
            "path":       path,
            "decoded_path": decoded_path,
            "status":     status_str,
            "user_agent": ua or "",
            "referer":    referer or "",
            **rule_metadata,
        },
        tags        = tags,
        mitre_attack= mitre,
        rule_id     = rule_id,
        rule_name   = rule_name,
    )


def _split_request(request: str) -> Tuple[str, str]:
    request = (request or "").strip()
    if not request:
        return "", ""
    m = re.match(r'^(\S+)\s+(.+?)(?:\s+HTTP/\d(?:\.\d)?)?$', request, re.I)
    if not m:
        parts = request.split(None, 1)
        return parts[0], parts[1] if len(parts) > 1 else ""
    return m.group(1), m.group(2)


def _decode_url(value: str) -> str:
    decoded = value or ""
    for _ in range(2):
        nxt = unquote_plus(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    return decoded


def _make_volume_event(
    ip: str,
    data: Dict,
    source_file: str,
    level: ThreatLevel,
    rule_name: str,
    tag: str,
    peak_per_minute: int = 0,
) -> LogEvent:
    count = data.get("count", 0)
    errors = data.get("errors", 0)
    first_ts = data.get("first_ts", "")
    last_ts = data.get("last_ts", "")
    sample = data.get("sample", "")
    msg = f"{rule_name}: {ip} 请求 {count} 次，错误 {errors} 次"
    if peak_per_minute:
        msg += f"（峰值 {peak_per_minute} 次/分钟）"
    return LogEvent(
        id          = gen_id("web"),
        timestamp   = last_ts or first_ts,
        level       = level,
        category    = "流量异常",
        source      = "Web (volume)",
        source_file = source_file,
        message     = msg,
        raw_line    = sample,
        ip          = ip,
        details     = {
            "count": str(count),
            "errors": str(errors),
            "first_ts": first_ts,
            "last_ts": last_ts,
            "sample": sample,
            "user_agent": data.get("user_agent", ""),
            "peak_per_minute": str(peak_per_minute),
        },
        tags        = [tag, "reconnaissance"],
        mitre_attack= "T1595",
        rule_name   = rule_name,
    )
