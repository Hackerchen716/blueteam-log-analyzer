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
from typing import List, Dict, Optional, Tuple
from urllib.parse import unquote_plus

from ..models import LogEvent, ParseResult, ParseStats, ThreatLevel
from ..utils.helpers import gen_id, normalize_timestamp, truncate
from .stats import compute_stats

# Combined Log Format
_COMBINED_RE = re.compile(
    r'^([\d.]+)\s+'                      # IP
    r'\S+\s+'                            # ident
    r'(\S+)\s+'                          # user
    r'\[([^\]]+)\]\s+'                   # timestamp
    r'"([^"]*)"\s+'                      # request
    r'(\d+)\s+'                          # status
    r'(\d+|-)\s*'                        # bytes
    r'(?:"([^"]*)")?\s*'                 # referer
    r'(?:"([^"]*)")?'                    # user-agent
)

# 攻击模式库（参考 OSTE-WLA / ModSecurity）
_ATTACK_PATTERNS: List[Tuple[re.Pattern, ThreatLevel, str, str, str, List[str]]] = [
    # (pattern, level, category, name, mitre, tags)
    (re.compile(r'(\.\.|%2e%2e|%252e|\.\.%2f|\.\.%5c)', re.I),
     ThreatLevel.HIGH, "Web攻击", "路径遍历", "T1083", ["path-traversal", "lfi"]),

    (re.compile(r'(union.{1,20}select|select.{1,50}from|insert.{1,20}into|'
                r'drop.{1,20}table|exec\s*\(|xp_cmdshell|'
                r';\s*drop|;\s*delete|;\s*update|'
                r'\bor\b\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+|'
                r'\band\b\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+)', re.I),
     ThreatLevel.CRITICAL, "Web攻击", "SQL注入", "T1190", ["sqli", "injection"]),

    (re.compile(r'(<script|javascript:|onerror\s*=|onload\s*=|'
                r'alert\s*\(|document\.cookie|<iframe)', re.I),
     ThreatLevel.HIGH, "Web攻击", "XSS攻击", "T1059.007", ["xss", "injection"]),

    (re.compile(r'(\/etc\/passwd|\/etc\/shadow|\/proc\/self|'
                r'\/windows\/system32|c:\\windows)', re.I),
     ThreatLevel.CRITICAL, "Web攻击", "LFI/RFI", "T1083", ["lfi", "rfi", "path-traversal"]),

    (re.compile(r'(cmd=|exec=|system\s*\(|passthru|shell_exec|'
                r'phpinfo\s*\(|eval\s*\(|assert\s*\()', re.I),
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
                r'burp.?suite|dirbuster|gobuster|wfuzz|hydra|medusa|'
                r'metasploit|w3af)', re.I),
     ThreatLevel.HIGH, "扫描器", "安全扫描器", "T1595", ["scanner", "reconnaissance"]),
]


def parse_web_access(content: str, source_file: str) -> ParseResult:
    t0 = time.time()
    lines = content.splitlines()
    events: List[LogEvent] = []

    # 第一遍：解析所有请求
    ip_stats: Dict[str, Dict] = defaultdict(lambda: {
        "count": 0, "errors": 0, "events": [], "first_ts": "",
        "last_ts": "", "sample": "", "user_agent": "",
    })

    for line in lines:
        if not line.strip():
            continue
        ev = _parse_access_line(line, source_file, ip_stats)
        if ev:
            events.append(ev)
            if ev.ip:
                ip_stats[ev.ip]["events"].append(ev)

    # 第二遍：DDoS / 扫描检测
    for ip, data in ip_stats.items():
        count = data["count"]
        evts  = data["events"]
        if count >= 1000 and not any("ddos" in e.tags for e in evts):
            if not evts:
                evts.append(_make_volume_event(ip, data, source_file, ThreatLevel.CRITICAL, "DDoS/高频请求", "ddos"))
                events.append(evts[-1])
            for e in evts:
                e.level = ThreatLevel.CRITICAL
                if "ddos" not in e.tags:
                    e.tags.append("ddos")
                e.rule_name = "DDoS 攻击"
        elif count >= 100 and not any("scanning" in e.tags or "web-attack" in e.tags for e in evts):
            if not evts:
                evts.append(_make_volume_event(ip, data, source_file, ThreatLevel.MEDIUM, "自动化扫描/高频访问", "scanning"))
                events.append(evts[-1])
            for e in evts:
                if e.level.score < ThreatLevel.MEDIUM.score:
                    e.level = ThreatLevel.MEDIUM
                if "scanning" not in e.tags:
                    e.tags.append("scanning")

    stats = compute_stats(events)
    return ParseResult(
        file_name     = source_file,
        log_type      = "Web Access Log (Apache/Nginx)",
        events        = events,
        stats         = stats,
        parse_time_ms = (time.time() - t0) * 1000,
        file_size_bytes = len(content.encode()),
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

    # 默认级别
    level     = ThreatLevel.INFO
    cat       = "Web"
    tags: List[str] = []
    mitre: Optional[str] = None
    rule_name: Optional[str] = None
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

    for pattern, lvl, category, name, attack_id, attack_tags in _ATTACK_PATTERNS:
        if pattern.search(check_str):
            level     = lvl
            cat       = category
            tags      = list(dict.fromkeys(attack_tags + ["web-attack"]))
            mitre     = attack_id
            rule_name = name
            event_msg = f"{name}: {method} {truncate(display_path, 100)} -> {status}"
            attack_detected = True
            break

    if not attack_detected:
        # HTTP 错误码
        if status == 401 or status == 403:
            level     = ThreatLevel.MEDIUM
            cat       = "访问控制"
            tags      = ["access-denied", "authentication"]
            rule_name = f"HTTP {status} 访问拒绝"
            event_msg = f"访问拒绝 {status}: {display_path}"

        elif status == 404:
            # 只标记可疑 404
            if re.search(r'\.(php|asp|aspx|jsp|cgi|sh|py|rb|pl)\b', display_path, re.I):
                level     = ThreatLevel.LOW
                cat       = "信息收集"
                tags      = ["recon", "404"]
                rule_name = "脚本文件探测"
                event_msg = f"404 探测: {display_path}"
            else:
                return None  # 过滤普通 404

        elif status >= 500:
            level     = ThreatLevel.MEDIUM
            cat       = "服务器错误"
            tags      = ["server-error"]
            rule_name = f"HTTP {status} 服务器错误"
            event_msg = f"服务器错误 {status}: {display_path}"

        elif 200 <= status < 300:
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
        },
        tags        = tags,
        mitre_attack= mitre,
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
) -> LogEvent:
    count = data.get("count", 0)
    errors = data.get("errors", 0)
    first_ts = data.get("first_ts", "")
    last_ts = data.get("last_ts", "")
    sample = data.get("sample", "")
    return LogEvent(
        id          = gen_id("web"),
        timestamp   = last_ts or first_ts,
        level       = level,
        category    = "流量异常",
        source      = "Web (volume)",
        source_file = source_file,
        message     = f"{rule_name}: {ip} 请求 {count} 次，错误 {errors} 次",
        raw_line    = sample,
        ip          = ip,
        details     = {
            "count": str(count),
            "errors": str(errors),
            "first_ts": first_ts,
            "last_ts": last_ts,
            "sample": sample,
            "user_agent": data.get("user_agent", ""),
        },
        tags        = [tag, "reconnaissance"],
        mitre_attack= "T1595",
        rule_name   = rule_name,
    )
