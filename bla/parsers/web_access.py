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
from ..models import LogEvent, ParseResult, ThreatLevel
from ..rules import get_web_attack_rules
from ..utils.helpers import file_size, gen_id, iter_file_lines, normalize_timestamp
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

_COMMAND_WORDS_RE = (
    r'(?:whoami|id|uname|cat|curl|wget|bash|sh|nc|netcat|python|perl|php|'
    r'powershell|cmd(?:\.exe)?)'
)
_COMMAND_SEPARATOR_RE = r'(?:;|%3b|\|\||%7c%7c|&&|%26%26)'
_COMMAND_PARAM_RE = r'(?:cmd|exec|command|shell|payload|run)\s*='
_COMMAND_EXEC_RE = (
    rf'(?:{_COMMAND_PARAM_RE}|{_COMMAND_SEPARATOR_RE}\s*{_COMMAND_WORDS_RE}\b|'
    rf'=\s*{_COMMAND_WORDS_RE}\b)'
)

_SUSPICIOUS_GENERIC = re.compile(
    r'(\.\./|%2e%2e|%252e|%2f%2e%2e|%5c%2e%2e|'
    rf'{_COMMAND_EXEC_RE}|/etc/passwd|'
    r'\b(select|union)\b.{0,40}\b(select|from)\b|'
    r'(\bor\b|\band\b)\s+\d+\s*=\s*\d+|'
    r'1\s*=\s*1|'
    r'(\bexec\s*\(|\bxp_cmdshell\b))',  # 仅匹配 exec( 调用，避免路径里 "exec" 单词误报
    re.I
)

# 命名 Web 攻击规则已统一迁入 ``bla/rules/web_attacks.yaml``（v1.4.5）。
# 解析器只负责"产出事实"，命名攻击的命中与元数据集中在规则层，便于研究员扩展
# 与 ``validate-rules`` 校验。``_SUSPICIOUS_GENERIC`` 作为通用兜底启发式仍保留在解析
# 阶段，用于在没有命中具名规则时标记可疑参数/命令特征。


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
        buckets = data["minute_buckets"]
        peak_per_minute = max(buckets.values()) if buckets else 0
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


def _parse_access_line(
    line: str,
    source_file: str,
    ip_stats: Dict,
) -> Optional[LogEvent]:
    m = _COMBINED_RE.match(line)
    if not m:
        return None

    ip, user, ts_raw, request, status_str, size_str, referer, ua = m.groups()
    status = int(status_str) if status_str.isdigit() else 0
    ts     = normalize_timestamp(ts_raw)

    # 解析请求。攻击 payload 里经常有空格，不能简单 split 后只取第二段。
    method, path = _split_request(request)
    decoded_path = _decode_url(path)
    display_path = decoded_path or path
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
    event_msg = f"{method} {display_path} -> {status}"

    # 攻击模式检测
    # request 已包含原始 path，单独再拼一次会让"需出现两次"的规则（如 SQLi 的
    # select...select）对同一良性取值自匹配而误报；decoded_path 仅在与原始 path 不同
    # （即存在 URL 编码）时才追加，用于揭示被编码的攻击载荷。
    check_parts = [request or "", _decode_url(ua or ""), _decode_url(referer or "")]
    if decoded_path and decoded_path != path:
        check_parts.append(decoded_path)
    check_str = " ".join(part for part in check_parts if part)
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
            elif _is_investigative_baseline(method, path, decoded_path, ua or "", referer or ""):
                level     = ThreatLevel.INFO
                cat       = "Web"
                tags      = ["web-baseline"]
                rule_name = "关键 Web 基线访问"
                event_msg = f"{method} {display_path} -> {status}"
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

        elif not tags and 200 <= status < 400:
            # 仅保留 2xx 成功访问作为"事发现场"基线上下文；3xx 跳转（如 301/304）
            # 属于纯噪声，不纳入基线，避免把首页跳转误留进事件表。
            if 200 <= status < 300 and _is_investigative_baseline(
                method, path, decoded_path, ua or "", referer or ""
            ):
                level     = ThreatLevel.INFO
                cat       = "Web"
                tags      = ["web-baseline"]
                rule_name = "关键 Web 基线访问"
                event_msg = f"{method} {display_path} -> {status}"
            else:
                return None  # 过滤普通正常成功请求与跳转

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


def _is_investigative_baseline(method: str, path: str, decoded_path: str, ua: str, referer: str) -> bool:
    """Keep successful-but-investigative Web requests for incident reconstruction.

    BLA intentionally filters ordinary 2xx/3xx traffic to avoid huge event
    tables.  Incident reconstruction still needs a narrow baseline around
    homepage, login, upload, and file-management activity so the report can
    explain the case without forcing users back into raw logs.  Generic admin
    page views are not retained here because they can be extremely repetitive;
    admin exploit/file-operation requests are still retained by attack rules or
    upload/file-management matching.
    """
    candidate = " ".join([path or "", decoded_path or "", ua or "", referer or ""])
    base = (decoded_path or path or "").split("?", 1)[0]
    if method.upper() in {"GET", "HEAD"} and base == "/":
        return True
    return bool(
        re.search(r"(/login\b|/login\.php\b|/wp-login\.php\b|signin|auth)", candidate, re.I)
        or re.search(r"(/upload\b|/uploads?/|/uploadfile/|rest-api=upload|[?&]cmd=mkfile\b|[?&]name=[^&\s]*shell)", candidate, re.I)
    )


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
