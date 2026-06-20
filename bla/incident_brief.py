"""Evidence-bounded incident brief generation.

This module turns parsed events and detector alerts into a human-facing
investigation brief.  It is intentionally separate from detection rules: rules
say "what matched"; the brief says "what can be responsibly concluded, what is
still uncertain, and what evidence supports each statement".
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .models import AnalysisSummary, LogEvent, ParseResult
from .utils.helpers import escape_markdown_text, sanitize_report_text


SCRIPT_EXT_RE = re.compile(r"\.(?:php|jsp|jspx|asp|aspx|ashx)(?:$|[?;/])", re.I)
UPLOAD_PATH_RE = re.compile(r"/(?:upload|uploads|uploadfile|files|static|assets|cache|tmp|data|images?)/", re.I)
ADMIN_PATH_RE = re.compile(r"(/admin\b|/admin\.php\b|[?&]m=admin\b|[?&]c=(?:media|admin)\b)", re.I)
LOGIN_PATH_RE = re.compile(r"(/login\b|/login\.php\b|/wp-login\.php\b|signin|auth)", re.I)
UPLOAD_ACTION_RE = re.compile(r"(rest-api=upload|[?&]cmd=mkfile\b|[?&]name=[^&\s]*shell|/upload\.php\b)", re.I)
SCANNER_UA_RE = re.compile(r"(python-requests|curl/|wget/|sqlmap|nikto|nmap|masscan|wpscan|dirsearch|gobuster|ffuf)", re.I)


def ensure_incident_brief(parse_results: List[ParseResult], summary: AnalysisSummary) -> Dict[str, Any]:
    """Attach and return a shared incident brief for all report outputs."""
    if not getattr(summary, "incident_brief", None):
        summary.incident_brief = build_incident_brief(parse_results, summary)
    return summary.incident_brief


def build_incident_brief(parse_results: List[ParseResult], summary: AnalysisSummary) -> Dict[str, Any]:
    records = _event_records(parse_results)
    if not records:
        return _empty_brief(summary)

    action_records = [(record, _classify_record(record)) for record in records]
    by_action: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for record, actions in action_records:
        for action in actions:
            by_action[action].append(record)

    suspected_artifacts = _suspected_artifacts(action_records)
    actor_profiles = _actor_profiles(action_records)
    confirmed_facts = _confirmed_facts(by_action, suspected_artifacts)
    key_timeline = _key_timeline(by_action)
    attack_paths = _attack_paths(by_action, suspected_artifacts)
    findings = _findings(by_action, suspected_artifacts, summary)
    hypotheses = _hypotheses(by_action, suspected_artifacts)
    uncertainties = _uncertainties(by_action, suspected_artifacts)
    next_evidence = _next_evidence(by_action, suspected_artifacts)
    headline = _headline(summary, by_action, suspected_artifacts)

    return {
        "schema": "bla-incident-brief-v1",
        "headline": headline,
        "scope": {
            "files_analyzed": summary.files_analyzed,
            "total_events": summary.total_events,
            "alert_count": len(summary.alerts),
            "incident_count": len(summary.incidents),
            "risk_score": summary.risk_score,
            "risk_level": summary.risk_level.value,
        },
        "confirmed_facts": confirmed_facts,
        "findings": findings,
        "hypotheses": hypotheses,
        "key_timeline": key_timeline,
        "attack_paths": attack_paths,
        "suspected_artifacts": suspected_artifacts,
        "actor_profiles": actor_profiles,
        "uncertainties": uncertainties,
        "next_evidence": next_evidence,
        "evidence_boundary": {
            "basis": "BLA parsed events and detector alerts only",
            "note": "结论只基于当前输入日志；缺失认证、文件系统、进程、数据库或网络流量证据时，报告会保留不确定项。",
        },
    }


def render_incident_brief_markdown(brief: Dict[str, Any]) -> str:
    headline = brief.get("headline", {})
    lines = [
        "# BLA 应急研判摘要",
        "",
        f"## 初步判断：{_md(headline.get('title', '未形成明确攻击研判'))}",
        "",
        f"- **置信度**：{_md(headline.get('confidence', 'low'))}",
        f"- **风险等级**：{_md(brief.get('scope', {}).get('risk_level', '?'))}",
        f"- **风险评分**：{brief.get('scope', {}).get('risk_score', 0)}/100",
        f"- **分析事件**：{brief.get('scope', {}).get('total_events', 0)} 条",
        "",
        _md(headline.get("summary", "")),
        "",
        "## 已确认事实",
        "",
    ]
    lines.extend(_markdown_items(brief.get("confirmed_facts", []), include_evidence=True))
    lines.extend(["", "## 主要发现", ""])
    lines.extend(_markdown_items(brief.get("findings", []), include_evidence=True))
    lines.extend(["", "## 研判假设", ""])
    lines.extend(_markdown_items(brief.get("hypotheses", []), include_evidence=True))
    lines.extend(["", "## 关键案情演化", ""])
    for item in brief.get("key_timeline", []):
        lines.append(f"- **{_md(item.get('phase', '阶段'))}**：{_md(_display_time_range(item.get('time_range', '?')))}，{_md(item.get('summary', ''))}")
        for ev in item.get("evidence", [])[:3]:
            lines.append(f"  - 证据：{_md(_evidence_label(ev))}")
    if not brief.get("key_timeline"):
        lines.append("- （暂无可归纳时间线）")
    attack_paths = brief.get("attack_paths", [])
    lines.extend(["", f"## 攻击路径研判（{len(attack_paths)} 条）", ""])
    if attack_paths:
        for item in attack_paths:
            ips = ", ".join(item.get("source_ips", [])[:5]) or "?"
            entries = ", ".join(item.get("entry_candidates", [])[:5]) or "?"
            artifacts = ", ".join(item.get("artifact_candidates", [])[:5]) or "?"
            lines.append(
                f"- **{_md(item.get('id', '?'))} {_md(item.get('title', '攻击路径'))}**："
                f"{_md(item.get('time_range_text') or _display_time_range(item.get('time_range', '?')))}，"
                f"置信度 {_md(item.get('confidence', 'low'))}，事件 {item.get('event_count', 0)} 条，"
                f"来源 IP：{_md(ips)}，入口候选：{_md(entries)}，文件候选：{_md(artifacts)}。"
            )
            if item.get("summary"):
                lines.append(f"  - 研判：{_md(item.get('summary'))}")
            for ev in item.get("evidence", [])[:3]:
                lines.append(f"  - 证据：{_md(_evidence_label(ev))}")
    else:
        lines.append("- （当前证据不足以拆分攻击路径）")
    lines.extend(["", "## 疑似落地/上传文件", ""])
    artifacts = brief.get("suspected_artifacts", [])
    if artifacts:
        lines.extend(["| 路径 | 置信度 | 首次出现 | 最近出现 | IP | 方法/状态 |", "|---|---|---|---|---|---|"])
        for item in artifacts[:20]:
            methods = ", ".join(f"{k}:{v}" for k, v in item.get("method_status", {}).items())
            lines.append(
                f"| {_md(item.get('path'))} | {_md(item.get('confidence'))} | "
                f"{_md(_display_time(item.get('first_seen')))} | {_md(_display_time(item.get('last_seen')))} | "
                f"{_md(', '.join(item.get('ips', [])[:5]))} | {_md(methods)} |"
            )
    else:
        lines.append("- （暂无疑似落地文件）")
    lines.extend(["", "## 参与 IP 行为画像", ""])
    for item in brief.get("actor_profiles", [])[:10]:
        roles = ", ".join(item.get("role_candidates", [])) or "未分类"
        lines.append(f"- **{_md(item.get('ip'))}**：{_md(roles)}，事件 {item.get('event_count', 0)} 条，置信度 {_md(item.get('confidence', 'low'))}")
    if not brief.get("actor_profiles"):
        lines.append("- （暂无 IP 画像）")
    lines.extend(["", "## 不能确认 / 风险边界", ""])
    for item in brief.get("uncertainties", []):
        lines.append(f"- {_md(item)}")
    if not brief.get("uncertainties"):
        lines.append("- （暂无）")
    boundary = brief.get("evidence_boundary", {})
    lines.extend(["", "## 证据边界", ""])
    lines.append(f"- **依据**：{_md(boundary.get('basis', '当前输入日志'))}")
    if boundary.get("note"):
        lines.append(f"- **说明**：{_md(boundary.get('note'))}")
    lines.extend(["", "## 建议补采证据", ""])
    for item in brief.get("next_evidence", []):
        lines.append(f"- [ ] {_md(item)}")
    if not brief.get("next_evidence"):
        lines.append("- [ ] （待补充）")
    return "\n".join(lines) + "\n"


def _event_records(parse_results: List[ParseResult]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    order = 0
    for result in parse_results:
        last_ts = ""
        for event in result.events:
            order += 1
            if event.timestamp:
                last_ts = event.timestamp
            method, path, status = _request_parts(event)
            timestamp = event.timestamp or (last_ts if method and path else "")
            ip = event.ip or _extract_ip(event.raw_line)
            record = {
                "event_id": event.id,
                "timestamp": timestamp,
                "sort_time": _sort_time(timestamp),
                "level": event.level.value,
                "category": event.category,
                "source_file": event.source_file or result.file_name,
                "source_type": event.details.get("source_type") or ("web" if event.source.startswith("Web") else "generic"),
                "ip": ip,
                "method": method,
                "path": path,
                "path_base": (path or "").split("?", 1)[0],
                "status": status,
                "message": event.message,
                "raw_line": event.raw_line,
                "tags": list(event.tags or []),
                "rule_name": event.rule_name or "",
                "user_agent": event.details.get("user_agent", ""),
                "referer": event.details.get("referer", ""),
                "details": dict(event.details or {}),
                "order": order,
            }
            records.append(record)
    records.sort(key=lambda item: (item["sort_time"], item["order"]))
    return records


def _request_parts(event: LogEvent) -> Tuple[str, str, str]:
    details = event.details or {}
    method = str(details.get("method") or "").upper()
    path = str(details.get("decoded_path") or details.get("path") or "")
    status = str(details.get("status") or "")
    if not method or not path:
        m = re.search(r'(?:request:\s*")?(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\S+)(?:\s+HTTP/[\d.]+)?', event.raw_line or "", re.I)
        if m:
            method = method or m.group(1).upper()
            path = path or m.group(2)
    if not status:
        m = re.search(r'->\s*(\d{3})\b', event.message or event.raw_line or "")
        if m:
            status = m.group(1)
    return method, path, status


def _classify_record(record: Dict[str, Any]) -> List[str]:
    path = record.get("path") or ""
    path_base = record.get("path_base") or ""
    method = record.get("method") or ""
    status = str(record.get("status") or "")
    raw = " ".join([
        path,
        record.get("message") or "",
        record.get("raw_line") or "",
        record.get("user_agent") or "",
        record.get("referer") or "",
    ])
    actions: List[str] = []
    if method in {"GET", "HEAD"} and path_base == "/":
        actions.append("homepage_visit")
    if "fatal error" in raw.lower() or "fastcgi" in raw.lower() or "createfile()" in raw.lower():
        actions.append("application_error")
    if LOGIN_PATH_RE.search(raw):
        actions.append("login_or_auth")
    if ADMIN_PATH_RE.search(raw):
        actions.append("admin_or_backend")
    if UPLOAD_PATH_RE.search(raw) or UPLOAD_ACTION_RE.search(raw):
        actions.append("upload_or_file_operation")
    if _is_script_upload_path(path):
        actions.append("script_in_upload_path")
        if status == "200" and method == "GET":
            actions.append("webshell_success_candidate")
        if status == "200" and method == "POST":
            actions.append("webshell_interaction_candidate")
    if "scanner" in record.get("tags", []) or SCANNER_UA_RE.search(raw):
        actions.append("scanner_or_script")
    if "ddos" in record.get("tags", []) or "scanning" in record.get("tags", []) or record.get("category") == "流量异常":
        actions.append("high_frequency_or_volume")
    if status in {"401", "403", "404", "405", "499"}:
        actions.append("failed_or_aborted_probe")
    return list(dict.fromkeys(actions))


def _suspected_artifacts(action_records: List[Tuple[Dict[str, Any], List[str]]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for record, actions in action_records:
        path = record.get("path_base") or ""
        if "script_in_upload_path" in actions or (UPLOAD_PATH_RE.search(path) and SCRIPT_EXT_RE.search(path)):
            grouped[path].append(record)

    artifacts = []
    for path, records in grouped.items():
        records = sorted(records, key=lambda item: (item["sort_time"], item["order"]))
        method_status: Counter = Counter()
        ips = []
        for record in records:
            method_status[f"{record.get('method') or '?'} {record.get('status') or '?'}"] += 1
            if record.get("ip") and record["ip"] not in ips:
                ips.append(record["ip"])
        success_posts = [r for r in records if r.get("method") == "POST" and str(r.get("status")) == "200"]
        success_gets = [r for r in records if r.get("method") == "GET" and str(r.get("status")) == "200"]
        confidence = "high" if success_posts and success_gets else ("medium" if success_gets or success_posts else "low")
        artifacts.append({
            "path": path,
            "confidence": confidence,
            "reason": "上传/静态目录下脚本文件被访问；GET/POST 200 越多，Webshell 交互置信度越高。",
            "first_seen": records[0].get("timestamp", ""),
            "first_seen_text": _display_time(records[0].get("timestamp", "")),
            "last_seen": records[-1].get("timestamp", ""),
            "last_seen_text": _display_time(records[-1].get("timestamp", "")),
            "event_count": len(records),
            "ips": ips,
            "method_status": dict(method_status.most_common()),
            "evidence": [_evidence_ref(record) for record in records[:8]],
        })
    return sorted(artifacts, key=lambda item: ({"high": 0, "medium": 1, "low": 2}.get(item["confidence"], 9), item["first_seen"]))


def _actor_profiles(action_records: List[Tuple[Dict[str, Any], List[str]]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Tuple[Dict[str, Any], List[str]]]] = defaultdict(list)
    for record, actions in action_records:
        ip = record.get("ip")
        if ip:
            grouped[ip].append((record, actions))
    profiles = []
    for ip, items in grouped.items():
        action_counter = Counter(action for _record, actions in items for action in actions)
        roles = []
        if action_counter["webshell_interaction_candidate"] or action_counter["webshell_success_candidate"]:
            roles.append("疑似 Webshell 访问/交互来源")
        if action_counter["scanner_or_script"] or action_counter["high_frequency_or_volume"]:
            roles.append("自动化扫描/脚本化访问来源")
        if action_counter["admin_or_backend"]:
            roles.append("后台/管理接口访问来源")
        if action_counter["login_or_auth"]:
            roles.append("登录/认证相关访问来源")
        confidence = "high" if len(roles) >= 2 or action_counter["webshell_interaction_candidate"] else ("medium" if roles else "low")
        first = min((item[0] for item in items), key=lambda r: (r["sort_time"], r["order"]))
        last = max((item[0] for item in items), key=lambda r: (r["sort_time"], r["order"]))
        profiles.append({
            "ip": ip,
            "confidence": confidence,
            "role_candidates": roles,
            "event_count": len(items),
            "first_seen": first.get("timestamp", ""),
            "first_seen_text": _display_time(first.get("timestamp", "")),
            "last_seen": last.get("timestamp", ""),
            "last_seen_text": _display_time(last.get("timestamp", "")),
            "top_actions": dict(action_counter.most_common(8)),
            "evidence": [_evidence_ref(first), _evidence_ref(last)],
        })
    return sorted(profiles, key=lambda item: (-item["event_count"], item["ip"]))[:20]


def _confirmed_facts(by_action: Dict[str, List[Dict[str, Any]]], artifacts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    facts: List[Dict[str, Any]] = []
    home = _first(by_action.get("homepage_visit", []))
    if home:
        facts.append(_statement(
            "首次站点首页访问证据",
            f"{_fmt_ts(home)}，{home.get('ip') or '?'} 请求首页 {home.get('method') or ''} /。",
            "confirmed",
            [home],
        ))
    access_home = _first([item for item in by_action.get("homepage_visit", []) if item.get("source_type") == "web"])
    if access_home and home and access_home.get("event_id") != home.get("event_id"):
        facts.append(_statement(
            "首次 access.log 首页访问证据",
            f"{_fmt_ts(access_home)}，{access_home.get('ip') or '?'} {access_home.get('method')} / -> {access_home.get('status') or '?'}。",
            "confirmed",
            [access_home],
        ))
    webshell_get = _first(by_action.get("webshell_success_candidate", []))
    if webshell_get:
        facts.append(_statement(
            "疑似 Webshell 首次成功访问",
            f"{_fmt_ts(webshell_get)}，{webshell_get.get('ip') or '?'} 成功访问 {webshell_get.get('path_base')}。",
            "high",
            [webshell_get],
        ))
    webshell_post = _first(by_action.get("webshell_interaction_candidate", []))
    if webshell_post:
        facts.append(_statement(
            "疑似 Webshell 首次交互",
            f"{_fmt_ts(webshell_post)}，{webshell_post.get('ip') or '?'} 对 {webshell_post.get('path_base')} 发起 POST 且返回 200。",
            "high",
            [webshell_post],
        ))
    upload = _first(by_action.get("upload_or_file_operation", []))
    if upload:
        facts.append(_statement(
            "上传/文件管理相关访问已出现",
            f"{_fmt_ts(upload)} 起出现上传目录、上传 API 或文件管理接口相关访问。",
            "confirmed",
            [upload],
        ))
    if artifacts:
        top = artifacts[0]
        facts.append({
            "title": "存在疑似上传目录脚本文件",
            "confidence": top.get("confidence", "medium"),
            "summary": f"{top.get('path')} 首次出现于 {top.get('first_seen') or '?'}，关联 {top.get('event_count', 0)} 条事件。",
            "evidence": top.get("evidence", [])[:5],
        })
    return facts


def _findings(
    by_action: Dict[str, List[Dict[str, Any]]],
    artifacts: List[Dict[str, Any]],
    summary: AnalysisSummary,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if artifacts:
        high = [item for item in artifacts if item.get("confidence") == "high"]
        findings.append({
            "title": "疑似 Webshell 失陷证据需要优先处置",
            "confidence": "high" if high else "medium",
            "summary": "上传/静态目录下脚本文件出现成功 GET/POST 访问，具备 Webshell 访问与交互特征。",
            "evidence": (high[0] if high else artifacts[0]).get("evidence", [])[:6],
        })
    scanner = _first(by_action.get("scanner_or_script", []))
    if scanner:
        findings.append(_statement(
            "存在脚本化或扫描器访问",
            "日志中出现 python-requests/curl/扫描器特征或高频访问行为，应与手工后台操作分开研判。",
            "medium",
            [scanner],
        ))
    if summary.alerts:
        top_alert = max(summary.alerts, key=lambda alert: alert.level.score)
        findings.append({
            "title": "检测告警支持当前研判",
            "confidence": top_alert.confidence,
            "summary": f"最高级别告警为 {top_alert.rule_name}：{top_alert.description}",
            "evidence": [{"event_id": event_id, "label": f"affected_event:{event_id}"} for event_id in top_alert.affected_events[:5]],
        })
    return findings


def _hypotheses(by_action: Dict[str, List[Dict[str, Any]]], artifacts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hypotheses: List[Dict[str, Any]] = []
    file_ops = [r for r in by_action.get("upload_or_file_operation", []) if "fileconnect" in (r.get("path") or "") or "cmd=mkfile" in (r.get("path") or "")]
    if file_ops:
        hypotheses.append(_statement(
            "后台文件管理接口可能被滥用",
            "出现 fileconnect/cmd=mkfile/name=shell.php 等文件管理接口痕迹；若与上传目录脚本访问相邻，应优先核验该接口是否可写入 Web 根目录。",
            "medium",
            file_ops[:3],
        ))
    upload_api = [r for r in by_action.get("upload_or_file_operation", []) if "rest-api=upload" in (r.get("path") or "")]
    if upload_api:
        hypotheses.append(_statement(
            "上传 API 可能参与写入链路",
            "出现 rest-api=upload/api_key 相关请求；仅凭 access/error 日志不能确认是否成功写文件。",
            "medium",
            upload_api[:3],
        ))
    if artifacts and not hypotheses:
        hypotheses.append({
            "title": "Webshell 写入方式尚不明确",
            "confidence": "low",
            "summary": "已看到疑似落地文件访问，但当前日志不足以确认具体上传接口、后台权限或漏洞编号。",
            "evidence": artifacts[0].get("evidence", [])[:3],
        })
    return hypotheses


def _uncertainties(by_action: Dict[str, List[Dict[str, Any]]], artifacts: List[Dict[str, Any]]) -> List[str]:
    items = [
        "仅凭 access/error 日志不能确认具体 CVE 或唯一漏洞入口。",
        "仅凭 HTTP 访问日志不能确认文件系统真实写入时间、写入账号或上传请求体内容。",
        "仅凭 Web 日志不能确认 Webshell 后续是否执行系统命令、是否落地进程或是否发生数据外传。",
        "源 IP 可能是代理、跳板或内网主机，不能直接等同真实操作者身份。",
    ]
    if not artifacts:
        items.insert(0, "当前输入未形成高置信 Webshell 落地文件清单。")
    if not by_action.get("login_or_auth"):
        items.append("当前输入缺少明确认证/会话日志，不能判断是否存在后台登录成功。")
    return items


def _next_evidence(by_action: Dict[str, List[Dict[str, Any]]], artifacts: List[Dict[str, Any]]) -> List[str]:
    items = [
        "Web 根目录与 uploads/uploadfile 目录文件清单、mtime/ctime、哈希和权限。",
        "应用认证/session 日志、后台操作审计、上传接口业务日志。",
        "Nginx/Apache 完整 access/error 日志与上游应用日志，覆盖事件前后至少 24 小时。",
        "EDR/XDR 进程树、Web 进程子进程、网络连接和命令执行记录。",
        "数据库变更日志、Webshell 可疑文件内容和同目录相邻文件。",
    ]
    if any("rest-api=upload" in (item.get("path") or "") for item in by_action.get("upload_or_file_operation", [])):
        items.append("上传 API 的服务端处理日志、API key 归属和鉴权校验记录。")
    if artifacts:
        items.append("对疑似脚本文件做静态分析和隔离取样，避免直接在生产环境执行。")
    return list(dict.fromkeys(items))


def _key_timeline(by_action: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    stage_defs = [
        ("站点访问与应用异常", ["homepage_visit", "application_error"], "站点首页访问、FastCGI/PHP/文件缺失等应用异常开始出现。"),
        ("登录/后台相关访问", ["login_or_auth", "admin_or_backend"], "出现登录页、后台路径或管理接口相关访问。"),
        ("上传/文件管理相关访问", ["upload_or_file_operation"], "出现上传目录、上传 API 或文件管理接口访问。"),
        ("疑似 Webshell 成功访问", ["webshell_success_candidate"], "上传/静态目录下脚本文件被成功 GET 访问。"),
        ("疑似 Webshell 交互", ["webshell_interaction_candidate"], "同类脚本文件出现 POST 200，具备交互特征。"),
        ("脚本化/高频后续活动", ["scanner_or_script", "high_frequency_or_volume"], "出现扫描器、脚本化 User-Agent 或高频访问。"),
    ]
    timeline = []
    for phase, action_names, summary in stage_defs:
        events = []
        for action in action_names:
            events.extend(by_action.get(action, []))
        events = _unique_records(events)
        if not events:
            continue
        events.sort(key=lambda item: (item["sort_time"], item["order"]))
        time_range = _time_range(events)
        timeline.append({
            "phase": phase,
            "time_range": time_range,
            "time_range_text": _display_time_range(time_range),
            "summary": summary,
            "event_count": len(events),
            "evidence": [_evidence_ref(item) for item in events[:6]],
        })
    return timeline


def _attack_paths(
    by_action: Dict[str, List[Dict[str, Any]]],
    artifacts: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    paths: List[Dict[str, Any]] = []

    probe_events = []
    for action in ("scanner_or_script", "high_frequency_or_volume", "failed_or_aborted_probe"):
        probe_events.extend(by_action.get(action, []))
    probe_path = _attack_path_record(
        "path-001",
        "扫描/试探路径",
        "出现扫描器、脚本化访问、高频访问或 4xx/499 探测行为。它说明攻击前置侦察或自动化试探存在，但不能单独证明成功入侵。",
        probe_events,
        "medium" if by_action.get("scanner_or_script") or by_action.get("high_frequency_or_volume") else "low",
        entry_candidates=_top_paths(probe_events, limit=5),
    )
    if probe_path:
        paths.append(probe_path)

    admin_events = []
    for action in ("login_or_auth", "admin_or_backend", "upload_or_file_operation"):
        admin_events.extend(by_action.get(action, []))
    admin_path = _attack_path_record(
        "path-002",
        "登录/后台/文件管理路径",
        "出现登录、后台、上传 API 或文件管理接口访问。若与疑似落地脚本相邻，应优先核验后台权限、文件管理接口和上传鉴权。",
        admin_events,
        "medium" if by_action.get("upload_or_file_operation") else "low",
        entry_candidates=_entry_candidates(admin_events),
    )
    if admin_path:
        paths.append(admin_path)

    shell_events = []
    for action in ("script_in_upload_path", "webshell_success_candidate", "webshell_interaction_candidate"):
        shell_events.extend(by_action.get(action, []))
    for artifact in artifacts:
        for ev in artifact.get("evidence", []):
            shell_events.append(_record_from_evidence(ev))
    artifact_paths = [item.get("path") for item in artifacts if item.get("path")]
    shell_confidence = "high" if by_action.get("webshell_interaction_candidate") else ("medium" if shell_events else "low")
    shell_path = _attack_path_record(
        "path-003",
        "疑似 Webshell 落地与交互路径",
        "上传/静态目录下脚本文件出现成功访问或 POST 交互，具备 Webshell 访问链特征；写入方式和漏洞编号仍需补证。",
        shell_events,
        shell_confidence,
        entry_candidates=_entry_candidates(by_action.get("upload_or_file_operation", [])),
        artifact_candidates=artifact_paths[:8],
    )
    if shell_path:
        paths.append(shell_path)

    return [item for item in paths if item.get("event_count", 0) > 0]


def _attack_path_record(
    path_id: str,
    title: str,
    summary: str,
    events: List[Dict[str, Any]],
    confidence: str,
    entry_candidates: Optional[List[str]] = None,
    artifact_candidates: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    events = _unique_records([item for item in events if item])
    if not events:
        return None
    events.sort(key=lambda item: (item.get("sort_time") or _sort_time(item.get("timestamp", "")), item.get("order", 0)))
    ip_counter = Counter(item.get("ip") for item in events if item.get("ip"))
    time_range = _time_range(events)
    return {
        "id": path_id,
        "title": title,
        "confidence": confidence,
        "status": "evidence_bounded_hypothesis",
        "summary": summary,
        "time_range": time_range,
        "time_range_text": _display_time_range(time_range),
        "event_count": len(events),
        "source_ips": [ip for ip, _count in ip_counter.most_common(8)],
        "entry_candidates": list(dict.fromkeys(entry_candidates or [])),
        "artifact_candidates": list(dict.fromkeys(artifact_candidates or [])),
        "evidence": [_evidence_ref(item) for item in events[:8]],
    }


def _entry_candidates(events: List[Dict[str, Any]], limit: int = 8) -> List[str]:
    candidates: List[str] = []
    for item in events:
        path = item.get("path") or item.get("url") or ""
        if not path:
            continue
        if "fileconnect" in path:
            candidates.append("fileconnect 文件管理接口")
        elif "cmd=mkfile" in path:
            candidates.append("cmd=mkfile 文件创建接口")
        elif "rest-api=upload" in path:
            candidates.append("rest-api=upload 上传 API")
        elif LOGIN_PATH_RE.search(path):
            candidates.append("登录/认证入口")
        elif ADMIN_PATH_RE.search(path):
            candidates.append("后台/管理入口")
        elif UPLOAD_PATH_RE.search(path):
            candidates.append((path.split("?", 1)[0] or path)[:120])
    if not candidates:
        candidates = _top_paths(events, limit=limit)
    return list(dict.fromkeys(candidates))[:limit]


def _top_paths(events: List[Dict[str, Any]], limit: int = 5) -> List[str]:
    counter = Counter((item.get("path") or item.get("url") or "").split("?", 1)[0] for item in events)
    return [path for path, _count in counter.most_common(limit) if path]


def _record_from_evidence(ev: Dict[str, Any]) -> Dict[str, Any]:
    timestamp = ev.get("timestamp", "")
    return {
        "event_id": ev.get("event_id", ""),
        "timestamp": timestamp,
        "sort_time": _sort_time(timestamp),
        "source_file": ev.get("source_file", ""),
        "source_type": ev.get("source_type", ""),
        "ip": ev.get("ip", ""),
        "method": ev.get("method", ""),
        "path": ev.get("url", "") or ev.get("path", ""),
        "path_base": (ev.get("url", "") or ev.get("path", "")).split("?", 1)[0],
        "status": ev.get("status", ""),
        "message": ev.get("message", ""),
        "raw_line": ev.get("raw_line", ""),
        "order": 0,
    }


def _headline(
    summary: AnalysisSummary,
    by_action: Dict[str, List[Dict[str, Any]]],
    artifacts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    if by_action.get("webshell_interaction_candidate") and artifacts:
        return {
            "title": "疑似 Webshell 失陷事件",
            "confidence": "high",
            "summary": "上传/静态目录下脚本文件出现成功访问和 POST 交互，应按疑似 Webshell 失陷优先处置；具体上传方式和漏洞入口仍需补证确认。",
        }
    if by_action.get("webshell_success_candidate") or artifacts:
        return {
            "title": "疑似上传目录脚本文件访问事件",
            "confidence": "medium",
            "summary": "发现上传/静态目录脚本访问线索，但当前证据尚不足以确认完整失陷链路。",
        }
    if summary.alerts:
        return {
            "title": "存在安全告警，需要人工研判",
            "confidence": "medium",
            "summary": f"BLA 发现 {len(summary.alerts)} 个告警；当前日志尚未形成明确 Webshell 失陷叙事。",
        }
    return {
        "title": "未形成明确攻击研判",
        "confidence": "low",
        "summary": "当前输入未形成高置信攻击事实链，可继续补充日志或降低过滤粒度。",
    }


def _empty_brief(summary: AnalysisSummary) -> Dict[str, Any]:
    return {
        "schema": "bla-incident-brief-v1",
        "headline": _headline(summary, {}, []),
        "scope": {
            "files_analyzed": summary.files_analyzed,
            "total_events": summary.total_events,
            "alert_count": len(summary.alerts),
            "incident_count": len(summary.incidents),
            "risk_score": summary.risk_score,
            "risk_level": summary.risk_level.value,
        },
        "confirmed_facts": [],
        "findings": [],
        "hypotheses": [],
        "key_timeline": [],
        "attack_paths": [],
        "suspected_artifacts": [],
        "actor_profiles": [],
        "uncertainties": ["没有可用于研判的事件。"],
        "next_evidence": [],
        "evidence_boundary": {"basis": "no events", "note": ""},
    }


def _statement(title: str, summary: str, confidence: str, records: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "title": title,
        "confidence": confidence,
        "summary": summary,
        "evidence": [_evidence_ref(item) for item in records[:8]],
    }


def _evidence_ref(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "event_id": record.get("event_id", ""),
        "timestamp": record.get("timestamp", ""),
        "source_file": record.get("source_file", ""),
        "ip": record.get("ip", ""),
        "method": record.get("method", ""),
        "url": record.get("path", ""),
        "status": record.get("status", ""),
        "message": _clip(record.get("message", ""), 220),
        "raw_line": _clip(record.get("raw_line", ""), 360),
    }


def _first(records: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not records:
        return None
    return min(records, key=lambda item: (item["sort_time"], item["order"]))


def _unique_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    result = []
    for item in records:
        key = item.get("event_id") or item.get("order")
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _time_range(records: List[Dict[str, Any]]) -> str:
    if not records:
        return ""
    first = records[0].get("timestamp", "")
    last = records[-1].get("timestamp", "")
    return first if first == last else f"{first} ~ {last}"


def _fmt_ts(record: Dict[str, Any]) -> str:
    raw = str(record.get("timestamp") or "").strip()
    display = _display_time(raw)
    if display and raw and display != raw:
        return f"{display}（{raw}）"
    return display or raw or "未知时间"


def _display_time(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    m = re.match(r"^(\d{4})[-/](\d{2})[-/](\d{2})[T\s](\d{2}):(\d{2}):(\d{2})", text)
    if not m:
        return text
    year, month, day, hour, minute, second = m.groups()
    return (
        f"{int(year)}年{int(month)}月{int(day)}日"
        f"{int(hour)}时{int(minute)}分{int(second):02d}秒"
    )


def _display_time_range(value: object) -> str:
    text = str(value or "").strip()
    if " ~ " not in text:
        return _display_time(text)
    start, end = text.split(" ~ ", 1)
    return f"{_display_time(start)} ~ {_display_time(end)}"


def _sort_time(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "9999-99-99T99:99:99"
    return text.replace("/", "-").replace(" ", "T")


def _extract_ip(value: str) -> str:
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", value or "")
    return m.group(1) if m else ""


def _is_script_upload_path(path: str) -> bool:
    return bool(path and SCRIPT_EXT_RE.search(path) and (UPLOAD_PATH_RE.search(path) or "shell" in path.lower()))


def _clip(value: object, limit: int) -> str:
    text = sanitize_report_text(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _md(value: object) -> str:
    return escape_markdown_text(value).replace("\r", " ").replace("\n", " ")


def _markdown_items(items: List[Dict[str, Any]], include_evidence: bool = False) -> List[str]:
    if not items:
        return ["- （暂无）"]
    lines = []
    for item in items:
        lines.append(f"- **{_md(item.get('title', ''))}**（{_md(item.get('confidence', ''))}）：{_md(item.get('summary', ''))}")
        if include_evidence:
            for ev in item.get("evidence", [])[:3]:
                lines.append(f"  - 证据：{_md(_evidence_label(ev))}")
    return lines


def _evidence_label(ev: Dict[str, Any]) -> str:
    bits = [
        _display_time(ev.get("timestamp") or ""),
        str(ev.get("source_file") or ""),
        str(ev.get("ip") or ""),
        " ".join(str(ev.get(k) or "") for k in ("method", "url")).strip(),
        f"-> {ev.get('status')}" if ev.get("status") else "",
        str(ev.get("message") or ev.get("raw_line") or ""),
    ]
    label = " | ".join(bit for bit in bits if bit)
    return label or str(ev.get("label") or ev.get("event_id") or "evidence")
