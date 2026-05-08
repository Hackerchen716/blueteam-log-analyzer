"""统计计算 - 被所有解析器共用"""
from __future__ import annotations
from collections import Counter
from typing import List, Dict, Any
from ..models import LogEvent, ParseStats


def compute_stats(events: List[LogEvent]) -> ParseStats:
    stats = ParseStats(total=len(events))
    ip_counter: Counter = Counter()
    user_counter: Counter = Counter()
    eid_counter: Counter = Counter()
    timestamps = []

    for ev in events:
        lvl = ev.level.value
        if lvl == "critical": stats.critical += 1
        elif lvl == "high":   stats.high += 1
        elif lvl == "medium": stats.medium += 1
        elif lvl == "low":    stats.low += 1
        else:                 stats.info += 1

        stats.categories[ev.category] = stats.categories.get(ev.category, 0) + 1

        if ev.ip:   ip_counter[ev.ip] += 1
        if ev.user: user_counter[ev.user] += 1
        if ev.event_id: eid_counter[ev.event_id] += 1
        if ev.timestamp: timestamps.append(ev.timestamp)

        for tag in ev.tags:
            if tag in ("sqli","xss","rce","lfi","rfi","brute-force",
                       "path-traversal","webshell","scanning","ddos",
                       "injection","command-injection","lolbin","malware-indicator"):
                stats.attack_types[tag] = stats.attack_types.get(tag, 0) + 1

    stats.top_ips   = [{"ip": ip, "count": c} for ip, c in ip_counter.most_common(10)]
    stats.top_users = [{"user": u, "count": c} for u, c in user_counter.most_common(10)]

    EID_DESC = {
        "4624":"登录成功","4625":"登录失败","4634":"账户注销","4647":"用户主动注销",
        "4648":"显式凭据登录","4672":"特权登录","4673":"敏感特权调用",
        "4720":"创建用户","4726":"删除用户","4728":"添加到全局组",
        "4732":"添加到本地组","4738":"账户属性变更","4740":"账户锁定","4756":"添加到通用组",
        "4688":"进程创建","7045":"安装服务",
        "4698":"创建计划任务","1102":"清除安全日志","4104":"PS脚本块",
        "4719":"审计策略修改","4768":"Kerberos TGT","4769":"Kerberos TGS",
        "4771":"Kerberos 预认证失败","4776":"NTLM 校验","4778":"RDP 重连","4779":"RDP 断开",
        "5140":"文件共享访问","5145":"共享对象访问","5156":"网络连接允许","5157":"网络连接阻止",
    }
    stats.top_event_ids = [
        {"event_id": eid, "count": c, "description": EID_DESC.get(eid, f"事件{eid}")}
        for eid, c in eid_counter.most_common(10)
    ]

    if timestamps:
        ts_sorted = sorted(timestamps)
        stats.time_start = ts_sorted[0]
        stats.time_end   = ts_sorted[-1]

    stats.windows_logon_stats = _compute_windows_logon_stats(events)
    stats.windows_process_creation_stats = _compute_windows_process_creation_stats(events)
    return stats


def _top_counter_items(counter: Counter, key_name: str, limit: int = 10) -> List[Dict[str, Any]]:
    return [
        {key_name: value, "count": count}
        for value, count in counter.most_common(limit)
        if value
    ]


def _compute_windows_logon_stats(events: List[LogEvent]) -> Dict[str, Any]:
    auth_events = [e for e in events if e.event_id in ("4624", "4625")]
    if not auth_events:
        return {}

    result: Dict[str, Any] = {
        "total_success": sum(1 for e in auth_events if e.event_id == "4624"),
        "total_failure": sum(1 for e in auth_events if e.event_id == "4625"),
        "unique_accounts": len({e.details.get("account_name") for e in auth_events if e.details.get("account_name")}),
        "unique_source_ips": len({e.details.get("source_ip") for e in auth_events if e.details.get("source_ip")}),
        "events": {},
    }

    event_names = {"4624": "登录成功", "4625": "登录失败"}
    for event_id, event_name in event_names.items():
        subset = [e for e in auth_events if e.event_id == event_id]
        if not subset:
            continue

        account_counter: Counter = Counter()
        domain_counter: Counter = Counter()
        principal_counter: Counter = Counter()
        ip_counter: Counter = Counter()
        workstation_counter: Counter = Counter()
        logon_type_counter: Counter = Counter()
        process_counter: Counter = Counter()
        logon_process_counter: Counter = Counter()
        auth_package_counter: Counter = Counter()
        failure_reason_counter: Counter = Counter()
        status_counter: Counter = Counter()
        sub_status_counter: Counter = Counter()

        for ev in subset:
            details = ev.details
            account = details.get("account_name", "")
            domain = details.get("account_domain", "")
            source_ip = details.get("source_ip", "")
            workstation = details.get("workstation", "")
            logon_type = details.get("LogonType", "")
            logon_type_label = details.get("logon_type_label", "")
            process_name = details.get("process_name", "") or ev.process or ""
            logon_process = details.get("logon_process", "")
            auth_package = details.get("auth_package", "")
            failure_reason = details.get("failure_reason", "")
            status_code = details.get("status_code", "")
            sub_status_code = details.get("sub_status_code", "")

            if account:
                account_counter[account] += 1
                principal_counter[f"{domain}\\{account}" if domain else account] += 1
            if domain:
                domain_counter[domain] += 1
            if source_ip:
                ip_counter[source_ip] += 1
            if workstation:
                workstation_counter[workstation] += 1
            if logon_type:
                logon_type_counter[f"{logon_type}|{logon_type_label or '未知'}"] += 1
            if process_name:
                process_counter[process_name] += 1
            if logon_process:
                logon_process_counter[logon_process] += 1
            if auth_package:
                auth_package_counter[auth_package] += 1
            if failure_reason:
                failure_reason_counter[failure_reason] += 1
            if status_code:
                status_counter[status_code] += 1
            if sub_status_code:
                sub_status_counter[sub_status_code] += 1

        event_summary: Dict[str, Any] = {
            "event_name": event_name,
            "total": len(subset),
            "unique_accounts": len(account_counter),
            "unique_source_ips": len(ip_counter),
            "principals": _top_counter_items(principal_counter, "principal"),
            "account_names": _top_counter_items(account_counter, "account_name"),
            "account_domains": _top_counter_items(domain_counter, "account_domain"),
            "source_ips": _top_counter_items(ip_counter, "source_ip"),
            "workstations": _top_counter_items(workstation_counter, "workstation"),
            "process_names": _top_counter_items(process_counter, "process_name"),
            "logon_processes": _top_counter_items(logon_process_counter, "logon_process"),
            "auth_packages": _top_counter_items(auth_package_counter, "auth_package"),
            "logon_types": [
                {
                    "logon_type": item.split("|", 1)[0],
                    "label": item.split("|", 1)[1],
                    "count": count,
                }
                for item, count in logon_type_counter.most_common(10)
            ],
        }

        if event_id == "4625":
            event_summary["failure_reasons"] = _top_counter_items(failure_reason_counter, "failure_reason")
            event_summary["status_codes"] = _top_counter_items(status_counter, "status_code")
            event_summary["sub_status_codes"] = _top_counter_items(sub_status_counter, "sub_status_code")

        result["events"][event_id] = event_summary

    return result


def _compute_windows_process_creation_stats(events: List[LogEvent]) -> Dict[str, Any]:
    proc_events = [e for e in events if e.event_id == "4688"]
    if not proc_events:
        return {}

    pair_counter: Counter = Counter()
    pair_latest: Dict[str, str] = {}
    pair_paths: Dict[str, str] = {}

    for ev in proc_events:
        parent = (ev.details.get("parent_process") or "").strip()
        child = (ev.details.get("child_process") or "").strip() or (ev.process or "")
        path = (ev.details.get("child_path") or "").strip() or (ev.details.get("NewProcessName") or "").strip()

        key = f"{parent} -> {child}" if parent else f"(unknown) -> {child}"
        pair_counter[key] += 1
        if path and key not in pair_paths:
            pair_paths[key] = path
        if ev.timestamp:
            cur = pair_latest.get(key, "")
            if not cur or ev.timestamp > cur:
                pair_latest[key] = ev.timestamp

    items = []
    for key, count in pair_counter.most_common(10):
        items.append({
            "parent_process": key.split(" -> ", 1)[0],
            "child_process": key.split(" -> ", 1)[1] if " -> " in key else key,
            "count": count,
            "path": pair_paths.get(key, ""),
            "time": pair_latest.get(key, ""),
        })

    return {
        "total": len(proc_events),
        "unique_pairs": len(pair_counter),
        "top": items,
    }
