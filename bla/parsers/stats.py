"""统计计算 - 被所有解析器共用"""
from __future__ import annotations
from collections import Counter
from typing import List
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
        "4624":"登录成功","4625":"登录失败","4648":"显式凭据登录",
        "4720":"创建用户","4726":"删除用户","4728":"添加到全局组",
        "4732":"添加到本地组","4688":"进程创建","7045":"安装服务",
        "4698":"创建计划任务","1102":"清除安全日志","4104":"PS脚本块",
        "4719":"审计策略修改","4672":"特权登录","4768":"Kerberos TGT",
    }
    stats.top_event_ids = [
        {"event_id": eid, "count": c, "description": EID_DESC.get(eid, f"事件{eid}")}
        for eid, c in eid_counter.most_common(10)
    ]

    if timestamps:
        ts_sorted = sorted(timestamps)
        stats.time_start = ts_sorted[0]
        stats.time_end   = ts_sorted[-1]

    return stats
