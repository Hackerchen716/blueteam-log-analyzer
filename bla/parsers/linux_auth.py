"""
Linux 认证日志解析器
支持: /var/log/auth.log (Debian/Ubuntu)
      /var/log/secure   (RHEL/CentOS)

检测能力:
  - SSH 暴力破解 / 密码喷洒
  - Root 直接登录
  - Sudo 滥用
  - 新用户创建
  - PAM 认证失败
"""

from __future__ import annotations
import datetime
import re
import time
from typing import List, Optional

from ..models import LogEvent, ParseResult, ThreatLevel
from ..utils.helpers import (
    MONTH_MAP, gen_id, get_syslog_year_override, normalize_timestamp, truncate,
)
from .stats import compute_stats

# syslog 标准格式
_SYSLOG_RE = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'   # timestamp
    r'(\S+)\s+'                                        # host
    r'(\S+?)(?:\[(\d+)\])?:\s+'                       # service[pid]
    r'(.*)$'                                           # message
)

# 常见 SSH 失败模式
_SSH_FAIL_RE  = re.compile(r'Failed password|authentication failure|Invalid user|Connection closed by invalid user', re.I)
_SSH_OK_RE    = re.compile(r'Accepted (password|publickey)', re.I)
_SSH_IP_RE    = re.compile(r'from\s+([\d.]+)', re.I)
_SSH_USER_RE  = re.compile(r'(?:for(?: invalid user)?|user)\s+(\S+)', re.I)
_SSH_PORT_RE  = re.compile(r'port\s+(\d+)', re.I)
_ROOT_SESS_RE = re.compile(r'session opened for user root', re.I)
_SUDO_CMD_RE  = re.compile(r'COMMAND=(.+)$')
_SUDO_USER_RE = re.compile(r'^(\S+)\s+:')
_NEW_USER_RE  = re.compile(r'new user:|useradd|adduser', re.I)
_LOCKOUT_RE   = re.compile(r'too many authentication failures|maximum authentication attempts', re.I)
_PAM_FAIL_RE  = re.compile(r'pam_unix.*(?:authentication failure|auth could not identify)', re.I)
_DISCONNECT_RE= re.compile(r'Disconnected from|Disconnecting', re.I)


def parse_linux_auth(content: str, source_file: str) -> ParseResult:
    """解析 Linux 认证日志。

    解析阶段只输出"基础事实"：每条 ``Failed password`` 打 ``failed-login`` 标
    签、``Accepted password`` 打 ``successful-login``、``sudo COMMAND=`` 打
    ``sudo-command`` 等等。**不做任何跨行聚合**——暴力破解 / 密码喷洒等基于
    阈值的判定全部交给 :mod:`bla.detection.engine`，确保规则只有一个真相源。
    """
    t0 = time.time()
    lines = content.splitlines()
    events: List[LogEvent] = []

    # 跨年处理：syslog 时间戳不带年份，按字典序排序会把 12 月排在 1 月之后。
    # 这里维护一个 base_year，每当月份发生回退就 +1，这样跨年日志也能保持
    # 时间单调递增。优先用 --syslog-year，否则用系统当前年份作为起点。
    base_year = get_syslog_year_override() or datetime.datetime.now().year
    last_month_num = 0

    for line in lines:
        if not line.strip():
            continue
        # 在调用 _parse_auth_line 之前先观察月份序列，决定本行该用哪个 year
        month_match = re.match(r'^(\w{3})\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', line)
        if month_match:
            mon_num = int(MONTH_MAP.get(month_match.group(1), '0'))
            if mon_num and last_month_num and mon_num < last_month_num - 1:
                # 月份回退（容忍 1 个月内的乱序），认为跨年了
                base_year += 1
            if mon_num:
                last_month_num = mon_num

        ev = _parse_auth_line(line, source_file, base_year)
        if ev:
            events.append(ev)

    stats = compute_stats(events)
    return ParseResult(
        file_name     = source_file,
        log_type      = "Linux Auth Log",
        events        = events,
        stats         = stats,
        parse_time_ms = (time.time() - t0) * 1000,
        file_size_bytes = len(content.encode()),
    )


def _parse_auth_line(line: str, source_file: str, syslog_year: Optional[int] = None) -> Optional[LogEvent]:
    m = _SYSLOG_RE.match(line)
    if not m:
        return None

    ts_raw, host, service, _pid, message = m.groups()
    ts = normalize_timestamp(ts_raw, syslog_year=syslog_year)
    svc_lower = service.lower()
    msg_lower = message.lower()

    level   = ThreatLevel.INFO
    cat     = "系统"
    tags: List[str] = []
    user    = ""
    ip      = ""
    port    = None
    mitre: Optional[str] = None
    rule_name: Optional[str] = None
    event_msg = message

    # ── SSH ──────────────────────────────────────────────
    if "sshd" in svc_lower:
        ip_m    = _SSH_IP_RE.search(message)
        user_m  = _SSH_USER_RE.search(message)
        port_m  = _SSH_PORT_RE.search(message)
        ip      = ip_m.group(1) if ip_m else ""
        user    = user_m.group(1) if user_m else ""
        port    = int(port_m.group(1)) if port_m else None

        if _SSH_FAIL_RE.search(message):
            level     = ThreatLevel.MEDIUM
            cat       = "SSH"
            tags      = ["failed-login", "authentication"]
            mitre     = "T1110.001"
            rule_name = "SSH 登录失败"
            event_msg = f"SSH 登录失败: 用户={user or '?'} 来源={ip or '?'}"

        elif _SSH_OK_RE.search(message):
            method = "密码" if "password" in msg_lower else "公钥"
            level     = ThreatLevel.INFO
            cat       = "SSH"
            tags      = ["successful-login", "authentication"]
            mitre     = "T1078"
            rule_name = f"SSH 登录成功({method})"
            event_msg = f"SSH 登录成功({method}): 用户={user or '?'} 来源={ip or '?'}"

        elif _ROOT_SESS_RE.search(message):
            level     = ThreatLevel.HIGH
            cat       = "SSH"
            tags      = ["root-login", "privilege-escalation"]
            mitre     = "T1078.003"
            rule_name = "Root 账户直接登录"
            event_msg = "Root 账户 SSH 会话已开启"

        elif _LOCKOUT_RE.search(message):
            level     = ThreatLevel.HIGH
            cat       = "SSH"
            tags      = ["brute-force", "lockout"]
            mitre     = "T1110"
            rule_name = "认证失败次数过多"
            event_msg = f"认证失败次数过多: 来源={ip or '?'}"

        elif _DISCONNECT_RE.search(message):
            cat   = "SSH"
            tags  = ["disconnect"]
            event_msg = f"SSH 断开: {ip or '?'}"

        else:
            return None  # 过滤 SSH 噪音

    # ── Sudo ─────────────────────────────────────────────
    elif "sudo" in svc_lower:
        user_m = _SUDO_USER_RE.match(message)
        user   = user_m.group(1) if user_m else ""

        if "command not allowed" in msg_lower or "not in sudoers" in msg_lower:
            level     = ThreatLevel.HIGH
            cat       = "Sudo"
            tags      = ["sudo-denied", "privilege-escalation"]
            mitre     = "T1548.003"
            rule_name = "Sudo 权限拒绝"
            event_msg = f"Sudo 拒绝: 用户={user} 消息={truncate(message, 80)}"

        elif "COMMAND=" in message:
            cmd_m = _SUDO_CMD_RE.search(message)
            cmd   = cmd_m.group(1) if cmd_m else ""
            # 检测危险命令
            if re.search(r'bash|sh\s*$|python|perl|ruby|nc\s|ncat|/bin/sh', cmd, re.I):
                level = ThreatLevel.HIGH
                tags  = ["sudo-shell", "privilege-escalation"]
                rule_name = "Sudo 获取 Shell"
            else:
                level = ThreatLevel.MEDIUM
                tags  = ["sudo-command", "privilege-escalation"]
                rule_name = "Sudo 命令执行"
            cat   = "Sudo"
            mitre = "T1548.003"
            event_msg = f"Sudo 执行: 用户={user} 命令={truncate(cmd, 80)}"
        else:
            return None

    # ── 用户管理 ─────────────────────────────────────────
    elif _NEW_USER_RE.search(message):
        level     = ThreatLevel.HIGH
        cat       = "账户管理"
        tags      = ["account-creation", "persistence"]
        mitre     = "T1136.001"
        rule_name = "创建新用户"
        event_msg = f"创建新用户: {truncate(message, 80)}"

    # ── PAM ──────────────────────────────────────────────
    elif _PAM_FAIL_RE.search(message):
        level     = ThreatLevel.MEDIUM
        cat       = "PAM"
        tags      = ["pam-failure", "authentication"]
        mitre     = "T1110"
        rule_name = "PAM 认证失败"
        event_msg = f"PAM 认证失败: {truncate(message, 80)}"

    else:
        return None  # 过滤其余噪音

    return LogEvent(
        id          = gen_id("auth"),
        timestamp   = ts,
        level       = level,
        category    = cat,
        source      = service,
        source_file = source_file,
        message     = event_msg,
        raw_line    = line,
        user        = user or None,
        host        = host,
        ip          = ip or None,
        port        = port,
        details     = {"host": host, "service": service, "raw_msg": message},
        tags        = tags,
        mitre_attack= mitre,
        rule_name   = rule_name,
    )
