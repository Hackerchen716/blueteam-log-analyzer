"""
Windows 事件日志解析器
支持格式:
  - XML 导出 (.xml)  — wevtutil qe Security /f:RenderedXml /e:Events > Security.xml
  - 二进制 EVTX (.evtx) — 需要 python-evtx 库（可选）
  - 纯文本事件导出

检测规则参考: Hayabusa / DeepBlueCLI / Sigma
"""

from __future__ import annotations

import os
import re
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from ..models import LogEvent, ParseResult, ParseStats, ThreatLevel
from ..utils.helpers import file_size, gen_id, iter_file_chunks, normalize_timestamp, truncate

_LOGON_TYPE_MAP = {
    "2": "交互式",
    "3": "网络",
    "4": "批处理",
    "5": "服务",
    "7": "解锁",
    "8": "网络明文",
    "9": "新凭据",
    "10": "远程交互/RDP",
    "11": "缓存交互",
}

_LOW_RISK_WINDOWS_GROUPS = {
    "none",
    "users",
    "domain users",
    "guests",
    "iis_iusrs",
}

_PRIVILEGED_WINDOWS_GROUPS = {
    "administrators",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "account operators",
    "server operators",
    "backup operators",
    "print operators",
    "remote desktop users",
    "remote management users",
    "dnsadmins",
    "hyper-v administrators",
}

_WINDOWS_BUILTIN_CREATED_ACCOUNTS = {
    "defaultaccount",
    "guest",
    "wdagutilityaccount",
}

_WINDOWS_SERVICE_ACCOUNTS = {
    "localsystem",
    "system",
    "localservice",
    "networkservice",
}

_WINDOWS_MAINTENANCE_SERVICE_NAMES = {
    "bits",
    "trustedinstaller",
    "usosvc",
    "waasmedicsvc",
    "windefend",
    "wuauserv",
}

_WINDOWS_MAINTENANCE_SERVICE_EXES = {
    "msmpeng.exe",
    "securityhealthservice.exe",
    "svchost.exe",
    "trustedinstaller.exe",
}

_WINDOWS_MAINTENANCE_TASK_PREFIXES = (
    "\\microsoft\\windows\\updateorchestrator\\",
    "\\microsoft\\windows\\windows defender\\",
    "\\microsoft\\windows\\windowsupdate\\",
    "\\microsoft\\windows\\waasmedic\\",
)

_WINDOWS_MAINTENANCE_TASK_EXES = {
    "mousocoreworker.exe",
    "mpcmdrun.exe",
    "musnotification.exe",
    "musnotificationux.exe",
    "usoclient.exe",
    "wuauclt.exe",
}


class MissingOptionalDependency(RuntimeError):
    """Raised when a parser cannot run because an optional dependency is absent."""


def _clean_win_value(value: str) -> str:
    value = (value or "").strip()
    return "" if value in ("-", "::1", "127.0.0.1", "::ffff:127.0.0.1") else value


def _pick_first(details: Dict[str, str], *keys: str) -> str:
    for key in keys:
        value = _clean_win_value(details.get(key, ""))
        if value:
            return value
    return ""


def _windows_basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1] if path else ""


def _command_executable(command: str) -> str:
    command = (command or "").strip()
    if not command:
        return ""
    quoted = re.match(r'^"([^"]+)"', command)
    token = quoted.group(1) if quoted else command.split()[0]
    return _windows_basename(token.strip("\"'"))


def _truthy_win_value(value: str) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def _norm_win_name(value: str) -> str:
    value = (value or "").strip().strip("\\/")
    if "\\" in value:
        value = value.rsplit("\\", 1)[-1]
    if "/" in value:
        value = value.rsplit("/", 1)[-1]
    return value.lower()


def _norm_win_path_text(value: str) -> str:
    text = (value or "").strip().strip("\"'").replace("/", "\\").lower()
    text = text.replace("%systemroot%", "c:\\windows")
    text = text.replace("%windir%", "c:\\windows")
    return text


def _is_windows_service_account(value: str) -> bool:
    return _norm_win_name(value) in _WINDOWS_SERVICE_ACCOUNTS


def _is_windows_system32_command(command: str) -> bool:
    text = _norm_win_path_text(command)
    return (
        "\\windows\\system32\\" in text
        or text.startswith("system32\\")
        or text.startswith("c:\\windows\\servicing\\")
        or text.startswith("%systemroot%\\system32\\")
        or text.startswith("%windir%\\system32\\")
    )


def _account_label(details: Dict[str, str], domain_key: str, user_key: str) -> str:
    user = _pick_first(details, user_key)
    domain = _pick_first(details, domain_key)
    if not user:
        return "?"
    return f"{domain}\\{user}" if domain else user


def _target_account_label(details: Dict[str, str]) -> str:
    return _account_label(details, "TargetDomainName", "TargetUserName")


def _subject_account_label(details: Dict[str, str]) -> str:
    return _account_label(details, "SubjectDomainName", "SubjectUserName")


def _group_label(details: Dict[str, str]) -> str:
    group = _pick_first(details, "TargetUserName")
    domain = _pick_first(details, "TargetDomainName")
    if not group:
        return "?"
    return f"{domain}\\{group}" if domain else group


def _member_label(details: Dict[str, str]) -> str:
    return _pick_first(details, "MemberName", "MemberSid", "TargetSid") or "?"


def _logon_type_label(logon_type: str) -> str:
    return _LOGON_TYPE_MAP.get((logon_type or "").strip(), "未知")


def _describe_network(details: Dict[str, str]) -> str:
    ip = _pick_first(details, "IpAddress", "SourceAddress")
    port = _pick_first(details, "IpPort")
    workstation = _pick_first(details, "WorkstationName")
    if ip and port:
        return f"{ip}:{port}"
    if ip:
        return ip
    if workstation:
        return workstation
    return "本地"


def _build_4624_message(details: Dict[str, str]) -> str:
    user = _pick_first(details, "TargetUserName", "SubjectUserName") or "?"
    domain = _pick_first(details, "TargetDomainName", "SubjectDomainName")
    domain_prefix = f"{domain}\\" if domain else ""
    logon_type = details.get("LogonType", "")
    logon_label = _logon_type_label(logon_type)
    auth_pkg = _pick_first(details, "AuthenticationPackageName")
    network = _describe_network(details)
    auth_part = f" 认证={auth_pkg}" if auth_pkg else ""
    return (
        f"登录成功: 账户={domain_prefix}{user} "
        f"登录类型={logon_type or '?'}({logon_label}) 来源={network}{auth_part}"
    )


def _build_4625_message(details: Dict[str, str]) -> str:
    user = _pick_first(details, "TargetUserName", "SubjectUserName") or "?"
    domain = _pick_first(details, "TargetDomainName", "SubjectDomainName")
    domain_prefix = f"{domain}\\" if domain else ""
    logon_type = details.get("LogonType", "")
    logon_label = _logon_type_label(logon_type)
    network = _describe_network(details)
    reason = _pick_first(details, "FailureReason")
    status = _pick_first(details, "Status")
    sub_status = _pick_first(details, "SubStatus")
    failure_bits = []
    if reason:
        failure_bits.append(reason)
    if status:
        failure_bits.append(f"Status={status}")
    if sub_status:
        failure_bits.append(f"SubStatus={sub_status}")
    failure_suffix = f" 失败原因={' | '.join(failure_bits)}" if failure_bits else ""
    return (
        f"登录失败: 账户={domain_prefix}{user} "
        f"登录类型={logon_type or '?'}({logon_label}) 来源={network}{failure_suffix}"
    )


def _augment_auth_details(eid: int, details: Dict[str, str]) -> None:
    if eid not in (4624, 4625):
        return

    details["account_name"] = _pick_first(details, "TargetUserName", "SubjectUserName")
    details["account_domain"] = _pick_first(details, "TargetDomainName", "SubjectDomainName")
    details["source_ip"] = _pick_first(details, "IpAddress", "SourceAddress")
    details["source_port"] = _pick_first(details, "IpPort")
    details["workstation"] = _pick_first(details, "WorkstationName")
    details["logon_type_label"] = _logon_type_label(details.get("LogonType", ""))
    details["logon_process"] = _pick_first(details, "LogonProcessName")
    details["auth_package"] = _pick_first(details, "AuthenticationPackageName")
    details["process_name"] = _pick_first(details, "ProcessName")
    details["failure_reason"] = _pick_first(details, "FailureReason")
    details["status_code"] = _pick_first(details, "Status")
    details["sub_status_code"] = _pick_first(details, "SubStatus")
    details["subject_user"] = _pick_first(details, "SubjectUserName")
    details["subject_domain"] = _pick_first(details, "SubjectDomainName")


def _augment_ntlm_details(eid: int, details: Dict[str, str]) -> None:
    if eid != 4776:
        return

    details["account_name"] = _pick_first(details, "TargetUserName")
    details["account_domain"] = _pick_first(details, "TargetDomainName")
    details["workstation"] = _pick_first(details, "Workstation", "WorkstationName")
    details["status_code"] = _pick_first(details, "Status")
    details["auth_package"] = _pick_first(details, "PackageName", "AuthenticationPackageName")
    details["credential_validation_result"] = "success" if _is_success_status(details.get("status_code", "")) else "failed"


def _augment_account_management_details(eid: int, details: Dict[str, str]) -> None:
    if eid not in (4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4738, 4756):
        return

    details["subject_user"] = _pick_first(details, "SubjectUserName")
    details["subject_domain"] = _pick_first(details, "SubjectDomainName")
    details["subject_account"] = _subject_account_label(details)
    details["operator_account"] = details["subject_account"]
    details["target_user"] = _pick_first(details, "TargetUserName")
    details["target_domain"] = _pick_first(details, "TargetDomainName")
    details["target_account"] = _target_account_label(details)
    details["target_sid"] = _pick_first(details, "TargetSid")
    if eid in (4728, 4729, 4732, 4756):
        details["group_name"] = _pick_first(details, "TargetUserName")
        details["group_domain"] = _pick_first(details, "TargetDomainName")
        details["group_account"] = _group_label(details)
        details["member_name"] = _member_label(details)
        details["member_sid"] = _pick_first(details, "MemberSid")
        details["member_account"] = _pick_first(details, "MemberName")
        _classify_group_change_details(details)
    elif eid == 4720:
        _classify_account_creation_details(details)


def _augment_explicit_credential_details(eid: int, details: Dict[str, str]) -> None:
    if eid != 4648:
        return
    details["subject_user"] = _pick_first(details, "SubjectUserName")
    details["subject_domain"] = _pick_first(details, "SubjectDomainName")
    details["subject_account"] = _subject_account_label(details)
    details["target_user"] = _pick_first(details, "TargetUserName")
    details["target_domain"] = _pick_first(details, "TargetDomainName")
    details["target_account"] = _target_account_label(details)
    details["target_server"] = _pick_first(details, "TargetServerName")
    details["source_ip"] = _pick_first(details, "IpAddress")


def _augment_4688_details(eid: int, details: Dict[str, str]) -> None:
    if eid != 4688:
        return

    parent = _pick_first(details, "ParentProcessName", "CreatorProcessName")
    child_path = _pick_first(details, "NewProcessName", "ProcessName")

    details["parent_process"] = parent
    details["child_process"] = _windows_basename(child_path)
    details["child_path"] = child_path
    details["command_line"] = _pick_first(details, "CommandLine")


def _augment_sysmon_details(eid: int, details: Dict[str, str]) -> None:
    if eid == 1:
        image = _pick_first(details, "Image")
        details["parent_process"] = _pick_first(details, "ParentImage")
        details["child_process"] = _windows_basename(image)
        details["child_path"] = image
        details["command_line"] = _pick_first(details, "CommandLine")
    elif eid == 3:
        details["source_ip"] = _pick_first(details, "SourceIp")
        details["source_port"] = _pick_first(details, "SourcePort")
        details["destination_ip"] = _pick_first(details, "DestinationIp")
        details["destination_port"] = _pick_first(details, "DestinationPort")
        details["destination_host"] = _pick_first(details, "DestinationHostname")
        details["network_protocol"] = _pick_first(details, "Protocol")
        details["initiated"] = _pick_first(details, "Initiated")
    elif eid == 10:
        source_image = _pick_first(details, "SourceImage")
        target_image = _pick_first(details, "TargetImage")
        details["source_process"] = _windows_basename(source_image)
        details["target_process"] = _windows_basename(target_image)
        details["granted_access"] = _pick_first(details, "GrantedAccess")
    elif eid == 22:
        details["dns_query"] = _pick_first(details, "QueryName")
        details["query_status"] = _pick_first(details, "QueryStatus")
    elif eid in (19, 20, 21):
        details["wmi_operation"] = _pick_first(details, "Operation")
        details["wmi_filter"] = _pick_first(details, "Filter", "Name")
        details["wmi_consumer"] = _pick_first(details, "Consumer", "Name")
        details["wmi_query"] = _pick_first(details, "Query")
        details["wmi_event_namespace"] = _pick_first(details, "EventNamespace")
        command = _pick_first(details, "Destination", "CommandLineTemplate", "ExecutablePath")
        details["persistence_mechanism"] = "wmi-event-subscription"
        details["persistence_command"] = command
        details["command_line"] = command
        details["child_process"] = _command_executable(command)


def _task_xml_value(task_content: str, tag: str) -> str:
    match = re.search(
        rf"<(?:[A-Za-z0-9_.-]+:)?{tag}\b[^>]*>(.*?)</(?:[A-Za-z0-9_.-]+:)?{tag}>",
        task_content or "",
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return ""
    return re.sub(r"<[^>]+>", "", match.group(1)).strip()


def _augment_persistence_details(eid: int, details: Dict[str, str]) -> None:
    if eid == 7045:
        command = _pick_first(details, "ImagePath", "ServiceFileName")
        details["service_name"] = _pick_first(details, "ServiceName")
        details["service_image_path"] = command
        details["service_account"] = _pick_first(details, "ServiceAccount", "AccountName")
        details["persistence_mechanism"] = "service"
        details["persistence_command"] = command
        details["command_line"] = command
        details["child_process"] = _command_executable(command)
        _classify_persistence_baseline(details, "service")
    elif eid in (4698, 4702):
        task_content = _pick_first(details, "TaskContent", "TaskContentNew")
        command = _task_xml_value(task_content, "Command")
        arguments = _task_xml_value(task_content, "Arguments")
        command_line = " ".join(part for part in (command, arguments) if part).strip()
        details["task_name"] = _pick_first(details, "TaskName")
        details["task_content"] = task_content
        details["task_command"] = command
        details["task_arguments"] = arguments
        details["persistence_mechanism"] = "scheduled-task"
        details["persistence_command"] = command_line or task_content
        details["command_line"] = command_line or task_content
        details["child_process"] = _command_executable(command or task_content)
        _classify_persistence_baseline(details, "scheduled-task")


def _mark_persistence_baseline(details: Dict[str, str], baseline: str, reason: str) -> None:
    details["persistence_baseline"] = baseline
    details["persistence_baseline_reason"] = reason
    details["persistence_alert_confidence"] = "low"
    details["evidence_strength"] = "low"
    details["false_positive_hint"] = (
        "Windows maintenance baseline candidate; keep the event, but verify change window, "
        "signature, and parent process before escalation."
    )


def _classify_persistence_baseline(details: Dict[str, str], mechanism: str) -> None:
    command = details.get("persistence_command", "")
    child = _norm_win_name(details.get("child_process", ""))
    if not command or not child or not _is_windows_system32_command(command):
        return
    if mechanism == "service":
        service = _norm_win_name(details.get("service_name", ""))
        account = details.get("service_account", "")
        if (
            service in _WINDOWS_MAINTENANCE_SERVICE_NAMES
            and child in _WINDOWS_MAINTENANCE_SERVICE_EXES
            and _is_windows_service_account(account)
        ):
            _mark_persistence_baseline(details, "windows-maintenance-service", service)
        return
    if mechanism == "scheduled-task":
        task_name = _norm_win_path_text(details.get("task_name", ""))
        subject = _pick_first(details, "SubjectUserName", "UserName")
        if (
            child in _WINDOWS_MAINTENANCE_TASK_EXES
            and _is_windows_service_account(subject)
            and any(task_name.startswith(prefix) for prefix in _WINDOWS_MAINTENANCE_TASK_PREFIXES)
        ):
            _mark_persistence_baseline(details, "windows-maintenance-task", details.get("task_name", ""))


def _classify_group_change_details(details: Dict[str, str]) -> None:
    group = _norm_win_name(details.get("group_name", ""))
    if group in _PRIVILEGED_WINDOWS_GROUPS:
        details["group_sensitivity"] = "privileged"
        details["evidence_strength"] = "high"
        return
    if group in _LOW_RISK_WINDOWS_GROUPS:
        details["group_sensitivity"] = "low"
        details["evidence_strength"] = "low"
        details["false_positive_hint"] = "Windows built-in or default group membership change; verify baseline before escalation."
        return
    details["group_sensitivity"] = "unknown"
    details["evidence_strength"] = "medium"


def _classify_account_creation_details(details: Dict[str, str]) -> None:
    target = _norm_win_name(details.get("target_user", ""))
    subject = _norm_win_name(details.get("subject_user", ""))
    subject_sid = details.get("SubjectUserSid", "")
    if target in _WINDOWS_BUILTIN_CREATED_ACCOUNTS and (subject.endswith("$") or subject_sid == "S-1-5-18"):
        details["account_sensitivity"] = "system-initialization"
        details["evidence_strength"] = "low"
        details["false_positive_hint"] = "Known Windows built-in account created by system or machine account during initialization."
    else:
        details["account_sensitivity"] = "new-local-account"
        details["evidence_strength"] = "high"


def _is_local_explicit_credential_use(details: Dict[str, str]) -> bool:
    target_server = _norm_win_name(details.get("target_server") or details.get("TargetServerName", ""))
    source_ip = _clean_win_value(details.get("source_ip") or details.get("IpAddress", ""))
    subject = _norm_win_name(details.get("subject_user") or details.get("SubjectUserName", ""))
    if target_server in {"localhost", "127.0.0.1", "::1"}:
        return True
    if subject.endswith("$") and not source_ip:
        return True
    return False

# Windows 事件 ID 规则库
# 格式: event_id -> (level, category, message_fn, tags, mitre, rule_name)
_WIN_RULES: Dict[int, dict] = {
    # ── 认证 ──────────────────────────────────────────────
    4624: dict(level=ThreatLevel.INFO,     cat="认证",    tags=["logon", "successful-login", "authentication"],
               mitre=None,         rule="登录成功",
               msg=_build_4624_message),
    4625: dict(level=ThreatLevel.MEDIUM,   cat="认证",    tags=["failed-logon", "failed-login", "brute-force", "authentication"],
               mitre="T1110.001",  rule="登录失败",
               msg=_build_4625_message),
    4648: dict(level=ThreatLevel.MEDIUM,   cat="认证",    tags=["explicit-creds","lateral-movement"],
               mitre="T1550",      rule="显式凭据登录",
               msg=lambda d: f"显式凭据登录: {_subject_account_label(d)} -> {d.get('TargetServerName','?')}"),
    4672: dict(level=ThreatLevel.INFO,     cat="权限",    tags=["privilege","admin"],
               mitre=None,         rule="特权账户登录",
               msg=lambda d: f"特权登录: {d.get('SubjectUserName','?')} 获得特殊权限"),
    4768: dict(level=ThreatLevel.INFO,     cat="Kerberos",tags=["kerberos","tgt"],
               mitre="T1558",      rule="Kerberos TGT 请求",
               msg=lambda d: f"Kerberos TGT: {d.get('TargetUserName','?')} 来自 {d.get('IpAddress','?')}"),
    4769: dict(level=ThreatLevel.INFO,     cat="Kerberos",tags=["kerberos","tgs"],
               mitre="T1558",      rule="Kerberos 服务票据",
               msg=lambda d: f"Kerberos TGS: {d.get('TargetUserName','?')} -> {d.get('ServiceName','?')}"),
    4771: dict(level=ThreatLevel.MEDIUM,   cat="Kerberos",tags=["kerberos","failed","failed-logon","failed-login","brute-force","authentication"],
               mitre="T1110",      rule="Kerberos 预认证失败",
               msg=lambda d: f"Kerberos 预认证失败: {d.get('TargetUserName','?')} 来自 {d.get('IpAddress','?')}"),
    4776: dict(level=ThreatLevel.INFO,     cat="认证",    tags=["ntlm","authentication","credential-validation"],
               mitre=None,         rule="NTLM 凭据校验",
               msg=lambda d: f"NTLM 校验: {d.get('TargetUserName','?')} 来自 {d.get('Workstation','?')} 状态={d.get('Status','0x0')}"),
    4634: dict(level=ThreatLevel.INFO,     cat="认证",    tags=["logoff"],
               mitre=None,         rule="账户注销",
               msg=lambda d: f"注销: 用户={d.get('TargetUserName','?')} 类型={d.get('LogonType','?')}"),
    4647: dict(level=ThreatLevel.INFO,     cat="认证",    tags=["logoff","user-initiated"],
               mitre=None,         rule="用户主动注销",
               msg=lambda d: f"用户主动注销: {d.get('TargetUserName','?')}"),
    4673: dict(level=ThreatLevel.MEDIUM,   cat="权限",    tags=["privilege","sensitive-call"],
               mitre="T1078.002",  rule="敏感特权调用",
               msg=lambda d: f"敏感特权调用: {d.get('SubjectUserName','?')} 服务={d.get('Service','?')}"),
    4740: dict(level=ThreatLevel.HIGH,     cat="账户管理",tags=["account-lockout","brute-force"],
               mitre="T1110",      rule="账户锁定",
               msg=lambda d: f"账户被锁定: {d.get('TargetUserName','?')} 来自 {d.get('TargetDomainName','?')}"),
    4738: dict(level=ThreatLevel.MEDIUM,   cat="账户管理",tags=["account-modified"],
               mitre="T1098",      rule="账户属性变更",
               msg=lambda d: f"账户属性变更: {d.get('TargetUserName','?')} 由 {d.get('SubjectUserName','?')}"),

    # ── 账户管理 ──────────────────────────────────────────
    4720: dict(level=ThreatLevel.HIGH,     cat="账户管理",tags=["account-creation","persistence"],
               mitre="T1136",      rule="创建用户账户",
               msg=lambda d: f"创建新账户: {_target_account_label(d)} 由 {_subject_account_label(d)}"),
    4722: dict(level=ThreatLevel.MEDIUM,   cat="账户管理",tags=["account-enabled"],
               mitre=None,         rule="账户已启用",
               msg=lambda d: f"账户启用: {_target_account_label(d)}"),
    4723: dict(level=ThreatLevel.MEDIUM,   cat="账户管理",tags=["password-change"],
               mitre="T1098",      rule="密码修改",
               msg=lambda d: f"密码修改: {_target_account_label(d)}"),
    4724: dict(level=ThreatLevel.HIGH,     cat="账户管理",tags=["password-reset","privilege-escalation"],
               mitre="T1098",      rule="密码重置",
               msg=lambda d: f"密码重置: {_target_account_label(d)} 由 {_subject_account_label(d)}"),
    4725: dict(level=ThreatLevel.MEDIUM,   cat="账户管理",tags=["account-disabled"],
               mitre="T1531",      rule="账户已禁用",
               msg=lambda d: f"账户禁用: {_target_account_label(d)}"),
    4726: dict(level=ThreatLevel.HIGH,     cat="账户管理",tags=["account-deletion"],
               mitre="T1531",      rule="删除用户账户",
               msg=lambda d: f"删除账户: {_target_account_label(d)}"),
    4728: dict(level=ThreatLevel.HIGH,     cat="账户管理",tags=["group-add","privilege-escalation"],
               mitre="T1098.001",  rule="添加到全局组",
               msg=lambda d: f"添加到全局组: {_member_label(d)} -> {_group_label(d)}"),
    4732: dict(level=ThreatLevel.HIGH,     cat="账户管理",tags=["group-add","privilege-escalation"],
               mitre="T1098.001",  rule="添加到本地组",
               msg=lambda d: f"添加到本地组: {_member_label(d)} -> {_group_label(d)}"),
    4756: dict(level=ThreatLevel.HIGH,     cat="账户管理",tags=["group-add","privilege-escalation"],
               mitre="T1098.001",  rule="添加到通用组",
               msg=lambda d: f"添加到通用组: {_member_label(d)} -> {_group_label(d)}"),

    # ── 进程 ──────────────────────────────────────────────
    4688: dict(level=ThreatLevel.INFO,     cat="进程",    tags=["process-creation"],
               mitre=None,         rule="进程创建",
               msg=lambda d: f"进程创建: {d.get('NewProcessName','?')} 参数: {truncate(d.get('CommandLine',''),80)}"),
    4689: dict(level=ThreatLevel.INFO,     cat="进程",    tags=["process-exit"],
               mitre=None,         rule="进程退出",
               msg=lambda d: f"进程退出: {d.get('ProcessName','?')}"),

    # ── 服务 ──────────────────────────────────────────────
    7045: dict(level=ThreatLevel.HIGH,     cat="服务",    tags=["service-install","persistence"],
               mitre="T1543.003",  rule="安装新服务",
               msg=lambda d: f"安装服务: {d.get('ServiceName','?')} 路径={d.get('ImagePath','?')}"),
    7036: dict(level=ThreatLevel.INFO,     cat="服务",    tags=["service-state"],
               mitre=None,         rule="服务状态变更",
               msg=lambda d: f"服务状态: {d.get('param1','?')} -> {d.get('param2','?')}"),

    # ── 计划任务 ──────────────────────────────────────────
    4698: dict(level=ThreatLevel.HIGH,     cat="计划任务",tags=["scheduled-task","persistence"],
               mitre="T1053.005",  rule="创建计划任务",
               msg=lambda d: f"创建计划任务: {d.get('TaskName','?')} 由 {d.get('SubjectUserName','?')}"),
    4702: dict(level=ThreatLevel.MEDIUM,   cat="计划任务",tags=["scheduled-task","persistence"],
               mitre="T1053.005",  rule="修改计划任务",
               msg=lambda d: f"修改计划任务: {d.get('TaskName','?')}"),
    4699: dict(level=ThreatLevel.MEDIUM,   cat="计划任务",tags=["scheduled-task"],
               mitre="T1053.005",  rule="删除计划任务",
               msg=lambda d: f"删除计划任务: {d.get('TaskName','?')}"),

    # ── 日志/审计 ─────────────────────────────────────────
    1102: dict(level=ThreatLevel.CRITICAL, cat="日志操作",tags=["log-cleared","defense-evasion","anti-forensics"],
               mitre="T1070.001",  rule="安全日志清除",
               msg=lambda d: f"安全审计日志已被清除！操作者: {d.get('SubjectUserName','?')}"),
    104:  dict(level=ThreatLevel.CRITICAL, cat="日志操作",tags=["log-cleared","defense-evasion","anti-forensics"],
               mitre="T1070.001",  rule="系统日志清除",
               msg=lambda d: "系统日志已被清除！"),
    4719: dict(level=ThreatLevel.CRITICAL, cat="策略",    tags=["audit-policy","defense-evasion"],
               mitre="T1562.002",  rule="审计策略修改",
               msg=lambda d: f"审计策略被修改: {d.get('SubjectUserName','?')}"),

    # ── PowerShell ────────────────────────────────────────
    4103: dict(level=ThreatLevel.MEDIUM,   cat="PowerShell",tags=["powershell","execution"],
               mitre="T1059.001",  rule="PowerShell 模块日志",
               msg=lambda d: f"PS模块: {truncate(d.get('Payload',''),100)}"),
    4104: dict(level=ThreatLevel.MEDIUM,   cat="PowerShell",tags=["powershell","script-block","execution"],
               mitre="T1059.001",  rule="PowerShell 脚本块",
               msg=lambda d: f"PS脚本块: {truncate(d.get('ScriptBlockText',''),100)}"),

    # ── 网络 ──────────────────────────────────────────────
    5156: dict(level=ThreatLevel.INFO,     cat="网络",    tags=["network","connection"],
               mitre="T1071",      rule="网络连接允许",
               msg=lambda d: f"网络连接: {d.get('Application','?')} -> {d.get('DestAddress','?')}:{d.get('DestPort','?')}"),
    5157: dict(level=ThreatLevel.MEDIUM,   cat="网络",    tags=["network","blocked"],
               mitre=None,         rule="网络连接阻止",
               msg=lambda d: f"连接阻止: {d.get('Application','?')} -> {d.get('DestAddress','?')}:{d.get('DestPort','?')}"),

    # ── RDP ───────────────────────────────────────────────
    4778: dict(level=ThreatLevel.MEDIUM,   cat="RDP",     tags=["rdp","lateral-movement"],
               mitre="T1021.001",  rule="RDP 会话重连",
               msg=lambda d: f"RDP重连: {d.get('AccountName','?')} 来自 {d.get('ClientAddress','?')}"),
    4779: dict(level=ThreatLevel.INFO,     cat="RDP",     tags=["rdp"],
               mitre="T1021.001",  rule="RDP 会话断开",
               msg=lambda d: f"RDP断开: {d.get('AccountName','?')}"),

    # ── 文件共享 / 横向移动 ───────────────────────────────
    5140: dict(level=ThreatLevel.MEDIUM,   cat="文件共享",tags=["smb","lateral-movement","file-share"],
               mitre="T1021.002",  rule="文件共享访问",
               msg=lambda d: f"文件共享访问: {d.get('SubjectUserName','?')} -> {d.get('ShareName','?')} 来自 {d.get('IpAddress','?')}"),
    5145: dict(level=ThreatLevel.MEDIUM,   cat="文件共享",tags=["smb","lateral-movement","file-share"],
               mitre="T1021.002",  rule="共享对象访问",
               msg=lambda d: f"共享对象访问: {d.get('SubjectUserName','?')} -> {d.get('ShareName','?')}/{d.get('RelativeTargetName','?')}"),

    # ── Sysmon ────────────────────────────────────────────
    1:    dict(level=ThreatLevel.INFO,     cat="Sysmon",  tags=["sysmon","process-creation"],
               mitre=None,         rule="Sysmon 进程创建",
               msg=lambda d: f"[Sysmon] 进程: {d.get('Image','?')} 参数: {truncate(d.get('CommandLine',''),80)}"),
    3:    dict(level=ThreatLevel.INFO,     cat="Sysmon",  tags=["sysmon","network"],
               mitre=None,         rule="Sysmon 网络连接",
               msg=lambda d: f"[Sysmon] 网络: {d.get('Image','?')} -> {d.get('DestinationIp','?')}:{d.get('DestinationPort','?')}"),
    7:    dict(level=ThreatLevel.MEDIUM,   cat="Sysmon",  tags=["sysmon","image-load","dll-injection"],
               mitre="T1055",      rule="Sysmon 镜像加载",
               msg=lambda d: f"[Sysmon] DLL加载: {d.get('ImageLoaded','?')} by {d.get('Image','?')}"),
    8:    dict(level=ThreatLevel.HIGH,     cat="Sysmon",  tags=["sysmon","remote-thread","injection"],
               mitre="T1055",      rule="Sysmon 远程线程",
               msg=lambda d: f"[Sysmon] 远程线程: {d.get('SourceImage','?')} -> {d.get('TargetImage','?')}"),
    10:   dict(level=ThreatLevel.MEDIUM,   cat="Sysmon",  tags=["sysmon","process-access"],
               mitre=None,         rule="Sysmon 进程访问",
               msg=lambda d: f"[Sysmon] 进程访问: {d.get('SourceImage','?')} -> {d.get('TargetImage','?')}"),
    11:   dict(level=ThreatLevel.INFO,     cat="Sysmon",  tags=["sysmon","file-creation"],
               mitre=None,         rule="Sysmon 文件创建",
               msg=lambda d: f"[Sysmon] 文件创建: {d.get('TargetFilename','?')}"),
    12:   dict(level=ThreatLevel.MEDIUM,   cat="Sysmon",  tags=["sysmon","registry"],
               mitre="T1547",      rule="Sysmon 注册表操作",
               msg=lambda d: f"[Sysmon] 注册表: {d.get('EventType','?')} {d.get('TargetObject','?')}"),
    13:   dict(level=ThreatLevel.MEDIUM,   cat="Sysmon",  tags=["sysmon","registry","persistence"],
               mitre="T1547",      rule="Sysmon 注册表修改",
               msg=lambda d: f"[Sysmon] 注册表修改: {d.get('TargetObject','?')} = {truncate(d.get('Details',''),50)}"),
    15:   dict(level=ThreatLevel.MEDIUM,   cat="Sysmon",  tags=["sysmon","ads","defense-evasion"],
               mitre="T1564.004",  rule="Sysmon ADS 创建",
               msg=lambda d: f"[Sysmon] ADS创建: {d.get('TargetFilename','?')}"),
    19:   dict(level=ThreatLevel.MEDIUM,   cat="Sysmon",  tags=["sysmon","wmi","wmi-subscription"],
               mitre="T1546.003",  rule="Sysmon WMI 事件过滤器",
               msg=lambda d: f"[Sysmon] WMI过滤器: {d.get('Name','?')} 操作={d.get('Operation','?')}"),
    20:   dict(level=ThreatLevel.MEDIUM,   cat="Sysmon",  tags=["sysmon","wmi","wmi-subscription"],
               mitre="T1546.003",  rule="Sysmon WMI 事件消费者",
               msg=lambda d: f"[Sysmon] WMI消费者: {d.get('Name','?')} 目标={truncate(d.get('Destination',''),80)} 操作={d.get('Operation','?')}"),
    21:   dict(level=ThreatLevel.MEDIUM,   cat="Sysmon",  tags=["sysmon","wmi","wmi-subscription"],
               mitre="T1546.003",  rule="Sysmon WMI 绑定",
               msg=lambda d: f"[Sysmon] WMI绑定: {truncate(d.get('Filter',''),50)} -> {truncate(d.get('Consumer',''),50)} 操作={d.get('Operation','?')}"),
    22:   dict(level=ThreatLevel.INFO,     cat="Sysmon",  tags=["sysmon","dns"],
               mitre=None,         rule="Sysmon DNS 查询",
               msg=lambda d: f"[Sysmon] DNS: {d.get('Image','?')} 查询 {d.get('QueryName','?')}"),
    25:   dict(level=ThreatLevel.HIGH,     cat="Sysmon",  tags=["sysmon","process-tampering"],
               mitre="T1055",      rule="Sysmon 进程篡改",
               msg=lambda d: f"[Sysmon] 进程篡改: {d.get('Image','?')}"),
}

# 高危进程/命令关键词 -> 动态升级级别
_DANGEROUS_CMDS = re.compile(
    r'mimikatz|meterpreter|cobalt.?strike|empire|powersploit|invoke-mimikatz|'
    r'invoke-expression.*download|net\.webclient|downloadstring|downloadfile|'
    r'bypass.*execution|encodedcommand|-enc\s|base64.*decode|'
    r'lsadump|sekurlsa|kerberos::ptt|privilege::debug|'
    r'procdump.*lsass|tasklist.*lsass|rundll32.*comsvcs',
    re.IGNORECASE
)

_CREDENTIAL_DUMP_CMDS = re.compile(
    r'mimikatz|invoke-mimikatz|lsadump|sekurlsa|kerberos::ptt|privilege::debug|'
    r'procdump(?:\.exe)?[^\r\n]*lsass|'
    r'rundll32(?:\.exe)?[^\r\n]*comsvcs(?:\.dll)?[^\r\n]*(?:minidump|lsass)|'
    r'reg(?:\.exe)?\s+save\s+hklm\\+(?:sam|security|system)\b|'
    r'ntdsutil(?:\.exe)?[^\r\n]*(?:ntds\.dit|ifm|create\s+full)',
    re.IGNORECASE
)

_LSASS_DUMP_CMD_HINT = re.compile(r'lsass|procdump(?:\.exe)?|comsvcs(?:\.dll)?', re.IGNORECASE)
_REGISTRY_HIVE_DUMP_CMD = re.compile(r'reg(?:\.exe)?\s+save\s+hklm\\+', re.IGNORECASE)
_NTDS_DUMP_CMD = re.compile(r'ntdsutil(?:\.exe)?', re.IGNORECASE)

_SYSMON_CALLBACK_DOMAIN = re.compile(r'dnslog|ceye|burpcollaborator|interactsh', re.IGNORECASE)
_SYSMON_CALLBACK_PROTOCOL = re.compile(r'jndi:(?:ldap|rmi)|(?:ldap|rmi)://', re.IGNORECASE)
_SYSMON_SUSPICIOUS_DOMAIN = re.compile(r'\b(?:c2|beacon|malware|evil|botnet|dga|tunnel|callback)\b', re.IGNORECASE)
_POWERSHELL_CMD = re.compile(r'powershell(?:\.exe)?|pwsh(?:\.exe)?', re.IGNORECASE)
_XMLNS_ATTR_RE = re.compile(r"\s+xmlns(?::[A-Za-z_][\w.-]*)?=(?:\"[^\"]*\"|'[^']*')")

_LOLBINS = re.compile(
    r'mshta\.exe|wscript\.exe|cscript\.exe|'
    r'regsvr32.*scrobj|rundll32.*javascript|'
    r'certutil.*-decode|certutil.*-urlcache|'
    r'bitsadmin.*transfer|forfiles.*cmd|'
    r'pcalua.*-a|syncappvpublishingserver',
    re.IGNORECASE
)

_WMI_PROCESS_NAMES = {"wmic.exe", "wmiprvse.exe", "winrs.exe", "winrshost.exe"}
_WMI_SUBSCRIPTION_CMD = re.compile(
    r'\\root\\subscription|__eventfilter|commandlineeventconsumer|filtertoconsumerbinding',
    re.IGNORECASE,
)
_WMI_CREATE_CMD = re.compile(r'\bcreate\b', re.IGNORECASE)
_DNS_TOOL_CMD = re.compile(r'\b(?:nslookup|resolve-dnsname|dig)(?:\.exe)?\b', re.IGNORECASE)
_DNS_EXFIL_PROCESS_NAMES = {
    "cmd.exe", "nslookup.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "nxc.exe",
}
_AUDITPOL_TAMPER_CMD = re.compile(
    r'\bauditpol(?:\.exe)?\b(?=.*(?:/clear\b|/remove\b|/success\s*:\s*disable|'
    r'/failure\s*:\s*disable|/value\s*:\s*disable|/logon\s*:\s*none|/sd\s*:))',
    re.IGNORECASE,
)
_UAC_BYPASS_REGISTRY_TARGET = re.compile(
    r'\\(?:software\\classes|s-\d-[^\\]+_classes)\\'
    r'(?:ms-settings|mscfile|exefile|folder|directory|launcher\.systemsettings)\\.*'
    r'(?:shell\\open\\command|shell\\runas\\command|delegateexecute|isolatedcommand)|'
    r'\\policies\\system\\localaccounttokenfilterpolicy',
    re.IGNORECASE,
)


def _append_tags(tags: list, *new_tags: str) -> None:
    for tag in new_tags:
        if tag not in tags:
            tags.append(tag)


def _credential_dump_method(command: str) -> Tuple[str, str]:
    if _REGISTRY_HIVE_DUMP_CMD.search(command):
        return "registry-hive-save", "T1003.002"
    if _NTDS_DUMP_CMD.search(command):
        return "ntds-dit-dump", "T1003.003"
    if _LSASS_DUMP_CMD_HINT.search(command):
        return "lsass-memory-dump", "T1003.001"
    return "credential-dump", "T1003"


def _looks_like_lsass_minidump_script(script: str) -> bool:
    text = (script or "").lower()
    return "lsass" in text and "minidumpwritedump" in text


def _sysmon_c2_reason(details: Dict[str, str]) -> str:
    indicators = " ".join(
        value for value in (
            details.get("dns_query", ""),
            details.get("QueryName", ""),
            details.get("destination_host", ""),
            details.get("DestinationHostname", ""),
        )
        if value
    )
    if not indicators:
        return ""
    if _SYSMON_CALLBACK_DOMAIN.search(indicators) or _SYSMON_CALLBACK_PROTOCOL.search(indicators):
        return "callback-domain"
    if _SYSMON_SUSPICIOUS_DOMAIN.search(indicators):
        return "suspicious-domain"
    return ""


def _looks_like_encoded_dns_token(token: str, min_length: int = 24) -> bool:
    token = (token or "").strip().strip(".").strip("=")
    if len(token) < min_length:
        return False
    if not re.fullmatch(r'[A-Za-z0-9_-]+', token):
        return False
    if len(set(token.lower())) < 6:
        return False
    has_upper = any(ch.isupper() for ch in token)
    has_lower = any(ch.islower() for ch in token)
    has_digit = any(ch.isdigit() for ch in token)
    if has_upper and has_lower:
        return True
    return has_digit and (has_upper or has_lower) and len(token) >= 40


def _dns_exfil_reason_for_query(details: Dict[str, str]) -> str:
    query = (
        details.get("dns_query")
        or details.get("QueryName")
        or details.get("destination_host")
        or details.get("DestinationHostname")
        or ""
    ).strip().strip(".")
    if not query:
        return ""
    process = _norm_win_name(details.get("Image") or details.get("process") or "")
    if process and process not in _DNS_EXFIL_PROCESS_NAMES:
        return ""
    labels = [part for part in query.split(".") if part]
    for label in labels[:-1]:
        if _looks_like_encoded_dns_token(label, min_length=40):
            return "encoded-dns-label"
    return ""


def _dns_exfil_reason_for_command(command: str) -> str:
    if not command or not _DNS_TOOL_CMD.search(command):
        return ""
    tokens = re.split(r'[\s"\'<>|&]+', command)
    for token in tokens:
        token = token.strip().strip(",;:()[]{}")
        if _looks_like_encoded_dns_token(token, min_length=16):
            return "encoded-dns-query-command"
    return ""


def _classify_persistence_command(details: Dict[str, str], tags: list, level: ThreatLevel) -> ThreatLevel:
    command = details.get("persistence_command", "")
    if not command:
        return level
    if _DANGEROUS_CMDS.search(command):
        if level.score < ThreatLevel.CRITICAL.score:
            level = ThreatLevel.CRITICAL
        _append_tags(tags, "suspicious-persistence", "command-execution")
        if _POWERSHELL_CMD.search(command):
            _append_tags(tags, "powershell")
        details["persistence_command_risk"] = "dangerous-command"
        details["persistence_alert_confidence"] = "high"
        details["evidence_strength"] = "high"
        details.pop("persistence_baseline", None)
        details.pop("persistence_baseline_reason", None)
        details.pop("false_positive_hint", None)
    elif _LOLBINS.search(command):
        if level.score < ThreatLevel.HIGH.score:
            level = ThreatLevel.HIGH
        _append_tags(tags, "suspicious-persistence", "lolbin")
        details["persistence_command_risk"] = "lolbin"
        details["persistence_alert_confidence"] = "medium"
        details["evidence_strength"] = "medium"
        details.pop("persistence_baseline", None)
        details.pop("persistence_baseline_reason", None)
        details.pop("false_positive_hint", None)
    return level


def _classify_event(eid: int, details: Dict[str, str], channel: str) -> Tuple[ThreatLevel, str, str, list, Optional[str], Optional[str]]:
    """返回 (level, category, message, tags, mitre, rule_name)"""
    rule = _WIN_RULES.get(eid)
    if not rule:
        return ThreatLevel.INFO, channel or "Windows", f"事件 ID {eid}", [], None, None

    level = rule["level"]
    msg   = rule["msg"](details)
    tags  = list(rule["tags"])
    mitre = rule.get("mitre")
    rule_name = rule.get("rule")

    if eid in (4728, 4732, 4756):
        sensitivity = details.get("group_sensitivity", "unknown")
        if sensitivity == "low":
            level = ThreatLevel.INFO
            tags = [tag for tag in tags if tag not in ("group-add", "privilege-escalation")]
            tags.append("baseline-change")
            mitre = None
        elif sensitivity == "unknown":
            level = ThreatLevel.MEDIUM
            tags = [tag for tag in tags if tag != "privilege-escalation"]
            details.setdefault("false_positive_hint", "Group is not in the privileged-group baseline; verify business baseline before escalation.")

    if eid == 4720 and details.get("account_sensitivity") == "system-initialization":
        level = ThreatLevel.INFO
        tags = [tag for tag in tags if tag not in ("account-creation", "persistence")]
        tags.append("system-initialization")
        mitre = None

    if eid == 4648 and _is_local_explicit_credential_use(details):
        level = ThreatLevel.INFO
        tags = [tag for tag in tags if tag not in ("explicit-creds", "lateral-movement")]
        tags.append("local-explicit-creds")
        details["credential_use_scope"] = "local-system"
        details["evidence_strength"] = "low"
        details["false_positive_hint"] = "Localhost or machine-account explicit credential use; not enough evidence for Pass-the-Hash or lateral movement."
        mitre = None

    if eid == 4624:
        lt = _safe_int(details.get("LogonType", "0"))
        if lt == 10:
            tags.extend(["remote-logon", "remote-access", "rdp"])
            details["remote_access_type"] = "rdp"
        elif lt == 3 and details.get("source_ip"):
            tags.extend(["network-logon", "remote-access"])
            details["remote_access_type"] = "network"

    # 动态级别升级
    if eid == 4625:
        lt = _safe_int(details.get("LogonType", "0"))
        if lt in (3, 10):
            level = ThreatLevel.HIGH  # 网络/RDP 失败登录更危险

    if eid == 4776:
        if _is_success_status(details.get("status_code", "") or details.get("Status", "")):
            level = ThreatLevel.INFO
            tags.append("auth-success")
            mitre = None
        else:
            level = ThreatLevel.MEDIUM
            tags.append("failed-logon")
            mitre = "T1110.001"

    if eid in (4688, 1):
        cmd = " ".join(
            value for value in (
                details.get("CommandLine", ""),
                details.get("NewProcessName", ""),
                details.get("Image", ""),
            )
            if value
        )
        child = _norm_win_name(details.get("child_process") or details.get("Image") or details.get("NewProcessName", ""))
        wmi_subscription_command = bool(_WMI_SUBSCRIPTION_CMD.search(cmd))
        if child in _WMI_PROCESS_NAMES or wmi_subscription_command:
            _append_tags(tags, "wmi")
            details.setdefault("execution_context", "wmi")
        if wmi_subscription_command and _WMI_CREATE_CMD.search(cmd):
            if level.score < ThreatLevel.HIGH.score:
                level = ThreatLevel.HIGH
            _append_tags(tags, "wmi-persistence", "persistence")
            details["persistence_mechanism"] = "wmi-event-subscription"
            details["persistence_command"] = cmd
            details["persistence_alert_confidence"] = "high"
            details["evidence_strength"] = "high"
            mitre = "T1546.003"
        auditpol_reason = "audit-policy-tampering" if _AUDITPOL_TAMPER_CMD.search(cmd) else ""
        if auditpol_reason:
            if level.score < ThreatLevel.CRITICAL.score:
                level = ThreatLevel.CRITICAL
            _append_tags(tags, "audit-policy", "defense-evasion", "auditpol-tampering")
            details["defense_evasion_method"] = auditpol_reason
            details["evidence_strength"] = "high"
            mitre = "T1562.002"
            rule_name = "审计策略命令篡改"
        dns_exfil_reason = _dns_exfil_reason_for_command(cmd)
        if dns_exfil_reason:
            if level.score < ThreatLevel.HIGH.score:
                level = ThreatLevel.HIGH
            _append_tags(tags, "dns-exfiltration", "dns-tunnel", "data-exfiltration")
            details["exfiltration_channel"] = "dns"
            details["exfiltration_indicator_type"] = dns_exfil_reason
            details["evidence_strength"] = "medium"
            mitre = "T1048.003"
            rule_name = "DNS 数据外传命令"
        if _CREDENTIAL_DUMP_CMDS.search(cmd):
            method, mitre = _credential_dump_method(cmd)
            level = ThreatLevel.CRITICAL
            _append_tags(tags, "credential-access", "credential-dump", "malware-indicator")
            if method == "lsass-memory-dump":
                _append_tags(tags, "lsass-dump")
            details["credential_dump_method"] = method
            details["evidence_strength"] = "high"
        elif _DANGEROUS_CMDS.search(cmd):
            level = ThreatLevel.CRITICAL
            _append_tags(tags, "malware-indicator")
            mitre = "T1059"
        elif _LOLBINS.search(cmd):
            level = ThreatLevel.HIGH
            _append_tags(tags, "lolbin")
            mitre = "T1218"

    if eid in (3, 22):
        dns_exfil_reason = _dns_exfil_reason_for_query(details)
        if dns_exfil_reason:
            if level.score < ThreatLevel.HIGH.score:
                level = ThreatLevel.HIGH
            _append_tags(tags, "dns-exfiltration", "dns-tunnel", "data-exfiltration")
            details["exfiltration_channel"] = "dns"
            details["exfiltration_indicator_type"] = dns_exfil_reason
            details["evidence_strength"] = "medium"
            mitre = "T1048.003"
            rule_name = "DNS 数据外传"
        c2_reason = _sysmon_c2_reason(details)
        if c2_reason:
            level = ThreatLevel.HIGH
            _append_tags(tags, "c2", "malicious-domain")
            if c2_reason == "callback-domain":
                _append_tags(tags, "callback-domain")
            details["c2_indicator_type"] = c2_reason
            details["evidence_strength"] = "medium"
            if not dns_exfil_reason:
                mitre = "T1071.004" if eid == 22 else "T1071"

    if eid in (19, 20, 21):
        operation = (details.get("wmi_operation") or details.get("Operation") or "").strip().lower()
        if operation == "created":
            if level.score < ThreatLevel.HIGH.score:
                level = ThreatLevel.HIGH
            _append_tags(tags, "wmi-persistence", "persistence")
            details["persistence_alert_confidence"] = "high"
            details["evidence_strength"] = "high"
        elif operation == "deleted":
            details["persistence_alert_confidence"] = "low"
            details["evidence_strength"] = "medium"
        else:
            details["persistence_alert_confidence"] = "medium"
            details["evidence_strength"] = "medium"

    if eid in (7045, 4698, 4702, 19, 20, 21):
        level = _classify_persistence_command(details, tags, level)

    if eid == 4104:
        script = details.get("ScriptBlockText", "")
        if _looks_like_lsass_minidump_script(script):
            level = ThreatLevel.CRITICAL
            _append_tags(tags, "credential-access", "credential-dump", "lsass-dump", "malware-indicator")
            details["credential_dump_method"] = "lsass-memory-dump"
            details["evidence_strength"] = "high"
            mitre = "T1003.001"
        elif _DANGEROUS_CMDS.search(script):
            level = ThreatLevel.CRITICAL
            tags.append("malware-indicator")
        elif re.search(r'invoke-|iex\s*\(|base64|webclient|downloadstring', script, re.I):
            level = ThreatLevel.HIGH

    if eid == 10:  # Sysmon 进程访问
        target = details.get("TargetImage", "").lower()
        if "lsass" in target:
            level = ThreatLevel.CRITICAL
            _append_tags(tags, "lsass", "lsass-dump", "credential-access")
            details["credential_dump_method"] = "lsass-memory-dump"
            details["evidence_strength"] = "high"
            mitre = "T1003.001"

    if eid in (12, 13, 14):
        target = _norm_win_path_text(details.get("TargetObject", ""))
        if _UAC_BYPASS_REGISTRY_TARGET.search(target):
            if level.score < ThreatLevel.HIGH.score:
                level = ThreatLevel.HIGH
            tags = [tag for tag in tags if tag != "persistence"]
            _append_tags(tags, "uac-bypass", "privilege-escalation", "defense-evasion")
            details["privilege_escalation_method"] = "uac-bypass-registry"
            details["evidence_strength"] = "high"
            mitre = "T1548.002"
            rule_name = "UAC 绕过注册表修改"

    return level, rule["cat"], msg, tags, mitre, rule_name


def _safe_int(value: str, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _is_success_status(value: str) -> bool:
    return str(value or "").strip().lower() in {"0", "0x0", "0x00000000", "success"}


def _parse_xml_event_with_error(xml_text: str, source_file: str) -> Tuple[Optional[LogEvent], Optional[Exception]]:
    """解析单个 <Event> XML 块，并返回异常对象（如有）便于上层统计错误数。"""
    try:
        return _parse_xml_event(xml_text, source_file), None
    except Exception as e:  # noqa: BLE001 — XML 行级失败不应中断整个分析
        return None, e


def build_windows_event_from_fields(
    eid: int,
    eid_str: str,
    ts_raw: str,
    computer: str,
    channel: str,
    details: Dict[str, str],
    source_file: str,
    raw_line: str,
) -> LogEvent:
    """Build a LogEvent from normalized Windows EventLog fields."""
    _augment_auth_details(eid, details)
    _augment_ntlm_details(eid, details)
    _augment_account_management_details(eid, details)
    _augment_explicit_credential_details(eid, details)
    _augment_4688_details(eid, details)
    _augment_sysmon_details(eid, details)
    _augment_persistence_details(eid, details)

    if eid in (4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4738, 4756):
        user = details.get("subject_user") or details.get("target_user") or ""
    elif eid == 4776:
        user = details.get("account_name") or details.get("TargetUserName") or ""
    else:
        user = details.get("account_name") or details.get("TargetUserName") or details.get("SubjectUserName") or ""
    ip = details.get("source_ip") or details.get("IpAddress") or details.get("SourceAddress") or ""
    if eid == 3:
        if _truthy_win_value(details.get("initiated", "")):
            ip = details.get("destination_ip") or ip
        else:
            ip = details.get("source_ip") or details.get("destination_ip") or ip
    process = details.get("NewProcessName") or details.get("ProcessName") or details.get("Image") or ""

    level, cat, msg, tags, mitre, rule_name = _classify_event(eid, details, channel)
    source_channel = channel or "Windows"

    return LogEvent(
        id=gen_id("win"),
        timestamp=normalize_timestamp(ts_raw),
        level=level,
        category=cat,
        source=f"{source_channel} (EID:{eid_str})",
        source_file=source_file,
        message=msg,
        raw_line=raw_line[:300],
        event_id=eid_str,
        user=user or None,
        host=computer or None,
        ip=ip or None,
        process=process or None,
        details=details,
        tags=tags,
        mitre_attack=mitre,
        rule_id=f"WIN-{eid_str}",
        rule_name=rule_name,
    )


def _parse_xml_event(xml_text: str, source_file: str) -> Optional[LogEvent]:
    """解析单个 <Event> XML 块。

    解析异常会向上抛出，由 :func:`_parse_xml_event_with_error` 捕获并记入
    ``ParseStats.parse_errors``，避免静默丢事件。
    """

    xml_clean = _XMLNS_ATTR_RE.sub("", xml_text)
    root = ET.fromstring(xml_clean)

    sys_el = root.find("System")
    if sys_el is None:
        return None

    def gtag(tag: str) -> str:
        el = sys_el.find(tag)
        return el.text.strip() if el is not None and el.text else ""

    eid_str = gtag("EventID") or ""
    eid = int(eid_str) if eid_str.isdigit() else 0
    ts_raw = ""
    tc = sys_el.find("TimeCreated")
    if tc is not None:
        ts_raw = tc.get("SystemTime", "")
    computer = gtag("Computer")
    channel  = gtag("Channel")

    # EventData
    details: Dict[str, str] = {}
    ed = root.find("EventData")
    if ed is not None:
        for data in ed.findall("Data"):
            name = data.get("Name", "")
            val  = data.text or ""
            if name:
                details[name] = val.strip()

    return build_windows_event_from_fields(
        eid=eid,
        eid_str=eid_str,
        ts_raw=ts_raw,
        computer=computer,
        channel=channel,
        details=details,
        source_file=source_file,
        raw_line=xml_text,
    )


_XML_EVENT_RE = re.compile(r'<Event[\s>][\s\S]*?</Event>', re.IGNORECASE)
_XML_EVENT_START_RE = re.compile(r'<Event(?=[\s>])', re.IGNORECASE)


def _iter_xml_event_blocks_from_text(content: str):
    last_end = 0
    for match in _XML_EVENT_RE.finditer(content):
        yield match.group()
        last_end = match.end()
    tail_start = _last_xml_event_start(content[last_end:])
    if tail_start >= 0:
        yield content[last_end + tail_start:]


def _iter_xml_event_blocks_from_chunks(chunks):
    """Yield complete ``<Event>...</Event>`` blocks while keeping only a small tail buffer."""
    buffer = ""
    for chunk in chunks:
        buffer += chunk
        while True:
            match = _XML_EVENT_RE.search(buffer)
            if not match:
                tail_start = _last_xml_event_start(buffer)
                buffer = buffer[tail_start:] if tail_start >= 0 else buffer[-64:]
                break
            yield match.group()
            buffer = buffer[match.end():]
    tail_start = _last_xml_event_start(buffer)
    if tail_start >= 0:
        yield buffer[tail_start:]


def _last_xml_event_start(text: str) -> int:
    last = -1
    for match in _XML_EVENT_START_RE.finditer(text):
        last = match.start()
    return last


def _parse_windows_xml_blocks(blocks, source_file: str, file_size_bytes: int, t0: float) -> ParseResult:
    events: List[LogEvent] = []
    parse_errors = 0
    for block in blocks:
        ev, err = _parse_xml_event_with_error(block, source_file)
        if ev:
            events.append(ev)
        elif err:
            parse_errors += 1

    stats = _compute_stats(events)
    stats.parse_errors = parse_errors
    return ParseResult(
        file_name      = source_file,
        log_type       = "Windows Event Log (XML)",
        events         = events,
        stats          = stats,
        parse_time_ms  = (time.time() - t0) * 1000,
        file_size_bytes= file_size_bytes,
    )


def parse_windows_xml(content: str, source_file: str) -> ParseResult:
    """解析内存中的 Windows XML 事件日志。"""
    t0 = time.time()
    return _parse_windows_xml_blocks(
        _iter_xml_event_blocks_from_text(content),
        source_file,
        len(content.encode()),
        t0,
    )


def parse_windows_xml_file(path: str, source_file: Optional[str] = None) -> ParseResult:
    """从文件流式解析 Windows XML，避免大日志一次性读入内存。"""
    t0 = time.time()
    source_name = source_file or os.path.basename(path)
    return _parse_windows_xml_blocks(
        _iter_xml_event_blocks_from_chunks(iter_file_chunks(path)),
        source_name,
        file_size(path),
        t0,
    )


def parse_windows_evtx(path: str) -> ParseResult:
    """
    解析二进制 EVTX 文件（需要 python-evtx）
    如未安装则抛出阻断型错误，避免生成"看似分析完成"的空报告。
    """
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views  # noqa: F401  imported for side effects
        t0 = time.time()
        events: List[LogEvent] = []
        parse_errors = 0
        with evtx.Evtx(path) as log:
            for record in log.records():
                try:
                    xml_text = record.xml()
                except Exception:
                    parse_errors += 1
                    continue
                ev, err = _parse_xml_event_with_error(xml_text, path)
                if ev:
                    events.append(ev)
                elif err:
                    parse_errors += 1
        stats = _compute_stats(events)
        stats.parse_errors = parse_errors
        return ParseResult(
            file_name     = path,
            log_type      = "Windows EVTX (Binary)",
            events        = events,
            stats         = stats,
            parse_time_ms = (time.time() - t0) * 1000,
            file_size_bytes=os.path.getsize(path) if os.path.exists(path) else 0,
        )
    except ImportError as exc:
        raise MissingOptionalDependency(
            "缺少可选依赖 python-evtx，EVTX 二进制日志未被解析。"
            "请先执行 python3 -m pip install -U \"blueteam-log-analyzer[evtx]\" 后重新运行；"
            "如果目标主机不方便安装 Python，可在 Windows 上用 "
            "wevtutil qe Security /f:RenderedXml /e:Events > Security.xml "
            "导出 XML 后再分析。"
        ) from exc


def _compute_stats(events: List[LogEvent]) -> ParseStats:
    from ..parsers.stats import compute_stats
    return compute_stats(events)
