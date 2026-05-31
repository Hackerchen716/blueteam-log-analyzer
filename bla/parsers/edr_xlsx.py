"""EDR Excel export parser.

The parser targets spreadsheet exports commonly produced by endpoint products
for process telemetry. It streams worksheet rows from the XLSX ZIP container
with the standard library, then emits generic EDR ``LogEvent`` objects for the
detector layer. It does not query any external reputation service.
"""

from __future__ import annotations

import csv
import datetime
import io
import os
import re
import time
import zipfile
from typing import Dict, Iterable, Iterator, List, Optional, Tuple
from xml.etree.ElementTree import iterparse

from ..models import LogEvent, ParseResult, ThreatLevel
from ..utils.helpers import file_size, gen_id, normalize_timestamp, truncate
from .stats import compute_stats

_MAX_CELL_TEXT = 4096
_MAX_SHARED_STRINGS = 200000
_HEADER_ALIASES = {
    "事件类型": "event_type",
    "eventtype": "event_type",
    "event_type": "event_type",
    "log_type": "event_type",
    "type": "event_type",
    "事件子类型": "event_subtype",
    "eventsubtype": "event_subtype",
    "event_subtype": "event_subtype",
    "subtype": "event_subtype",
    "operation": "event_subtype",
    "时间": "timestamp",
    "time": "timestamp",
    "timestamp": "timestamp",
    "@timestamp": "timestamp",
    "event_time": "timestamp",
    "进程用户名": "user",
    "username": "user",
    "user": "user",
    "account": "user",
    "进程id": "process_id",
    "processid": "process_id",
    "process_id": "process_id",
    "pid": "process_id",
    "进程名": "process_name",
    "process": "process_name",
    "processname": "process_name",
    "process_name": "process_name",
    "image": "process_name",
    "filename": "process_name",
    "进程映像路径": "process_path",
    "process_path": "process_path",
    "processpath": "process_path",
    "image_path": "process_path",
    "imagepath": "process_path",
    "processimage": "process_path",
    "进程文件签名": "process_signature",
    "process_signature": "process_signature",
    "processsigner": "process_signature",
    "signer": "process_signature",
    "publisher": "process_signature",
    "signature": "process_signature",
    "进程sha1值": "process_sha1",
    "process_sha1": "process_sha1",
    "processsha1": "process_sha1",
    "sha1": "process_sha1",
    "目标进程pid": "target_pid",
    "target_pid": "target_pid",
    "targetprocessid": "target_pid",
    "进程事件文件路径": "target_path",
    "target_path": "target_path",
    "targetpath": "target_path",
    "file_path": "target_path",
    "filepath": "target_path",
    "path": "target_path",
    "目标进程文件签名": "target_signature",
    "target_signature": "target_signature",
    "targetsigner": "target_signature",
    "file_signature": "target_signature",
    "文件sha1值": "file_sha1",
    "file_sha1": "file_sha1",
    "filesha1": "file_sha1",
    "hash": "file_sha1",
    "文件类型": "file_type",
    "file_type": "file_type",
    "ext": "file_type",
    "文件大小": "file_size",
    "file_size": "file_size",
    "size": "file_size",
    "上次修改时间": "modified_time",
    "modified_time": "modified_time",
    "mtime": "modified_time",
    "创建时间": "created_time",
    "created_time": "created_time",
    "ctime": "created_time",
    "最后访问时间": "accessed_time",
    "accessed_time": "accessed_time",
    "atime": "accessed_time",
    "进程命令": "command",
    "command": "command",
    "cmd": "command",
    "commandline": "command",
    "command_line": "command",
    "cmdline": "command",
}
_REQUIRED_HINTS = {"event_type", "event_subtype", "timestamp", "process_name"}
_PROCESS_EVENT_RE = re.compile(r"process|进程|线程|驱动", re.I)
_REMOTE_THREAD_RE = re.compile(r"remote.?thread|远程线程", re.I)
_PROCESS_CREATE_RE = re.compile(r"process.?creat|进程创建|启动|创建", re.I)
_PROCESS_LOAD_RE = re.compile(r"process.?load|image.?load|进程加载|模块加载|驱动加载", re.I)
_USER_WRITABLE_RE = re.compile(
    r"(?:\\users\\[^\\]+\\(?:downloads|desktop|documents|appdata\\local\\temp)\\|"
    r"/users/[^/]+/(?:downloads|desktop|documents|appdata/local/temp)/|"
    r"\\programdata\\|/programdata/|\\inetpub\\wwwroot\\|/inetpub/wwwroot/)",
    re.I,
)
_TEMP_INSTALLER_RE = re.compile(r"(?:\\|/)(?:appdata\\local\\temp|temp)(?:\\|/).*?(?:\\|/)is-[^\\/]+\.tmp(?:\\|/)", re.I)
_EXECUTABLE_RE = re.compile(r"\.(?:exe|dll|scr|com|tmp|ps1|bat|cmd|vbs|js|jar)(?:$|[\"'\s])", re.I)
_RANDOM_STEM_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9]{6,16}$")
_MIXED_RANDOM_SEGMENT_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])[A-Za-z0-9]{5,16}$")
_RANDOM_TASK_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_-]{6,40}$")
_BRAND_RE = re.compile(
    r"(?:tencent|meeting|wemeet|wechat|weixin|dingtalk|qq|chrome|edge|office|word|excel|adobe|zoom|teams)",
    re.I,
)
_TASK_DELETE_RE = re.compile(r"\bschtasks(?:\.exe)?\b.*(?:^|\s)/delete\b.*(?:^|\s)/tn\s+\"?([^\"\s]+)", re.I)
_ICACLS_ACL_RE = re.compile(r"\bicacls(?:\.exe)?\b.*(?:^|\s)/(?:deny|grant)\b", re.I)
_PORTPROXY_RESET_RE = re.compile(r"\bnetsh(?:\.exe)?\"?\s+interface\s+portproxy\s+reset\b", re.I)
_SEVEN_ZIP_EXTRACT_RE = re.compile(r"\b7zG?\.exe\"?\s+x\b.*(?:^|\s)-o\"?([^\"\s]+)", re.I)
_SECURITY_COMPONENT_RE = re.compile(
    r"(?:Guangzhou TEC Solutions|TAuxMod|dtsframe|dtframe|winahframe|winahdcore|TMailHook|TIjtDrvd|winncap|thooksv)",
    re.I,
)
_COMMON_PATH_SEGMENTS = {
    "administrator", "admini~1", "users", "downloads", "documents", "desktop",
    "appdata", "local", "temp", "program files", "program files (x86)",
    "windows", "system32", "syswow64", "inetpub", "wwwroot", "tencent",
    "wemeet", "meeting", "tencentmeeting", "officialwebsite",
}


def looks_like_edr_xlsx(file_path: str, sample_text: str = "") -> bool:
    """Return True for XLSX files whose first sheet looks like EDR telemetry."""
    if not str(file_path).lower().endswith(".xlsx"):
        return False
    try:
        rows = []
        for _, row in _iter_xlsx_rows(file_path, max_rows=3):
            rows.append(row)
    except (OSError, KeyError, ValueError, zipfile.BadZipFile):
        return False
    return any(_header_score(row) >= 6 for row in rows)


def parse_edr_xlsx_file(path: str, source_file: Optional[str] = None) -> ParseResult:
    """Parse an EDR XLSX export without materializing worksheet XML."""
    t0 = time.time()
    source_name = source_file or os.path.basename(path)
    events: List[LogEvent] = []
    parse_errors = 0
    header: List[Tuple[int, str]] = []

    try:
        for row_number, row in _iter_xlsx_rows(path):
            if not any(str(item).strip() for item in row):
                continue
            if not header:
                candidate = _normalize_header(row)
                if len({name for _, name in candidate}) >= 6 and _REQUIRED_HINTS.issubset({name for _, name in candidate}):
                    header = candidate
                continue
            fields = _fields_from_row(header, row)
            event = _event_from_fields(fields, source_name, row_number)
            if event:
                events.append(event)
    except (OSError, KeyError, ValueError, zipfile.BadZipFile):
        parse_errors += 1

    stats = compute_stats(events)
    stats.parse_errors += parse_errors
    return ParseResult(
        file_name=source_name,
        log_type="EDR Excel Export",
        events=events,
        stats=stats,
        parse_time_ms=(time.time() - t0) * 1000,
        file_size_bytes=file_size(path),
    )


def parse_edr_xlsx_content(content: str, source_file: str) -> ParseResult:
    """Parse CSV/TSV text copied from an EDR spreadsheet export."""
    t0 = time.time()
    events: List[LogEvent] = []
    delimiter = "\t" if content.splitlines()[0:1] and content.splitlines()[0].count("\t") >= content.splitlines()[0].count(",") else ","
    reader = csv.reader(io.StringIO(content), delimiter=delimiter)
    header: List[Tuple[int, str]] = []
    for row_number, row in enumerate(reader, start=1):
        if not row or not any(str(item).strip() for item in row):
            continue
        if not header:
            header = _normalize_header(row)
            continue
        event = _event_from_fields(_fields_from_row(header, row), source_file, row_number)
        if event:
            events.append(event)
    stats = compute_stats(events)
    return ParseResult(
        file_name=source_file,
        log_type="EDR Excel Export",
        events=events,
        stats=stats,
        parse_time_ms=(time.time() - t0) * 1000,
        file_size_bytes=len(content.encode()),
    )


def _iter_xlsx_rows(path: str, max_rows: Optional[int] = None) -> Iterator[Tuple[int, List[str]]]:
    with zipfile.ZipFile(path) as archive:
        shared_strings = _read_shared_strings(archive)
        worksheet_names = sorted(name for name in archive.namelist() if name.startswith("xl/worksheets/sheet") and name.endswith(".xml"))
        if not worksheet_names:
            raise ValueError("xlsx has no worksheets")
        yielded = 0
        for worksheet_name in worksheet_names:
            with archive.open(worksheet_name) as handle:
                for _, elem in iterparse(handle, events=("end",)):
                    if _local_name(elem.tag) != "row":
                        continue
                    row_number = int(elem.attrib.get("r", "0") or "0")
                    values: Dict[int, str] = {}
                    for cell in list(elem):
                        if _local_name(cell.tag) != "c":
                            continue
                        ref = cell.attrib.get("r", "")
                        col = _column_index(ref)
                        if col is None:
                            continue
                        values[col] = _cell_value(cell, shared_strings)
                    if values:
                        yielded += 1
                        yield row_number, [values.get(idx, "") for idx in range(max(values) + 1)]
                        if max_rows is not None and yielded >= max_rows:
                            return
                    elem.clear()


def _read_shared_strings(archive: zipfile.ZipFile) -> List[str]:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return []
    strings: List[str] = []
    with archive.open("xl/sharedStrings.xml") as handle:
        for _, elem in iterparse(handle, events=("end",)):
            if _local_name(elem.tag) != "si":
                continue
            text = "".join(node.text or "" for node in elem.iter() if _local_name(node.tag) == "t")
            strings.append(text[:_MAX_CELL_TEXT])
            if len(strings) >= _MAX_SHARED_STRINGS:
                break
            elem.clear()
    return strings


def _cell_value(cell, shared_strings: List[str]) -> str:
    cell_type = cell.attrib.get("t", "")
    if cell_type == "inlineStr":
        return _inline_text(cell)
    value = ""
    for child in list(cell):
        name = _local_name(child.tag)
        if name == "v":
            value = child.text or ""
            break
        if name == "is":
            value = "".join(node.text or "" for node in child.iter() if _local_name(node.tag) == "t")
            break
    if cell_type == "s":
        try:
            return shared_strings[int(value)]
        except (ValueError, IndexError):
            return ""
    if cell_type == "b":
        return "TRUE" if value == "1" else "FALSE"
    return value[:_MAX_CELL_TEXT]


def _inline_text(cell) -> str:
    return "".join(node.text or "" for node in cell.iter() if _local_name(node.tag) == "t")[:_MAX_CELL_TEXT]


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _column_index(ref: str) -> Optional[int]:
    match = re.match(r"([A-Z]+)", ref.upper())
    if not match:
        return None
    index = 0
    for char in match.group(1):
        index = index * 26 + (ord(char) - ord("A") + 1)
    return index - 1


def _normalize_header(row: Iterable[str]) -> List[Tuple[int, str]]:
    result = []
    for index, value in enumerate(row):
        key = _canonical_key(value)
        if key:
            result.append((index, key))
    return result


def _header_score(row: Iterable[str]) -> int:
    return len({name for _, name in _normalize_header(row)})


def _canonical_key(value: object) -> str:
    text = str(value or "").strip().lower().replace(" ", "").replace("-", "_")
    return _HEADER_ALIASES.get(text, "")


def _fields_from_row(header: List[Tuple[int, str]], row: List[str]) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for index, key in header:
        value = row[index] if index < len(row) else ""
        if value:
            fields[key] = str(value).strip()
    return fields


def _event_from_fields(fields: Dict[str, str], source_file: str, row_number: int) -> Optional[LogEvent]:
    event_type = _field(fields, "event_type")
    subtype = _field(fields, "event_subtype")
    if not _PROCESS_EVENT_RE.search(" ".join((event_type, subtype))):
        return None

    timestamp = _normalize_time(_field(fields, "timestamp"))
    process_name = _basename(_field(fields, "process_name") or _field(fields, "process_path"))
    process_path = _field(fields, "process_path")
    process_signature = _field(fields, "process_signature")
    target_path = _field(fields, "target_path")
    target_name = _basename(target_path)
    target_signature = _field(fields, "target_signature")
    command = _field(fields, "command")
    details = dict(fields)
    details.update({
        "p0_kind": "edr",
        "source_type": "edr",
        "row_number": str(row_number),
        "action": subtype,
        "process": process_name,
        "target_process": target_name,
        "parent_process": process_path,
        "child_process": target_name,
        "child_path": target_path,
        "command_line": command,
    })
    tags = ["edr", "process-event"]
    is_create = bool(_PROCESS_CREATE_RE.search(subtype))
    is_load = bool(_PROCESS_LOAD_RE.search(subtype))
    is_remote_thread = bool(_REMOTE_THREAD_RE.search(subtype))
    if _PROCESS_CREATE_RE.search(subtype):
        tags.append("process-create")
    if _PROCESS_LOAD_RE.search(subtype):
        tags.append("process-load")

    level = ThreatLevel.INFO
    mitre = None
    rule_id = None
    rule_name = None
    reasons: List[str] = []
    suspicious_path = _first_path(process_path, target_path)

    task_name = _schtasks_delete_task(command)
    acl_path = _icacls_random_acl_path(command)
    archive_output = _archive_extract_output(command)
    if is_create and task_name:
        level = ThreatLevel.HIGH
        mitre = "T1053.005"
        rule_id = "EDR-XLSX-SCHTASKS-DELETE"
        rule_name = "EDR 随机计划任务删除"
        tags.extend(["scheduled-task", "task-cleanup", "defense-evasion", "edr-key-evidence", "lolbin"])
        details["task_name"] = task_name
        details["event_family"] = "persistence"
        reasons.append("random-scheduled-task-delete")
    elif is_create and acl_path:
        level = ThreatLevel.HIGH
        mitre = "T1222.001"
        rule_id = "EDR-XLSX-RANDOM-ACL"
        rule_name = "EDR 随机目录 ACL 修改"
        tags.extend(["acl-modification", "defense-evasion", "random-path", "edr-key-evidence", "lolbin"])
        if _is_webroot_path(acl_path):
            tags.append("webroot-executable")
        details["acl_path"] = acl_path
        details["event_family"] = "defense-evasion"
        reasons.append("random-directory-acl-change")
    elif is_create and _PORTPROXY_RESET_RE.search(command or ""):
        level = ThreatLevel.MEDIUM
        rule_id = "EDR-XLSX-PORTPROXY-RESET"
        rule_name = "EDR 端口转发配置重置"
        tags.extend(["portproxy-reset", "network-config", "edr-key-evidence", "lolbin"])
        details["event_family"] = "network"
        reasons.append("portproxy-reset")
    elif is_create and archive_output:
        level = ThreatLevel.MEDIUM
        mitre = "T1204.002"
        rule_id = "EDR-XLSX-ARCHIVE-EXTRACT"
        rule_name = "EDR 用户解压可疑安装目录"
        tags.extend(["archive-extract", "user-execution", "edr-key-evidence"])
        details["archive_output_path"] = archive_output
        details["event_family"] = "execution"
        suspicious_path = archive_output
        reasons.append("archive-extract-to-brand-like-user-dir")
    elif is_load and _is_common_security_component_load(target_path, target_signature):
        tags.extend(["security-component-load", "context-only"])
        details["event_family"] = "other"
        reasons.append("common-security-component-load")
    elif is_remote_thread and _is_suspicious_unsigned_execution(fields):
        level = ThreatLevel.HIGH
        mitre = "T1055"
        rule_id = "EDR-XLSX-REMOTE-THREAD"
        rule_name = "EDR 远程线程创建"
        tags.extend(["process-injection", "suspicious-execution"])
        details["event_family"] = "defense-evasion"
        reasons.append("remote-thread")
    elif is_remote_thread:
        level = ThreatLevel.MEDIUM
        mitre = "T1055"
        rule_id = "EDR-XLSX-REMOTE-THREAD"
        rule_name = "EDR 远程线程创建"
        tags.append("process-injection")
        details["event_family"] = "defense-evasion"
        reasons.append("remote-thread-observed")
    elif _is_suspicious_unsigned_execution(fields):
        level = ThreatLevel.HIGH
        rule_id = "EDR-XLSX-UNSIGNED-USER-PROCESS"
        rule_name = "EDR 可疑无签名进程"
        target_is_masquerade = _looks_like_masquerade(target_name, target_path, target_signature)
        process_is_masquerade = _looks_like_masquerade(process_name, process_path, process_signature)
        mitre = "T1036" if (process_is_masquerade or target_is_masquerade) else "T1204.002"
        tags.extend(["unsigned-process", "user-writable-path", "suspicious-execution", "edr-key-evidence"])
        details["event_family"] = "defense-evasion" if mitre == "T1036" else "execution"
        if process_is_masquerade or target_is_masquerade:
            tags.append("masquerading")
            reasons.append("brand-like-unsigned-user-path")
        if _looks_like_random_user_exec(process_name, process_path) or _looks_like_random_user_exec(target_name, target_path):
            tags.append("random-name")
            reasons.append("random-looking-user-path-executable")
        if _looks_like_dropper(fields):
            tags.append("dropper")
            reasons.append("unsigned-parent-child-user-path")
        if _is_webroot_path(process_path) or _is_webroot_path(target_path):
            tags.append("webroot-executable")
            reasons.append("webroot-executable")
    elif _is_unsigned_user_writable(process_path, process_signature) or _is_unsigned_user_writable(target_path, target_signature):
        level = ThreatLevel.MEDIUM
        rule_id = "EDR-XLSX-UNSIGNED-USER-PATH"
        rule_name = "EDR 用户目录无签名进程迹象"
        mitre = "T1204.002"
        tags.extend(["unsigned-process", "user-writable-path"])
        details["event_family"] = "execution"
        reasons.append("unsigned-user-writable-path")

    if reasons:
        details["suspicion_reasons"] = ",".join(dict.fromkeys(reasons))

    actor = process_name or "?"
    target = target_name or (truncate(target_path, 80) if target_path else "?")
    special_message = _special_message(rule_id, subtype, actor, target, details)
    message = special_message or f"EDR {subtype or '进程事件'}: {actor}"
    if target != "?":
        message += f" -> {target}"
    if not special_message and level.score >= ThreatLevel.HIGH.score and suspicious_path:
        message += f" 路径={truncate(suspicious_path, 100)}"
    if not special_message and command and level.score >= ThreatLevel.HIGH.score:
        message += f" 命令={truncate(command, 100)}"

    return LogEvent(
        id=gen_id("edr"),
        timestamp=timestamp,
        level=level,
        category="EDR",
        source="EDR/XDR",
        source_file=source_file,
        message=message,
        raw_line=_raw_line(fields),
        user=_field(fields, "user") or None,
        process=process_name or target_name or None,
        details=details,
        tags=list(dict.fromkeys(tags)),
        mitre_attack=mitre,
        rule_id=rule_id,
        rule_name=rule_name,
    )


def _normalize_time(value: str) -> str:
    if re.fullmatch(r"\d+(?:\.\d+)?", value or ""):
        try:
            serial = float(value)
            if serial > 20000:
                return (datetime.datetime(1899, 12, 30) + datetime.timedelta(days=serial)).strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass
    return normalize_timestamp(value)


def _is_suspicious_unsigned_execution(fields: Dict[str, str]) -> bool:
    subtype = _field(fields, "event_subtype")
    if not (_PROCESS_CREATE_RE.search(subtype) or _PROCESS_LOAD_RE.search(subtype) or _REMOTE_THREAD_RE.search(subtype)):
        return False
    process_name = _basename(_field(fields, "process_name") or _field(fields, "process_path"))
    process_path = _field(fields, "process_path")
    process_signature = _field(fields, "process_signature")
    target_path = _field(fields, "target_path")
    target_name = _basename(target_path)
    target_signature = _field(fields, "target_signature")
    if _PROCESS_LOAD_RE.search(subtype):
        if _is_common_security_component_load(target_path, target_signature):
            return False
        return bool(
            _looks_like_random_user_exec(target_name, target_path)
            or _is_unsigned_user_writable(target_path, target_signature)
            or (_is_webroot_path(target_path) and _is_unsigned(target_signature))
        )
    return (
        _looks_like_masquerade(process_name, process_path, process_signature)
        or _looks_like_masquerade(target_name, target_path, target_signature)
        or _looks_like_random_user_exec(process_name, process_path)
        or _looks_like_random_user_exec(target_name, target_path)
        or _looks_like_dropper(fields)
        or (
            (_is_unsigned_user_writable(process_path, process_signature) or _is_unsigned_user_writable(target_path, target_signature))
            and (_TEMP_INSTALLER_RE.search(process_path) or _TEMP_INSTALLER_RE.search(target_path))
        )
        or (
            (_is_webroot_path(process_path) and _is_unsigned(process_signature))
            or (_is_webroot_path(target_path) and _is_unsigned(target_signature))
        )
    )


def _special_message(rule_id: Optional[str], subtype: str, actor: str, target: str, details: Dict[str, str]) -> str:
    if rule_id == "EDR-XLSX-SCHTASKS-DELETE":
        task = details.get("task_name") or "?"
        return f"EDR 随机计划任务删除: {actor} 任务={task}"
    if rule_id == "EDR-XLSX-RANDOM-ACL":
        path = details.get("acl_path") or "?"
        return f"EDR 随机目录 ACL 修改: {actor} 路径={truncate(path, 100)}"
    if rule_id == "EDR-XLSX-PORTPROXY-RESET":
        return f"EDR 端口转发配置重置: {actor}"
    if rule_id == "EDR-XLSX-ARCHIVE-EXTRACT":
        path = details.get("archive_output_path") or "?"
        return f"EDR 压缩包解压: {actor} 输出={truncate(path, 100)}"
    return ""


def _schtasks_delete_task(command: str) -> str:
    match = _TASK_DELETE_RE.search(command or "")
    if not match:
        return ""
    task_name = match.group(1).strip().strip('"')
    return task_name if _looks_like_random_token(task_name) else ""


def _icacls_random_acl_path(command: str) -> str:
    if not _ICACLS_ACL_RE.search(command or ""):
        return ""
    path = _first_quoted_or_path(command)
    if path and _is_random_work_dir(path):
        return path.rstrip("\\/")
    return ""


def _archive_extract_output(command: str) -> str:
    match = _SEVEN_ZIP_EXTRACT_RE.search(command or "")
    if not match:
        return ""
    output = match.group(1).strip().strip('"')
    if _USER_WRITABLE_RE.search(output) and (_BRAND_RE.search(output) or _is_random_work_dir(output)):
        return output
    return ""


def _first_quoted_or_path(command: str) -> str:
    for match in re.finditer(r'"([^"]+)"', command or ""):
        value = match.group(1).strip()
        if "\\" in value or "/" in value:
            return value
    match = re.search(r"([A-Za-z]:\\[^\s]+)", command or "")
    return match.group(1) if match else ""


def _is_random_work_dir(path: str) -> bool:
    if not path:
        return False
    normalized = path.replace("/", "\\").rstrip("\\.")
    if not re.search(r"\\users\\[^\\]+\\documents\\|\\inetpub\\wwwroot\\", normalized, re.I):
        return False
    segments = [segment.strip(" .") for segment in normalized.split("\\") if segment.strip(" .")]
    random_segments = [segment for segment in segments if _looks_like_random_token(segment)]
    return len(random_segments) >= 2 or (
        len(random_segments) >= 1 and _looks_like_random_user_exec(_basename(normalized), normalized)
    )


def _looks_like_random_token(value: str) -> bool:
    token = str(value or "").strip().strip('"')
    if not token or token.lower() in _COMMON_PATH_SEGMENTS:
        return False
    if _RANDOM_TASK_RE.fullmatch(token):
        return True
    if _RANDOM_STEM_RE.fullmatch(token):
        return True
    if _MIXED_RANDOM_SEGMENT_RE.fullmatch(token):
        return any(char.isdigit() for char in token) or not _BRAND_RE.search(token)
    return False


def _looks_like_masquerade(process_name: str, process_path: str, signature: str) -> bool:
    text = " ".join((process_name or "", process_path or ""))
    return bool(
        _is_unsigned(signature)
        and _BRAND_RE.search(text)
        and _USER_WRITABLE_RE.search(process_path or "")
        and _is_executable_path(process_path or process_name)
    )


def _looks_like_random_user_exec(name: str, path: str) -> bool:
    stem = os.path.splitext(_basename(name or path))[0]
    return bool(stem and _RANDOM_STEM_RE.fullmatch(stem) and _USER_WRITABLE_RE.search(path or ""))


def _looks_like_dropper(fields: Dict[str, str]) -> bool:
    process_path = _field(fields, "process_path")
    process_signature = _field(fields, "process_signature")
    target_path = _field(fields, "target_path")
    target_signature = _field(fields, "target_signature")
    if not target_path or not _is_executable_path(target_path):
        return False
    if not (_is_unsigned(process_signature) or _is_unsigned(target_signature)):
        return False
    return bool(
        (_USER_WRITABLE_RE.search(process_path or "") and _USER_WRITABLE_RE.search(target_path or ""))
        or _TEMP_INSTALLER_RE.search(process_path or "")
        or _TEMP_INSTALLER_RE.search(target_path or "")
    )


def _is_unsigned_user_writable(path: str, signature: str) -> bool:
    return bool(path and _is_unsigned(signature) and _USER_WRITABLE_RE.search(path) and _is_executable_path(path))


def _is_unsigned(signature: str) -> bool:
    return str(signature or "").strip().lower() in {"", "-", "none", "null", "unknown", "unsigned", "无", "未知", "未签名"}


def _is_executable_path(value: str) -> bool:
    return bool(value and (_EXECUTABLE_RE.search(value) or os.path.splitext(_basename(value))[1].lower() in {".exe", ".dll", ".tmp"}))


def _is_webroot_path(value: str) -> bool:
    return bool(value and re.search(r"(?:\\|/)inetpub(?:\\|/)wwwroot(?:\\|/)", value, re.I))


def _is_common_security_component_load(path: str, signature: str) -> bool:
    return bool(
        path
        and _SECURITY_COMPONENT_RE.search(" ".join((path or "", signature or "")))
        and re.search(r"(?:\\|/)(?:windows|winnt)(?:\\|/)(?:system32|syswow64)(?:\\|/)", path, re.I)
    )


def _first_path(*values: str) -> str:
    for value in values:
        if value and ("\\" in value or "/" in value):
            return value
    return ""


def _basename(path: str) -> str:
    return re.split(r"[\\/]", str(path or ""))[-1].strip('"')


def _field(fields: Dict[str, str], key: str) -> str:
    return str(fields.get(key, "") or "").strip()


def _raw_line(fields: Dict[str, str]) -> str:
    return "\t".join(f"{key}={value}" for key, value in fields.items() if value)
