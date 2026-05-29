"""Shell history parser for bash/zsh command traces."""

from __future__ import annotations

import datetime
import re
import shlex
import time
from typing import Dict, Iterable, List, Optional

from ..models import LogEvent, ParseResult, ThreatLevel
from ..utils.helpers import file_size, gen_id, iter_file_lines, strip_terminal_control, truncate
from .stats import compute_stats

_BASH_EXTENDED_RE = re.compile(r"^:\s*(\d{9,})(?::\d+)?;(.*)$")
_NUMBERED_HISTORY_RE = re.compile(r"^\s*\d{1,6}\s+(.+)$")
_URL_RE = re.compile(r"https?://[^\s\"']+", re.I)
_REMOTE_PATH_RE = re.compile(r"^([^:/\\]+):(?:/|\\).+")
_UNIX_HOME_RE = re.compile(r"(?:^|/)(?:home|Users)/([^/\\]+)(?:/|$)")
_WIN_USER_RE = re.compile(r"(?:^|[\\/])Users[\\/]([^\\/]+)(?:[\\/]|$)", re.I)

_NOISE_RE = re.compile(
    r"^(?:ls(?:\s+-[\w-]+)?|cd(?:\s+.+)?|pwd|clear|exit|logout|nano\s+.+|vim\s+.+|vi\s+.+|touch\s+.+|mkdir\s+.+)\s*$",
    re.I,
)

_DOWNLOAD_RE = re.compile(r"\b(?:wget|curl|fetch|git\s+clone)\b.*(?:https?://|ftp://)", re.I)
_UPLOAD_RE = re.compile(r"\b(?:curl|wget)\b.*(?:--upload-file|-T\s+|-F\s+[^=\s]+=@)", re.I)
_NETCAT_EXFIL_RE = re.compile(
    r"\b(?:nc|ncat|netcat)\b\s+\S+\s+\d{1,5}\b[^|;&\n]*<\s*(?:/|~|\./|\../)[^\s;&|]+",
    re.I,
)
_PIPE_EXFIL_RE = re.compile(r"\b(?:tar|gzip|zip|7z)\b.+\|\s*(?:curl|nc|ncat|netcat)\b", re.I)
_REMOTE_DEST_RE = re.compile(r"^(?:[^@\s:]+@)?[^:\s]+:[/\\].+")
_LOCAL_SOURCE_RE = re.compile(
    r"^(?:/|~|\./|\../|[A-Za-z]:[\\/]|[^@\s:]+\.(?:sql|sqlite|db|dump|bak|zip|tar|tgz|gz|7z|rar|csv|xlsx?|json|env|pem|key))",
    re.I,
)
_EXPLOIT_TOOL_RE = re.compile(r"linpeas|linux-exploit-suggester|les\.sh|pspy|dirtycow|exploit|enum4linux", re.I)
_SHELL_UPGRADE_RE = re.compile(
    r"pty\.spawn|/bin/(?:ba)?sh\s+-i|os\.execl\([^)]*(?:/bin/)?sh|(?:^|\s)(?:nc|ncat|socat)\b.*(?:-e|exec)",
    re.I,
)
_SUID_ENUM_RE = re.compile(r"find\s+/\s+.*(?:-perm\s+-?4000|-perm\s+/4000|-perm\s+-u=s)", re.I)
_PRIV_ESC_RE = re.compile(
    r"\bsudo\s+-l\b|\bsu\s+root\b|/bin/(?:ba)?sh\s+-p\b|(?:^|\s)sh\s+-p\b|cat\s+/etc/sudoers",
    re.I,
)
_CRED_TARGET_RE = (
    r"(?:/etc/(?:shadow|gshadow)|"
    r"(?:~|/root|/home/[^\s/]+)/\.ssh/(?:authorized_keys|id_[a-z0-9_]+|config)|"
    r"(?:[^\s'\";&|]*/)?\.env(?:\.[\w.-]+)?|"
    r"[^\s'\";&|]*(?:config|database|db)[^\s'\";&|]*\.(?:php|py|js|json|ya?ml|ini|conf))"
)
_CRED_FILE_RE = re.compile(
    r"\b(?:cat|less|more|tail|head|strings|grep)\b[^\n;&|]*(?:^|[\s'\"=])" + _CRED_TARGET_RE,
    re.I,
)
_DISCOVERY_RE = re.compile(
    r"^(?:id|whoami|hostname|uname\b|env|ps\b|ifconfig\b|ip\s+a|ip\s+addr|iptables\b|lsof\b|tcpdump\b|last\b|"
    r"crontab\s+-l|dpkg\s+-l|cat\s+/etc/(?:passwd|fstab|resolv\.conf|network|sysconfig/network)|"
    r"find\s+/|ls\s+-a?l?h?R\b)",
    re.I,
)
_ARTIFACT_DELETE_RE = re.compile(
    r"\b(?:rm|shred|truncate)\b.*(?:"
    r"\.bash_history|/var/log/|/var/www/|/uploads/|"
    r"/tmp/[^\s]*(?:\.sh|\.py|\.php|\.phtml|\.jsp)|"
    r"(?:shell|backdoor|webshell|x)\.(?:php|phtml|jsp)|history"
    r")",
    re.I,
)
_HISTORY_CLEAR_RE = re.compile(r"\bhistory\s+-c\b|unset\s+HISTFILE|cat\s+/dev/null\s+>\s+.*history", re.I)


def parse_shell_history(content: str, source_file: str) -> ParseResult:
    return parse_shell_history_lines(
        content.splitlines(),
        source_file,
        file_size_bytes=len(content.encode()),
        source_context=_source_context(source_file),
    )


def parse_shell_history_file(path: str, source_file: Optional[str] = None) -> ParseResult:
    display_name = source_file or path
    source_context = _source_context(path)
    source_context.update(_source_context(display_name))
    return parse_shell_history_lines(
        iter_file_lines(path),
        display_name,
        file_size_bytes=file_size(path),
        source_context=source_context,
    )


def parse_shell_history_lines(
    lines: Iterable[str],
    source_file: str,
    file_size_bytes: int = 0,
    source_context: Optional[Dict[str, str]] = None,
) -> ParseResult:
    t0 = time.time()
    events: List[LogEvent] = []
    source_context = source_context if source_context is not None else _source_context(source_file)
    for index, line in enumerate(lines, start=1):
        parsed = _extract_history_command(line)
        if not parsed:
            continue
        command, timestamp = parsed
        if not command.strip() or _NOISE_RE.match(command.strip()):
            continue
        ev = _command_to_event(command.strip(), line.rstrip("\n"), source_file, index, timestamp, source_context)
        if ev:
            events.append(ev)

    stats = compute_stats(events)
    return ParseResult(
        file_name=source_file,
        log_type="Shell History",
        events=events,
        stats=stats,
        parse_time_ms=(time.time() - t0) * 1000,
        file_size_bytes=file_size_bytes,
    )


def _extract_history_command(line: str) -> Optional[tuple[str, str]]:
    text = line.rstrip("\n")
    if not text.strip():
        return None

    extended = _BASH_EXTENDED_RE.match(text)
    if extended:
        ts = _epoch_to_iso(extended.group(1))
        return extended.group(2).strip(), ts

    numbered = _NUMBERED_HISTORY_RE.match(text)
    if numbered:
        return numbered.group(1).strip(), ""

    return text.strip(), ""


def _epoch_to_iso(value: str) -> str:
    try:
        return datetime.datetime.fromtimestamp(int(value), datetime.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def _source_context(source_file: str) -> Dict[str, str]:
    text = strip_terminal_control(source_file)
    context: Dict[str, str] = {}

    remote = _REMOTE_PATH_RE.match(text)
    if remote:
        context["asset"] = remote.group(1)

    account = ""
    home = _UNIX_HOME_RE.search(text) or _WIN_USER_RE.search(text)
    if home:
        account = home.group(1)
    elif re.search(r"(?:^|/)root(?:/|$)", text):
        account = "root"
    if account:
        context["account"] = account
    return context


def _command_to_event(
    command: str,
    raw_line: str,
    source_file: str,
    sequence: int,
    timestamp: str,
    source_context: Optional[Dict[str, str]] = None,
) -> Optional[LogEvent]:
    lower = command.lower()
    level = ThreatLevel.INFO
    category = "Shell 历史"
    tags = ["shell-history", "shell-command"]
    mitre: Optional[str] = None
    rule_name = "Shell 命令"
    action = "command"

    if _HISTORY_CLEAR_RE.search(command):
        level = ThreatLevel.CRITICAL
        category = "防御规避"
        tags += ["defense-evasion", "log-cleared"]
        mitre = "T1070.003"
        rule_name = "Shell 历史清除"
        action = "history-clear"
    elif _ARTIFACT_DELETE_RE.search(command):
        level = ThreatLevel.HIGH
        category = "防御规避"
        tags += ["defense-evasion", "artifact-deletion"]
        mitre = "T1070.004"
        rule_name = "可疑痕迹删除"
        action = "artifact-deletion"
    elif _CRED_FILE_RE.search(command):
        level = ThreatLevel.HIGH
        category = "凭据访问"
        tags += ["credential-access", "linux-credential-file"]
        mitre = "T1003.008" if "/etc/shadow" in lower or "/etc/gshadow" in lower else "T1552.004"
        rule_name = "Linux 敏感凭据文件读取"
        action = "credential-file-read"
    elif _SHELL_UPGRADE_RE.search(command):
        level = ThreatLevel.HIGH
        category = "执行"
        tags += ["shell-upgrade", "command-execution"]
        mitre = "T1059.004"
        rule_name = "交互式 Shell/TTY 升级"
        action = "shell-upgrade"
    elif _SUID_ENUM_RE.search(command):
        level = ThreatLevel.HIGH
        category = "权限提升"
        tags += ["privilege-escalation", "suid-enumeration"]
        mitre = "T1548.001"
        rule_name = "SUID 提权枚举"
        action = "suid-enumeration"
    elif _PRIV_ESC_RE.search(command):
        level = ThreatLevel.HIGH
        category = "权限提升"
        tags += ["privilege-escalation", "sudo-enumeration"]
        mitre = "T1548.003"
        rule_name = "提权命令痕迹"
        action = "privilege-command"
    elif _is_data_exfiltration_command(command):
        level = ThreatLevel.HIGH
        category = "数据外传"
        tags += ["data-exfiltration", "shell-exfiltration"]
        mitre = "T1041"
        rule_name = "Shell 数据外传命令"
        action = "data-exfiltration"
    elif _DOWNLOAD_RE.search(command):
        level = ThreatLevel.HIGH if _EXPLOIT_TOOL_RE.search(command) else ThreatLevel.MEDIUM
        category = "工具下载"
        tags += ["tool-download", "ingress-tool-transfer"]
        mitre = "T1105"
        rule_name = "远程工具下载"
        action = "tool-download"
    elif _DISCOVERY_RE.search(command):
        level = ThreatLevel.MEDIUM if any(item in lower for item in ("sudoers", "shadow", "tcpdump", "iptables")) else ThreatLevel.LOW
        category = "侦察"
        tags += ["recon", "host-discovery"]
        mitre = "T1083"
        rule_name = "主机信息枚举"
        action = "host-discovery"
    else:
        return None

    url = _first_url(command)
    details = {
        "command": command,
        "sequence": str(sequence),
        "action": action,
        "source_type": "shell-history",
    }
    if url:
        details["url"] = url
    account = (source_context or {}).get("account", "")
    asset = (source_context or {}).get("asset", "")
    if account:
        details["account"] = account
    if asset:
        details["asset"] = asset

    return LogEvent(
        id=gen_id("sh"),
        timestamp=timestamp,
        level=level,
        category=category,
        source="shell-history",
        source_file=source_file,
        message=f"{rule_name}: {truncate(command, 110)}",
        raw_line=raw_line,
        user=account or None,
        host=asset or None,
        process=_command_name(command),
        details=details,
        tags=tags,
        mitre_attack=mitre,
        rule_name=rule_name,
    )


def _first_url(command: str) -> str:
    match = _URL_RE.search(command)
    return match.group(0) if match else ""


def _command_name(command: str) -> Optional[str]:
    try:
        return command.strip().split()[0]
    except IndexError:
        return None


def _is_data_exfiltration_command(command: str) -> bool:
    if _UPLOAD_RE.search(command) or _NETCAT_EXFIL_RE.search(command) or _PIPE_EXFIL_RE.search(command):
        return True
    return _is_remote_copy_upload(command)


def _is_remote_copy_upload(command: str) -> bool:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    if not tokens:
        return False
    tool = tokens[0].rsplit("/", 1)[-1].lower()
    if tool not in {"scp", "rsync"}:
        return False
    args = [item for item in tokens[1:] if item and not item.startswith("-")]
    if len(args) < 2:
        return False
    destination = args[-1]
    if not _is_remote_destination(destination):
        return False
    return any(_LOCAL_SOURCE_RE.match(item) and not _is_remote_destination(item) for item in args[:-1])


def _is_remote_destination(value: str) -> bool:
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return False
    return bool(_REMOTE_DEST_RE.match(value))
