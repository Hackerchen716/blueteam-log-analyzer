"""工具函数"""
import argparse
import datetime
import ipaddress
import os
import re
import sys
import threading
from functools import lru_cache
from typing import Iterator, Optional

_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_counter = 0
_counter_lock = threading.Lock()
_syslog_year_override: Optional[int] = None
_OSC_RE = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)", re.S)
_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ESC_RE = re.compile(r"\x1b[ -/]*[@-~]")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_ESCAPED_OSC_RE = re.compile(r"\\x1b\].*?(?:\\x07|\\x1b\\\\)", re.I | re.S)
_ESCAPED_CSI_RE = re.compile(r"\\x1b\[[0-?]*[ -/]*[@-~]", re.I)
_ESCAPED_ESC_RE = re.compile(r"\\x1b[ -/]*[@-~]", re.I)
_ESCAPED_CONTROL_RE = re.compile(r"\\x(?:0[0-8bcef]|1[0-9a-f]|7f|8[0-9a-f]|9[0-9a-f])", re.I)
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b("
    r"cookie|set-cookie|x-api-key|api[_-]?key|token|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|secret|passwd|password|pwd|session[_-]?id"
    r")\b\s*[:=]\s*([^\s;&,\"]+|\"[^\"]*\"|'[^']*')"
)
_AUTHORIZATION_RE = re.compile(
    r"(?i)\b(authorization)\b\s*[:=]\s*(?:Bearer\s+)?([^\s;&,\"]+|\"[^\"]*\"|'[^']*')"
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")


class SafeArgumentParser(argparse.ArgumentParser):
    """ArgumentParser variant that sanitizes attacker-controlled error text."""

    def error(self, message):
        super().error(sanitize_report_text(message))

def gen_id(prefix: str = "evt") -> str:
    global _counter
    with _counter_lock:
        _counter += 1
        return f"{prefix}-{_counter:06d}"

def reset_counter():
    global _counter
    with _counter_lock:
        _counter = 0

def set_syslog_year(year: Optional[int]):
    """Set the year used for syslog timestamps that do not include one."""
    global _syslog_year_override
    _syslog_year_override = year


def get_syslog_year_override() -> Optional[int]:
    return _syslog_year_override

MONTH_MAP = {
    'Jan':'01','Feb':'02','Mar':'03','Apr':'04','May':'05','Jun':'06',
    'Jul':'07','Aug':'08','Sep':'09','Oct':'10','Nov':'11','Dec':'12'
}

def normalize_timestamp(ts: str, syslog_year: Optional[int] = None) -> str:
    """将各种时间格式统一为 ISO8601。

    ``syslog_year`` 用于 syslog/auth.log 这类不带年份的时间戳。优先级：
    显式参数 > :func:`set_syslog_year` 设置的全局值 > 系统当前年份。
    """
    if not ts:
        return ""
    ts = ts.strip()
    # 已是 ISO 格式
    if re.match(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', ts):
        return ts.replace(' ', 'T')
    # syslog: "Mar 15 09:00:01"
    m = re.match(r'(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})', ts)
    if m:
        year = syslog_year or _syslog_year_override or datetime.datetime.now().year
        mon = MONTH_MAP.get(m.group(1), '01')
        day = m.group(2).zfill(2)
        return f"{year}-{mon}-{day}T{m.group(3)}"
    # Apache: "15/Mar/2024:10:00:01 +0800"
    m2 = re.match(r'(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})', ts)
    if m2:
        mon = MONTH_MAP.get(m2.group(2), '01')
        return f"{m2.group(3)}-{mon}-{m2.group(1)}T{m2.group(4)}"
    return ts

_PLACEHOLDER_SOURCE_VALUES = {
    "",
    "-",
    "localhost",
    "127.0.0.1",
    "::1",
    "::ffff:127.0.0.1",
    "0.0.0.0",
}


def is_placeholder_source(value: str) -> bool:
    """Return True for empty, loopback, or system-local source markers."""
    return str(value or "").strip().lower() in _PLACEHOLDER_SOURCE_VALUES


def format_timestamp_local(ts: str, offset_hours: int = 8) -> str:
    """Format ISO timestamps as UTC+8 for operator-facing reports.

    The raw UTC value is preserved in the display when the input timestamp is
    timezone-aware, so responders can reconcile local time with original logs.
    """
    if not ts:
        return ""
    raw = ts.strip()
    try:
        parsed = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return raw
    if parsed.tzinfo is None:
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    local_tz = datetime.timezone(datetime.timedelta(hours=offset_hours))
    local = parsed.astimezone(local_tz).strftime("%Y-%m-%d %H:%M:%S")
    utc = parsed.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{local} UTC+{offset_hours} (UTC: {utc})"


def truncate(s: str, n: int = 120) -> str:
    return s if len(s) <= n else s[:n] + "…"


def strip_terminal_control(value: object) -> str:
    """Remove terminal control sequences from attacker-controlled text."""
    text = str(value or "")
    text = _ESCAPED_OSC_RE.sub("", text)
    text = _ESCAPED_CSI_RE.sub("", text)
    text = _ESCAPED_ESC_RE.sub("", text)
    text = _ESCAPED_CONTROL_RE.sub("", text)
    text = _OSC_RE.sub("", text)
    text = _CSI_RE.sub("", text)
    text = _ESC_RE.sub("", text)
    return _CONTROL_RE.sub("", text)


def redact_sensitive_text(value: object) -> str:
    """Mask common secrets before writing shareable reports."""
    text = str(value or "")
    text = _AUTHORIZATION_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    text = _BEARER_RE.sub("Bearer <redacted>", text)
    return _SENSITIVE_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)


def sanitize_report_text(value: object) -> str:
    """Strip terminal controls and redact obvious secrets for reports."""
    return redact_sensitive_text(strip_terminal_control(value))


def escape_markdown_text(value: object) -> str:
    """Escape attacker-controlled text for Markdown tables/lists/headings."""
    text = sanitize_report_text(value)
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("`", "\\`")
    )


def safe_write(text: str, stream=None) -> None:
    """Write text without crashing on legacy Windows console encodings."""
    stream = stream or sys.stdout
    try:
        stream.write(text)
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "utf-8"
        stream.write(text.encode(encoding, errors="replace").decode(encoding, errors="replace"))


def safe_print(*values, sep: str = " ", end: str = "\n", file=None, flush: bool = False) -> None:
    """print() compatible helper that tolerates non-UTF-8 output streams."""
    stream = file or sys.stdout
    safe_write(sep.join(str(v) for v in values) + end, stream)
    if flush:
        stream.flush()


def format_sanitized_traceback(exc: BaseException) -> str:
    """Return a traceback with terminal controls stripped and secrets masked."""
    import traceback

    return sanitize_report_text("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))


def print_sanitized_traceback(exc: BaseException, file=None) -> None:
    """Print a sanitized traceback to stderr by default."""
    safe_write(format_sanitized_traceback(exc), file or sys.stderr)


class SafeStream:
    """Small write/flush adapter for modules that stream terminal reports."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, text: str) -> None:
        safe_write(text, self._stream)

    def flush(self) -> None:
        self._stream.flush()


def safe_stream(stream):
    return SafeStream(stream)


@lru_cache(maxsize=4096)
def is_private_ip(ip: str) -> bool:
    """Return True only for RFC1918 private address ranges.

    ``ipaddress.ip_address(...).is_private`` also marks documentation ranges
    such as 203.0.113.0/24 and 198.51.100.0/24 as private-like. For alert
    confidence downgrades we only want internal RFC1918 space.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    return any(ip_obj in network for network in _RFC1918_NETWORKS)

def detect_encoding(raw: bytes) -> str:
    """简单检测文件编码"""
    if raw[:3] == b'\xef\xbb\xbf':
        return 'utf-8-sig'
    if raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return 'utf-16'
    try:
        raw.decode('utf-8')
        return 'utf-8'
    except UnicodeDecodeError:
        return 'latin-1'

def read_file_sample(path: str, max_bytes: int = 8192) -> str:
    """读取文件开头一小段用于类型识别，避免为探测日志类型读完整大文件。"""
    with open(path, 'rb') as f:
        raw = f.read(max_bytes)
    enc = detect_encoding(raw)
    return raw.decode(enc, errors='replace')

def read_file(path: str) -> str:
    """安全读取文件，自动处理编码"""
    with open(path, 'rb') as f:
        raw = f.read()
    enc = detect_encoding(raw)
    return raw.decode(enc, errors='replace')

def iter_file_lines(path: str) -> Iterator[str]:
    """逐行读取文本文件，保持与 read_file 相同的编码兜底策略。"""
    enc = detect_encoding(_read_prefix(path))
    with open(path, 'r', encoding=enc, errors='replace') as f:
        for line in f:
            yield line.rstrip('\n\r')


def iter_file_chunks(path: str, chunk_size: int = 1024 * 1024) -> Iterator[str]:
    """按文本块读取文件，供 XML/JSON 等解析器避免一次性读入大文件。"""
    enc = detect_encoding(_read_prefix(path))
    with open(path, 'r', encoding=enc, errors='replace') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk

def file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0

def _read_prefix(path: str, max_bytes: int = 8192) -> bytes:
    with open(path, 'rb') as f:
        return f.read(max_bytes)
