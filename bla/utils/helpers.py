"""工具函数"""
import datetime
import ipaddress
import os
import re
import sys
import threading
from typing import Iterator, Optional

_counter = 0
_counter_lock = threading.Lock()
_syslog_year_override: Optional[int] = None

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

def truncate(s: str, n: int = 120) -> str:
    return s if len(s) <= n else s[:n] + "…"


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
    return (
        ip_obj in ipaddress.ip_network("10.0.0.0/8") or
        ip_obj in ipaddress.ip_network("172.16.0.0/12") or
        ip_obj in ipaddress.ip_network("192.168.0.0/16")
    )

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

def file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0

def _read_prefix(path: str, max_bytes: int = 8192) -> bytes:
    with open(path, 'rb') as f:
        return f.read(max_bytes)
