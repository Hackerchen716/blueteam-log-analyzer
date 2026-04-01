"""工具函数"""
import re
import datetime
from typing import Optional

_counter = 0

def gen_id(prefix: str = "evt") -> str:
    global _counter
    _counter += 1
    return f"{prefix}-{_counter:06d}"

def reset_counter():
    global _counter
    _counter = 0

MONTH_MAP = {
    'Jan':'01','Feb':'02','Mar':'03','Apr':'04','May':'05','Jun':'06',
    'Jul':'07','Aug':'08','Sep':'09','Oct':'10','Nov':'11','Dec':'12'
}

def normalize_timestamp(ts: str) -> str:
    """将各种时间格式统一为 ISO8601"""
    if not ts:
        return ""
    ts = ts.strip()
    # 已是 ISO 格式
    if re.match(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', ts):
        return ts.replace(' ', 'T')
    # syslog: "Mar 15 09:00:01"
    m = re.match(r'(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})', ts)
    if m:
        year = datetime.datetime.now().year
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

def is_private_ip(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

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

def read_file(path: str) -> str:
    """安全读取文件，自动处理编码"""
    with open(path, 'rb') as f:
        raw = f.read()
    enc = detect_encoding(raw)
    return raw.decode(enc, errors='replace')
