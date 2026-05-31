"""Windows EventLog JSON parser.

Handles OTRF/Mordor-style JSONL or JSON sequence exports where each record is
already a flattened Windows EventLog event. The parser only normalizes records
into LogEvent objects; detection remains in the detector layer.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from ..models import LogEvent, ParseResult, ParseStats
from ..utils.helpers import file_size, iter_file_chunks, iter_file_lines, read_file_sample
from .stats import compute_stats
from .windows_evtx import build_windows_event_from_fields

_EVENT_ID_RE = re.compile(
    r'"(?:EventID|event_id)"\s*:|"\s*event\s*"\s*:\s*\{[^{}]{0,512}"code"\s*:',
    re.IGNORECASE | re.DOTALL,
)
_WINDOWS_SOURCE_RE = re.compile(
    r'"(?:SourceName|provider_name|provider)"\s*:\s*"Microsoft-Windows-',
    re.IGNORECASE,
)
_WINDOWS_CHANNEL_RE = re.compile(
    r'"Channel"\s*:\s*"(?:Security|System|Application|Microsoft-Windows-[^"]+)"',
    re.IGNORECASE,
)
_WINDOWS_PROVIDER_RE = re.compile(r'"(?:ProviderGuid|provider_guid|provider_name)"\s*:', re.IGNORECASE)
_WINDOWS_TIME_RE = re.compile(r'"(?:TimeCreated|@timestamp|UtcTime|EventTime)"\s*:', re.IGNORECASE)
_WINDOWS_WINLOG_RE = re.compile(r'"winlog"\s*:\s*\{', re.IGNORECASE)


def looks_like_windows_event_json(file_path: str, sample_text: str) -> bool:
    """Return True for flattened Windows EventLog JSON/JSONL exports."""
    name = os.path.basename(file_path).lower()
    stripped = sample_text.lstrip()
    if not stripped or stripped[0] not in "{[":
        return False
    if not (name.endswith(".json") or name.endswith(".jsonl") or "windows" in name):
        return False

    sample = sample_text[:8192]
    if not _EVENT_ID_RE.search(sample):
        return False

    indicators = 0
    for pattern in (
        _WINDOWS_SOURCE_RE,
        _WINDOWS_CHANNEL_RE,
        _WINDOWS_PROVIDER_RE,
        _WINDOWS_TIME_RE,
        _WINDOWS_WINLOG_RE,
    ):
        if pattern.search(sample):
            indicators += 1
    return indicators >= 2


def parse_windows_json(content: str, source_file: str) -> ParseResult:
    """Parse in-memory Windows EventLog JSON content."""
    t0 = time.time()
    events: List[LogEvent] = []
    parse_errors = 0
    try:
        records = _iter_json_records_from_text(content)
        for record, raw_line, decode_error in records:
            if decode_error:
                parse_errors += 1
                continue
            event = _event_from_json_record(record, raw_line, source_file)
            if event:
                events.append(event)
    except json.JSONDecodeError:
        parse_errors += 1
    return _result(source_file, events, t0, len(content.encode()), parse_errors)


def parse_windows_json_file(path: str, source_file: Optional[str] = None) -> ParseResult:
    """Parse Windows EventLog JSON from disk without loading the full file."""
    t0 = time.time()
    source_name = source_file or os.path.basename(path)
    events: List[LogEvent] = []
    parse_errors = 0
    sample = read_file_sample(path)
    if sample.lstrip().startswith("["):
        try:
            records = _iter_json_array_records_from_chunks(iter_file_chunks(path))
            for record, raw_line in records:
                event = _event_from_json_record(record, raw_line, source_name)
                if event:
                    events.append(event)
        except json.JSONDecodeError:
            parse_errors += 1
    elif _looks_like_single_line_json_records(sample):
        for raw_line in _iter_non_empty_json_lines(iter_file_lines(path)):
            try:
                value = json.loads(raw_line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            if not isinstance(value, dict):
                continue
            event = _event_from_json_record(value, raw_line, source_name)
            if event:
                events.append(event)
    else:
        try:
            records = _iter_json_sequence_records_from_chunks(iter_file_chunks(path))
            for record, raw_line in records:
                event = _event_from_json_record(record, raw_line, source_name)
                if event:
                    events.append(event)
        except json.JSONDecodeError:
            parse_errors += 1
    return _result(source_name, events, t0, file_size(path), parse_errors)


def _looks_like_single_line_json_records(sample_text: str) -> bool:
    for line in sample_text.splitlines():
        raw = line.strip()
        if not raw:
            continue
        try:
            return isinstance(json.loads(raw), dict)
        except json.JSONDecodeError:
            return False
    return False


def _iter_non_empty_json_lines(lines: Iterable[str]) -> Iterator[str]:
    for line in lines:
        raw = line.strip()
        if not raw:
            continue
        yield raw


def _iter_json_records_from_text(content: str) -> Iterator[Tuple[Dict[str, Any], str, bool]]:
    stripped = content.lstrip()
    if not stripped:
        return
    if stripped.startswith("["):
        value = json.loads(content)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    yield item, json.dumps(item, ensure_ascii=False), False
        return

    decoder = json.JSONDecoder()
    pos = 0
    length = len(content)
    while pos < length:
        while pos < length and content[pos].isspace():
            pos += 1
        if pos >= length:
            break
        try:
            value, end = decoder.raw_decode(content, pos)
        except json.JSONDecodeError as exc:
            next_line = content.find("\n", pos)
            if next_line < 0:
                raise exc
            bad_line = content[pos:next_line].strip()
            if bad_line:
                yield {}, bad_line, True
            pos = next_line + 1
            continue
        if isinstance(value, dict):
            yield value, content[pos:end], False
        pos = end


def _iter_json_sequence_records_from_chunks(chunks: Iterable[str]) -> Iterator[Tuple[Dict[str, Any], str]]:
    decoder = json.JSONDecoder()
    iterator = iter(chunks)
    buffer = ""
    pos = 0
    eof = False

    def fill() -> bool:
        nonlocal buffer, eof
        if eof:
            return False
        try:
            buffer += next(iterator)
            return True
        except StopIteration:
            eof = True
            return False

    def skip_ws() -> bool:
        nonlocal pos
        while True:
            while pos < len(buffer) and buffer[pos].isspace():
                pos += 1
            if pos < len(buffer):
                return True
            if not fill():
                return False

    def compact() -> None:
        nonlocal buffer, pos
        if pos > 65536:
            buffer = buffer[pos:]
            pos = 0

    while skip_ws():
        start = pos
        while True:
            try:
                value, end = decoder.raw_decode(buffer, pos)
                break
            except json.JSONDecodeError as exc:
                if not fill():
                    raise exc

        if isinstance(value, dict):
            yield value, buffer[start:end]
        pos = end
        compact()


def _iter_json_array_records_from_chunks(chunks: Iterable[str]) -> Iterator[Tuple[Dict[str, Any], str]]:
    decoder = json.JSONDecoder()
    iterator = iter(chunks)
    buffer = ""
    pos = 0
    eof = False

    def fill() -> bool:
        nonlocal buffer, eof
        if eof:
            return False
        try:
            buffer += next(iterator)
            return True
        except StopIteration:
            eof = True
            return False

    def skip_ws() -> bool:
        nonlocal pos
        while True:
            while pos < len(buffer) and buffer[pos].isspace():
                pos += 1
            if pos < len(buffer):
                return True
            if not fill():
                return False

    def compact() -> None:
        nonlocal buffer, pos
        if pos > 65536:
            buffer = buffer[pos:]
            pos = 0

    if not skip_ws():
        return
    if buffer[pos] != "[":
        raise json.JSONDecodeError("expected JSON array", buffer, pos)
    pos += 1

    while True:
        if not skip_ws():
            raise json.JSONDecodeError("unterminated JSON array", buffer, pos)
        if buffer[pos] == "]":
            return

        while True:
            try:
                value, end = decoder.raw_decode(buffer, pos)
                break
            except json.JSONDecodeError as exc:
                if not fill():
                    raise exc

        if isinstance(value, dict):
            yield value, json.dumps(value, ensure_ascii=False)
        pos = end

        if not skip_ws():
            raise json.JSONDecodeError("unterminated JSON array", buffer, pos)
        if buffer[pos] == ",":
            pos += 1
            compact()
            continue
        if buffer[pos] == "]":
            return
        raise json.JSONDecodeError("expected comma or array end", buffer, pos)


def _event_from_json_record(record: Dict[str, Any], raw_line: str, source_file: str) -> Optional[LogEvent]:
    details = _normalize_windows_json_record(record)
    eid = _safe_event_id(details.get("EventID"))
    if eid <= 0:
        return None
    eid_str = str(eid)
    ts_raw = _pick_record_value(details, "TimeCreated", "@timestamp", "UtcTime", "EventTime", "EventReceivedTime")
    computer = _pick_record_value(details, "Hostname", "Computer", "host")
    channel = _pick_record_value(details, "Channel")
    return build_windows_event_from_fields(
        eid=eid,
        eid_str=eid_str,
        ts_raw=ts_raw,
        computer=computer,
        channel=channel,
        details=details,
        source_file=source_file,
        raw_line=raw_line,
    )


def _normalize_windows_json_record(record: Dict[str, Any]) -> Dict[str, str]:
    details = _stringify_record(record)

    event_data = _nested_dict(record, "winlog", "event_data")
    for key, value in event_data.items():
        _set_if_missing(details, str(key), value)

    _set_if_missing(details, "EventID", _first_nested_value(
        record,
        ("EventID",),
        ("event_id",),
        ("winlog", "event_id"),
        ("event", "code"),
    ))
    _set_if_missing(details, "SourceName", _first_nested_value(
        record,
        ("SourceName",),
        ("ProviderName",),
        ("provider_name",),
        ("winlog", "provider_name"),
        ("event", "provider"),
    ))
    _set_if_missing(details, "Channel", _first_nested_value(
        record,
        ("Channel",),
        ("channel",),
        ("winlog", "channel"),
    ))
    host = _first_nested_value(
        record,
        ("Hostname",),
        ("Computer",),
        ("host", "name"),
        ("winlog", "computer_name"),
        ("agent", "hostname"),
    )
    _set_if_missing(details, "Hostname", host)
    _set_if_missing(details, "Computer", host)
    _set_if_missing(details, "TimeCreated", _first_nested_value(
        record,
        ("TimeCreated",),
        ("@timestamp",),
        ("timestamp",),
        ("winlog", "time_created"),
        ("event", "created"),
    ))

    command_line = _first_nested_value(record, ("process", "command_line"))
    process_path = _first_nested_value(record, ("process", "executable"), ("process", "name"))
    parent_path = _first_nested_value(record, ("process", "parent", "executable"), ("process", "parent", "name"))
    _set_if_missing(details, "CommandLine", command_line)
    _set_if_missing(details, "Image", process_path)
    _set_if_missing(details, "NewProcessName", process_path)
    _set_if_missing(details, "ParentImage", parent_path)
    _set_if_missing(details, "ParentProcessName", parent_path)

    source_ip = _first_nested_value(record, ("source", "ip"), ("client", "ip"))
    source_port = _first_nested_value(record, ("source", "port"), ("client", "port"))
    destination_ip = _first_nested_value(record, ("destination", "ip"), ("server", "ip"))
    destination_port = _first_nested_value(record, ("destination", "port"), ("server", "port"))
    destination_host = _first_nested_value(
        record,
        ("destination", "domain"),
        ("destination", "address"),
        ("server", "domain"),
        ("server", "address"),
    )
    _set_if_missing(details, "IpAddress", source_ip)
    _set_if_missing(details, "SourceIp", source_ip)
    _set_if_missing(details, "IpPort", source_port)
    _set_if_missing(details, "SourcePort", source_port)
    _set_if_missing(details, "DestinationIp", destination_ip)
    _set_if_missing(details, "DestAddress", destination_ip)
    _set_if_missing(details, "DestinationPort", destination_port)
    _set_if_missing(details, "DestPort", destination_port)
    _set_if_missing(details, "DestinationHostname", destination_host)

    _set_if_missing(details, "QueryName", _first_nested_value(record, ("dns", "question", "name")))
    _set_if_missing(details, "TargetUserName", _first_nested_value(record, ("user", "name")))
    _set_if_missing(details, "TargetDomainName", _first_nested_value(record, ("user", "domain")))
    _set_if_missing(details, "Message", _first_nested_value(record, ("message",)))
    return details


def _safe_event_id(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _stringify_record(record: Dict[str, Any]) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for key, value in record.items():
        if value is None:
            continue
        if isinstance(value, (dict, list)):
            fields[str(key)] = json.dumps(value, ensure_ascii=False, sort_keys=True)
        else:
            fields[str(key)] = str(value)
    return fields


def _nested_dict(record: Dict[str, Any], *path: str) -> Dict[str, Any]:
    value = _nested_value(record, *path)
    return value if isinstance(value, dict) else {}


def _nested_value(record: Dict[str, Any], *path: str) -> Any:
    value: Any = record
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _first_nested_value(record: Dict[str, Any], *paths: Tuple[str, ...]) -> Any:
    for path in paths:
        value = _nested_value(record, *path)
        if value is None:
            continue
        text = _stringify_value(value).strip()
        if text and text != "-":
            return value
    return None


def _set_if_missing(fields: Dict[str, str], key: str, value: Any) -> None:
    if fields.get(key, "").strip():
        return
    if value is None:
        return
    text = _stringify_value(value).strip()
    if not text or text == "-":
        return
    fields[key] = text


def _stringify_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _pick_record_value(record: Dict[str, str], *keys: str) -> str:
    for key in keys:
        value = record.get(key, "").strip()
        if value and value != "-":
            return value
    return ""


def _result(
    source_file: str,
    events: List[LogEvent],
    t0: float,
    file_size_bytes: int,
    parse_errors: int = 0,
) -> ParseResult:
    stats = compute_stats(events) if events else ParseStats(total=0)
    stats.parse_errors += parse_errors
    return ParseResult(
        file_name=source_file,
        log_type="Windows Event Log (JSON)",
        events=events,
        stats=stats,
        parse_time_ms=(time.time() - t0) * 1000,
        file_size_bytes=file_size_bytes,
    )
