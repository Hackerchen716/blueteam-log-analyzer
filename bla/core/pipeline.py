"""Reusable analysis pipeline for CLI, collectors, tests, and future UI layers."""
from __future__ import annotations

import glob
import hashlib
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

from ..allowlist import apply_allowlist, load_allowlist
from ..config import DEFAULT_THRESHOLDS, load_thresholds, load_thresholds_from_env, set_thresholds
from ..detection import run_detection
from ..detection.enrichment import enrich_events
from ..incident_brief import ensure_incident_brief
from ..models import AnalysisSummary, LogEvent, ParseResult
from ..output import (
    generate_csv_report,
    generate_html_report,
    generate_incident_brief_report,
    generate_incident_evidence_csv,
    generate_ioc_report,
    generate_json_report,
    generate_report_bundle,
    generate_sarif_report,
)
from ..parsers import auto_parse
from ..parsers.stats import compute_stats
from ..rules import set_rule_dirs
from ..utils.helpers import reset_counter, sanitize_report_text, set_syslog_year

PrintFn = Callable[..., None]

COLLECTABLE_HIDDEN_FILES = {".bash_history", ".zsh_history"}

# 目录遍历时跳过的文档/说明类文件：它们不是日志，但常含安全关键词（如 README 里的
# “Webshell/jndi/tactic/technique” 等），被通用兜底解析后会产生噪声甚至高危误报。
# 仅在自动遍历目录时跳过；用户显式指定的单个文件仍会被解析（尊重显式意图）。
NON_LOG_DOC_EXTENSIONS = {".md", ".markdown", ".rst", ".adoc"}


class AnalysisError(RuntimeError):
    """Raised when the pipeline cannot complete a user-facing analysis."""


@dataclass
class AnalysisOutputs:
    html: Optional[str] = None
    json: Optional[str] = None
    csv: Optional[str] = None
    ioc: Optional[str] = None
    sarif: Optional[str] = None
    brief: Optional[str] = None
    evidence_csv: Optional[str] = None
    bundle_dir: Optional[str] = None
    geoip_cache_path: Optional[str] = None
    include_json_events: bool = True
    json_events_limit: Optional[int] = None
    json_raw_line_limit: Optional[int] = None


@dataclass
class AnalysisOptions:
    paths: List[str]
    profile: str = "default"
    parser_name: Optional[str] = None
    jobs: int = 0
    config_path: Optional[str] = None
    rule_dirs: Optional[List[str]] = None
    allowlist_path: Optional[str] = None
    syslog_year: Optional[int] = None
    rdp_only: bool = False
    outputs: Optional[AnalysisOutputs] = None


@dataclass
class AnalysisRunResult:
    files: List[str]
    parse_results: List[ParseResult]
    summary: AnalysisSummary
    suppressed_events: int = 0
    parse_errors: List[str] = field(default_factory=list)


def collect_files(paths: Iterable[str]) -> List[str]:
    files = []
    for path in paths:
        if os.path.isfile(path):
            files.append(path)
        elif os.path.isdir(path):
            _collect_directory_files(path, files)
        else:
            for match in glob.glob(path):
                if os.path.isfile(match):
                    files.append(match)
                elif os.path.isdir(match):
                    _collect_directory_files(match, files)
    return sorted(set(files))


def _collect_directory_files(path: str, files: List[str]) -> None:
    root_real = os.path.realpath(path)
    for root, dirnames, fnames in os.walk(path, followlinks=False):
        dirnames[:] = [
            dirname for dirname in dirnames
            if not dirname.startswith(".")
            and _is_within_real_root(os.path.join(root, dirname), root_real)
        ]
        for fname in fnames:
            if fname.startswith(".") and fname not in COLLECTABLE_HIDDEN_FILES:
                continue
            if os.path.splitext(fname)[1].lower() in NON_LOG_DOC_EXTENSIONS:
                continue
            candidate = os.path.join(root, fname)
            if os.path.isfile(candidate) and _is_within_real_root(candidate, root_real):
                files.append(candidate)


def _is_within_real_root(path: str, root_real: str) -> bool:
    try:
        return os.path.commonpath([os.path.realpath(path), root_real]) == root_real
    except ValueError:
        return False


def parse_files(
    files: List[str],
    jobs: int = 0,
    parser_name: Optional[str] = None,
    quiet: bool = False,
    print_fn: Optional[PrintFn] = None,
    rdp_only: bool = False,
    errors_out: Optional[List[str]] = None,
) -> List[ParseResult]:
    parse_results: List[ParseResult] = []
    errors: List[str] = []
    display_names = _source_display_names(files)
    workers = jobs if jobs > 0 else min(8, max(1, len(files)))
    emit = print_fn if print_fn is not None else print
    if len(files) <= 1 or workers == 1:
        for i, fpath in enumerate(files, 1):
            fname = sanitize_report_text(display_names.get(fpath, os.path.basename(fpath)))
            if not quiet:
                emit(f"  [{i}/{len(files)}] 解析: {fname} ...", end=" ", flush=True)
            try:
                result = auto_parse(fpath, parser_name=parser_name)
                if rdp_only:
                    result = _filter_rdp_only_result(result)
                _apply_display_source_name(result, display_names.get(fpath, result.file_name))
                parse_results.append(result)
                if not quiet:
                    emit(f"✓ ({result.stats.total} 事件)")
            except Exception as e:
                safe_error = sanitize_report_text(e)
                errors.append(f"{fname}: {safe_error}")
                if not quiet:
                    emit(f"✗ 错误: {safe_error}", flush=True)
                continue
    else:
        if not quiet:
            emit(f"  并行解析（{workers} 个线程）...")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_path = {pool.submit(auto_parse, fpath, parser_name): fpath for fpath in files}
            for done, future in enumerate(as_completed(future_to_path), 1):
                fpath = future_to_path[future]
                fname = sanitize_report_text(display_names.get(fpath, os.path.basename(fpath)))
                try:
                    result = future.result()
                    if rdp_only:
                        result = _filter_rdp_only_result(result)
                    _apply_display_source_name(result, display_names.get(fpath, result.file_name))
                    parse_results.append(result)
                    if not quiet:
                        emit(f"  [{done}/{len(files)}] ✓ {fname} ({result.stats.total} 事件)")
                except Exception as e:
                    safe_error = sanitize_report_text(e)
                    errors.append(f"{fname}: {safe_error}")
                    if not quiet:
                        emit(f"  [{done}/{len(files)}] ✗ {fname}: {safe_error}", flush=True)
    if errors_out is not None:
        errors_out.extend(errors)
    if errors and not parse_results:
        joined = "\n- ".join(errors)
        if quiet:
            raise AnalysisError(f"所有文件解析失败；请先处理解析错误：\n- {joined}")
        raise AnalysisError("所有文件解析失败；请先处理上方解析错误。")
    return parse_results


def _source_display_names(files: List[str]) -> Dict[str, str]:
    """Return stable, non-absolute labels for parsed inputs.

    Unique basenames keep the historical display name. When multiple inputs
    share a basename, use the shortest path suffix that distinguishes them.
    """
    labels = {path: os.path.basename(path) for path in files}
    basename_groups: Dict[str, List[str]] = {}
    for path in files:
        basename_groups.setdefault(os.path.basename(path), []).append(path)

    for group in basename_groups.values():
        if len(group) <= 1:
            continue
        parts_by_path = {path: _path_suffix_parts(path) for path in group}
        max_depth = max((len(parts) for parts in parts_by_path.values()), default=1)
        for depth in range(2, max_depth + 1):
            candidates = {
                path: "/".join(parts[-depth:])
                for path, parts in parts_by_path.items()
            }
            if len(set(candidates.values())) == len(group):
                labels.update(candidates)
                break
        else:
            labels.update({
                path: "/".join(parts_by_path[path])
                for path in group
            })
    return labels


def _path_suffix_parts(path: str) -> List[str]:
    normalized = os.path.normpath(path).replace("\\", "/")
    parts = [part for part in normalized.split("/") if part and part != "."]
    return parts or [os.path.basename(path)]


def _apply_display_source_name(result: ParseResult, display_name: Optional[str]) -> None:
    if not display_name or display_name == result.file_name:
        return
    original_name = result.file_name
    result.file_name = display_name
    for event in result.events:
        if event.source_file == original_name:
            event.source_file = display_name


def build_local_manifest_context(
    files: List[str],
    parse_results: List[ParseResult],
    parse_errors: Optional[List[str]] = None,
    suppressed_events: int = 0,
) -> Dict[str, Any]:
    """Build local input provenance for a report bundle manifest."""
    return _local_manifest_context(files, parse_results, parse_errors or [], suppressed_events)


def _local_manifest_context(
    files: List[str],
    parse_results: List[ParseResult],
    parse_errors: List[str],
    suppressed_events: int,
) -> Dict[str, Any]:
    result_by_name = {result.file_name: result for result in parse_results}
    display_names = _source_display_names(files)
    inputs = []
    for path in files:
        name = display_names.get(path, os.path.basename(path))
        result = result_by_name.get(name)
        inputs.append({
            "name": name,
            "type": result.log_type if result else "",
            "size_bytes": _file_size_or_zero(path),
            "sha256": _sha256_file_or_empty(path),
            "events": result.stats.total if result else 0,
        })
    return {
        "inputs": inputs,
        "parse_errors": list(parse_errors),
        "suppressed_events": suppressed_events,
    }


def _file_size_or_zero(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _sha256_file_or_empty(path: str) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def run_analysis(
    options: AnalysisOptions,
    quiet: bool = True,
    print_fn: Optional[PrintFn] = None,
) -> AnalysisRunResult:
    """Run parse -> enrich -> allowlist -> detect, optionally writing reports."""
    _configure_runtime(options)
    files = collect_files(options.paths)
    if not files:
        raise AnalysisError("未找到任何日志文件")

    reset_counter()
    parse_errors: List[str] = []
    parse_results = parse_files(
        files,
        options.jobs,
        parser_name=options.parser_name,
        quiet=quiet,
        print_fn=print_fn,
        rdp_only=options.rdp_only,
        errors_out=parse_errors,
    )
    if not parse_results:
        raise AnalysisError("所有文件解析失败")

    for result in parse_results:
        enrich_events(result.events)

    suppressed = 0
    if options.allowlist_path:
        allowlist = load_allowlist(options.allowlist_path)
        parse_results, suppressed = apply_allowlist(parse_results, allowlist)

    all_events = [event for result in parse_results for event in result.events]
    summary = run_detection(all_events, profile=options.profile, pre_enriched=True)
    ensure_incident_brief(parse_results, summary)
    if options.outputs:
        manifest_context = (
            build_local_manifest_context(files, parse_results, parse_errors, suppressed)
            if options.outputs.bundle_dir else None
        )
        write_reports(parse_results, summary, options.outputs, manifest_context=manifest_context)

    return AnalysisRunResult(
        files=files,
        parse_results=parse_results,
        summary=summary,
        suppressed_events=suppressed,
        parse_errors=parse_errors,
    )


def write_reports(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    outputs: AnalysisOutputs,
    manifest_context: Optional[Dict[str, Any]] = None,
) -> None:
    if outputs.html:
        generate_html_report(parse_results, summary, outputs.html, geoip_cache_path=outputs.geoip_cache_path)
    if outputs.json:
        generate_json_report(
            parse_results,
            summary,
            outputs.json,
            include_events=outputs.include_json_events,
            events_limit=outputs.json_events_limit,
            raw_line_limit=outputs.json_raw_line_limit,
        )
    if outputs.csv:
        generate_csv_report(parse_results, summary, outputs.csv)
    if outputs.ioc:
        generate_ioc_report(parse_results, summary, outputs.ioc)
    if outputs.sarif:
        generate_sarif_report(parse_results, summary, outputs.sarif)
    if outputs.brief:
        generate_incident_brief_report(parse_results, summary, outputs.brief)
    if outputs.evidence_csv:
        generate_incident_evidence_csv(parse_results, summary, outputs.evidence_csv)
    if outputs.bundle_dir:
        generate_report_bundle(
            parse_results,
            summary,
            outputs.bundle_dir,
            manifest_context=manifest_context,
            geoip_cache_path=outputs.geoip_cache_path,
            include_json_events=outputs.include_json_events,
            json_events_limit=outputs.json_events_limit,
            json_raw_line_limit=outputs.json_raw_line_limit,
        )


def _configure_runtime(options: AnalysisOptions) -> None:
    if options.syslog_year is not None:
        set_syslog_year(options.syslog_year)

    thresholds = load_thresholds_from_env(DEFAULT_THRESHOLDS, validate=options.config_path is None)
    if options.config_path:
        thresholds = load_thresholds(options.config_path, base=thresholds)
    set_thresholds(thresholds)

    rule_dirs: List[str] = []
    if os.environ.get("BLA_RULES_DIR"):
        rule_dirs.extend([p for p in os.environ["BLA_RULES_DIR"].split(os.pathsep) if p])
    if options.rule_dirs:
        rule_dirs.extend(options.rule_dirs)
    set_rule_dirs(rule_dirs)


def _filter_rdp_only_result(result: ParseResult) -> ParseResult:
    filtered_events = [
        event for event in result.events
        if event.event_id in {"4624", "4625"} and _has_remote_logon_source(event)
    ]
    stats = compute_stats(filtered_events)
    stats.parse_errors = result.stats.parse_errors
    return ParseResult(
        file_name=result.file_name,
        log_type=result.log_type,
        events=filtered_events,
        stats=stats,
        parse_time_ms=result.parse_time_ms,
        file_size_bytes=result.file_size_bytes,
    )


def _has_remote_logon_source(event: LogEvent) -> bool:
    logon_type = str(event.details.get("LogonType") or event.details.get("logon_type") or "").strip()
    return logon_type == "10" and bool(event.details.get("source_ip") or event.ip)
