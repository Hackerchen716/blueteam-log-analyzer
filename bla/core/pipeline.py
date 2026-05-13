"""Reusable analysis pipeline for CLI, collectors, tests, and future UI layers."""
from __future__ import annotations

import glob
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional

from ..allowlist import apply_allowlist, load_allowlist
from ..config import load_thresholds, load_thresholds_from_env, set_thresholds
from ..detection import run_detection
from ..detection.enrichment import enrich_events
from ..models import AnalysisSummary, ParseResult
from ..output import (
    generate_csv_report,
    generate_html_report,
    generate_ioc_report,
    generate_json_report,
    generate_report_bundle,
    generate_sarif_report,
)
from ..parsers import auto_parse
from ..rules import set_rule_dirs
from ..utils.helpers import reset_counter, set_syslog_year

PrintFn = Callable[..., None]


class AnalysisError(RuntimeError):
    """Raised when the pipeline cannot complete a user-facing analysis."""


@dataclass
class AnalysisOutputs:
    html: Optional[str] = None
    json: Optional[str] = None
    csv: Optional[str] = None
    ioc: Optional[str] = None
    sarif: Optional[str] = None
    bundle_dir: Optional[str] = None


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
    outputs: Optional[AnalysisOutputs] = None


@dataclass
class AnalysisRunResult:
    files: List[str]
    parse_results: List[ParseResult]
    summary: AnalysisSummary
    suppressed_events: int = 0


def collect_files(paths: Iterable[str]) -> List[str]:
    files = []
    for path in paths:
        if os.path.isfile(path):
            files.append(path)
        elif os.path.isdir(path):
            for root, _, fnames in os.walk(path):
                for fname in fnames:
                    if not fname.startswith("."):
                        files.append(os.path.join(root, fname))
        else:
            files.extend(glob.glob(path))
    return sorted(set(files))


def parse_files(
    files: List[str],
    jobs: int = 0,
    parser_name: Optional[str] = None,
    quiet: bool = False,
    print_fn: Optional[PrintFn] = None,
) -> List[ParseResult]:
    parse_results: List[ParseResult] = []
    errors: List[str] = []
    workers = jobs if jobs > 0 else min(8, max(1, len(files)))
    emit = print_fn if print_fn is not None else print
    if len(files) <= 1 or workers == 1:
        for i, fpath in enumerate(files, 1):
            fname = os.path.basename(fpath)
            if not quiet:
                emit(f"  [{i}/{len(files)}] 解析: {fname} ...", end=" ", flush=True)
            try:
                result = auto_parse(fpath, parser_name=parser_name)
                parse_results.append(result)
                if not quiet:
                    emit(f"✓ ({result.stats.total} 事件)")
            except Exception as e:
                errors.append(f"{fname}: {e}")
                if not quiet:
                    emit(f"✗ 错误: {e}", flush=True)
                continue
    else:
        if not quiet:
            emit(f"  并行解析（{workers} 个线程）...")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_path = {pool.submit(auto_parse, fpath, parser_name): fpath for fpath in files}
            for done, future in enumerate(as_completed(future_to_path), 1):
                fpath = future_to_path[future]
                fname = os.path.basename(fpath)
                try:
                    result = future.result()
                    parse_results.append(result)
                    if not quiet:
                        emit(f"  [{done}/{len(files)}] ✓ {fname} ({result.stats.total} 事件)")
                except Exception as e:
                    errors.append(f"{fname}: {e}")
                    if not quiet:
                        emit(f"  [{done}/{len(files)}] ✗ {fname}: {e}", flush=True)
    if errors and not parse_results:
        joined = "\n- ".join(errors)
        if quiet:
            raise AnalysisError(f"所有文件解析失败；请先处理解析错误：\n- {joined}")
        raise AnalysisError("所有文件解析失败；请先处理上方解析错误。")
    return parse_results


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
    parse_results = parse_files(
        files,
        options.jobs,
        parser_name=options.parser_name,
        quiet=quiet,
        print_fn=print_fn,
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
    if options.outputs:
        write_reports(parse_results, summary, options.outputs)

    return AnalysisRunResult(
        files=files,
        parse_results=parse_results,
        summary=summary,
        suppressed_events=suppressed,
    )


def write_reports(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    outputs: AnalysisOutputs,
) -> None:
    if outputs.html:
        generate_html_report(parse_results, summary, outputs.html)
    if outputs.json:
        generate_json_report(parse_results, summary, outputs.json)
    if outputs.csv:
        generate_csv_report(parse_results, summary, outputs.csv)
    if outputs.ioc:
        generate_ioc_report(parse_results, summary, outputs.ioc)
    if outputs.sarif:
        generate_sarif_report(parse_results, summary, outputs.sarif)
    if outputs.bundle_dir:
        generate_report_bundle(parse_results, summary, outputs.bundle_dir)


def _configure_runtime(options: AnalysisOptions) -> None:
    if options.syslog_year is not None:
        set_syslog_year(options.syslog_year)

    set_thresholds(load_thresholds_from_env())
    if options.config_path:
        set_thresholds(load_thresholds(options.config_path))

    rule_dirs: List[str] = []
    if os.environ.get("BLA_RULES_DIR"):
        rule_dirs.extend([p for p in os.environ["BLA_RULES_DIR"].split(os.pathsep) if p])
    if options.rule_dirs:
        rule_dirs.extend(options.rule_dirs)
    set_rule_dirs(rule_dirs)
