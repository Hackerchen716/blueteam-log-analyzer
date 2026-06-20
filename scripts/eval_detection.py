#!/usr/bin/env python3
"""Measurable detection-quality harness for BLA.

Runs the Web-access detection path over a labeled corpus and reports a
confusion matrix plus precision / recall / false-positive rate. The corpus
deliberately includes *adversarial benign* traffic (requests that look like
attacks but are normal) so the false-positive rate is meaningful rather than
self-congratulatory.

Usage:
    python3 scripts/eval_detection.py            # print the matrix
    python3 scripts/eval_detection.py --min-recall 0.95 --max-fp-rate 0.0
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bla.detection import run_detection  # noqa: E402
from bla.parsers import auto_parse, parse_content  # noqa: E402
from bla.parsers.web_access import parse_web_access  # noqa: E402

DEFAULT_CASES = ROOT / "tests" / "fixtures" / "detection_quality" / "cases.jsonl"


def load_cases(path: Path, base_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Load JSONL cases. ``file`` entries are resolved relative to ``base_dir``."""
    base = base_dir or path.parent
    cases = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        case = json.loads(line)
        if "file" in case:
            case["_resolved_file"] = str((base / case["file"]).resolve())
        cases.append(case)
    return cases


def _log_line(case: Dict[str, Any]) -> str:
    request = case["request"]
    status = case.get("status", 200)
    ua = case.get("ua", "Mozilla/5.0")
    return f'1.2.3.4 - - [15/Mar/2024:10:00:00 +0800] "{request}" {status} 10 "-" "{ua}"\n'


def _events_for_case(case: Dict[str, Any]):
    """Build LogEvents from one of three input kinds: request | content | file."""
    if "request" in case:
        return parse_web_access(_log_line(case), "eval.log").events
    if "content" in case:
        return parse_content(
            case["content"], case.get("source", "eval.log"), parser_name=case.get("parser")
        ).events
    if "file" in case:
        path = case.get("_resolved_file", case["file"])
        parser = case.get("parser")
        if parser:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
            return parse_content(text, Path(path).name, parser_name=parser).events
        return auto_parse(str(path)).events
    raise ValueError(f"case 缺少 request/content/file: {case.get('name')}")


def run_case(case: Dict[str, Any]) -> Dict[str, Any]:
    """Run full parse + detection; flagged = the tool raised at least one alert.

    使用真实告警（而非单纯的 web-attack 标签）作为信号，衡量用户实际看到的检测结果，
    覆盖 web 之外的爆破/横向/持久化等全部检测器。
    """
    events = _events_for_case(case)
    summary = run_detection(events, profile=case.get("profile", "default"))
    alerts = summary.alerts
    return {
        "flagged": bool(alerts),
        "rule_ids": sorted({a.rule_id for a in alerts if a.rule_id}),
        "rule_names": sorted({a.rule_name for a in alerts if a.rule_name}),
    }


def _metrics(tp: int, fp: int, fn: int, tn: int) -> Dict[str, float]:
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    fp_rate = fp / (fp + tn) if (fp + tn) else 0.0
    total = tp + fp + fn + tn
    accuracy = (tp + tn) / total if total else 1.0
    return {"precision": precision, "recall": recall, "fp_rate": fp_rate, "accuracy": accuracy}


def evaluate(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    tp = fp = fn = tn = 0
    false_positives: List[Dict[str, Any]] = []
    false_negatives: List[Dict[str, Any]] = []
    by_category: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})

    for case in cases:
        expected = bool(case["expect_alert"])
        outcome = run_case(case)
        flagged = outcome["flagged"]
        cat = case.get("category", "?")
        if expected and flagged:
            tp += 1
            by_category[cat]["tp"] += 1
        elif expected and not flagged:
            fn += 1
            by_category[cat]["fn"] += 1
            false_negatives.append({"name": case["name"], "request": case["request"]})
        elif not expected and flagged:
            fp += 1
            by_category[cat]["fp"] += 1
            false_positives.append({
                "name": case["name"], "request": case["request"],
                "rule_ids": outcome["rule_ids"], "rule_names": outcome["rule_names"],
            })
        else:
            tn += 1
            by_category[cat]["tn"] += 1

    summary = {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "total": len(cases)}
    summary.update(_metrics(tp, fp, fn, tn))
    return {
        "summary": summary,
        "by_category": dict(by_category),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


def _print_report(report: Dict[str, Any]) -> None:
    s = report["summary"]
    print("=" * 64)
    print(" BLA 检测质量评测")
    print("=" * 64)
    print(f"  样本: {s['total']}   TP={s['tp']} FP={s['fp']} FN={s['fn']} TN={s['tn']}")
    print(f"  precision={s['precision']:.3f}  recall={s['recall']:.3f}  "
          f"误报率={s['fp_rate']:.3f}  accuracy={s['accuracy']:.3f}")
    print("-" * 64)
    print("  分类             TP  FP  FN  TN")
    for cat, c in sorted(report["by_category"].items()):
        print(f"  {cat:14}  {c['tp']:>3} {c['fp']:>3} {c['fn']:>3} {c['tn']:>3}")
    if report["false_negatives"]:
        print("-" * 64)
        print("  漏报 (应告警但未命中):")
        for item in report["false_negatives"]:
            print(f"    - {item['name']}: {item['request']}")
    if report["false_positives"]:
        print("-" * 64)
        print("  误报 (良性却被标记):")
        for item in report["false_positives"]:
            print(f"    - {item['name']}: {item['request']}  -> {', '.join(item['rule_ids']) or '?'}")
    print("=" * 64)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run BLA detection-quality evaluation.")
    parser.add_argument("--cases", default=str(DEFAULT_CASES), help="labeled corpus JSONL path")
    parser.add_argument("--manifest", action="append", default=[],
                        help="extra JSONL with file-based real-log cases (repeatable)")
    parser.add_argument("--min-recall", type=float, default=0.0)
    parser.add_argument("--min-precision", type=float, default=0.0)
    parser.add_argument("--max-fp-rate", type=float, default=1.0)
    args = parser.parse_args()

    cases = load_cases(Path(args.cases))
    for manifest in args.manifest:
        manifest_path = Path(manifest)
        cases.extend(load_cases(manifest_path, base_dir=manifest_path.parent))
    report = evaluate(cases)
    _print_report(report)

    s = report["summary"]
    failed = []
    if s["recall"] < args.min_recall:
        failed.append(f"recall {s['recall']:.3f} < {args.min_recall}")
    if s["precision"] < args.min_precision:
        failed.append(f"precision {s['precision']:.3f} < {args.min_precision}")
    if s["fp_rate"] > args.max_fp_rate:
        failed.append(f"fp_rate {s['fp_rate']:.3f} > {args.max_fp_rate}")
    if failed:
        print("eval-detection FAILED: " + "; ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
