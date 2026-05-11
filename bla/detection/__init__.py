"""
BlueTeam Log Analyzer - 威胁检测引擎
"""
from .engine import run_detection as _engine_run_detection
from .correlation import correlate_incidents
from .enrichment import enrich_events
from .evidence import enrich_alert_evidence


def run_detection(events, profile: str = "default"):
    summary = _engine_run_detection(events, profile=profile)
    summary.alerts = enrich_alert_evidence(summary.alerts, events)
    return summary


__all__ = ["run_detection", "correlate_incidents", "enrich_events", "enrich_alert_evidence"]
