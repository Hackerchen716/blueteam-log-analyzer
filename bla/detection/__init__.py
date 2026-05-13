"""
BlueTeam Log Analyzer - 威胁检测引擎
"""
from .engine import run_detection as _engine_run_detection
from .engine import list_detector_names, register_detector
from .correlation import correlate_incidents
from .enrichment import enrich_events
from .evidence import enrich_alert_evidence
from .registry import DetectorRegistry, DetectorSpec


def run_detection(events, profile: str = "default", pre_enriched: bool = False, detector_registry=None):
    summary = _engine_run_detection(
        events,
        profile=profile,
        pre_enriched=pre_enriched,
        detector_registry=detector_registry,
    )
    summary.alerts = enrich_alert_evidence(summary.alerts, events)
    return summary


__all__ = [
    "DetectorRegistry",
    "DetectorSpec",
    "correlate_incidents",
    "enrich_alert_evidence",
    "enrich_events",
    "list_detector_names",
    "register_detector",
    "run_detection",
]
