"""Shared imports for regression test modules.

The split regression files intentionally import these names with ``*`` so
individual test modules stay focused on behavior rather than boilerplate.
"""
import csv
import io
import json as _json
import os
import subprocess
import sys
import tempfile
import unittest
import warnings
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from bla.__version__ import __version__
from bla.allowlist import apply_allowlist
from bla.config import (
    DEFAULT_THRESHOLDS,
    THRESHOLDS,
    Thresholds,
    load_thresholds,
    load_thresholds_from_env,
    set_thresholds,
)
from bla.core import AnalysisError, AnalysisOptions, collect_files, run_analysis
from bla.core.pipeline import parse_files
from bla.detection import DetectorRegistry, DetectorSpec, list_detector_names, run_detection
from bla.detection.engine import _dedup_alerts
from bla.ioc import extract_iocs, format_ioc_report
from bla.log_sources import LOG_SOURCE_PRIORITIES, format_log_source_priorities
from bla.models import (
    AnalysisSummary,
    DetectionAlert,
    LogEvent,
    ParseResult,
    ParseStats,
    ThreatLevel,
    TimelineEntry,
)
from bla.output.bundle import generate_report_bundle
from bla.output.csv_report import generate_csv_report
from bla.output.html_report import generate_html_report
from bla.output.json_report import generate_json_report
from bla.output.manifest import generate_manifest
from bla.output.sarif_report import generate_sarif_report
from bla.output.terminal import print_terminal_report
from bla.parsers import _parse_generic, auto_parse, list_parser_names, parse_content
from bla.parsers.linux_auth import parse_linux_auth
from bla.parsers.p0_security import (
    list_p0_adapter_kinds,
    parse_p0_security_json,
    parse_p0_security_json_file,
    parse_p0_security_lines,
)
from bla.parsers.shell_history import parse_shell_history
from bla.parsers.web_access import parse_web_access
from bla.parsers.windows_evtx import _parse_xml_event, parse_windows_xml, parse_windows_xml_file
from bla.remote import RemoteWorkspace, SSHClient
from bla.remote.ssh_workspace import _split_workspace_line
from bla.rules import reset_rule_cache, set_rule_dirs, validate_web_attack_rules
from bla.rules.loader import _parse_simple_yaml
from bla.utils.helpers import gen_id, is_private_ip, normalize_timestamp, reset_counter, set_syslog_year

__all__ = [
    name for name in globals()
    if name == "__version__" or not name.startswith("__")
]
