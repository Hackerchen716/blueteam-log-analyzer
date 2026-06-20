"""Tests for the allowlist suppression engine."""
from _support import *  # noqa: F401,F403

from bla.allowlist import is_allowlisted, load_allowlist


def _ev(**kw):
    base = dict(
        id=gen_id("t"), timestamp="2024-03-15T10:00:00", level=ThreatLevel.HIGH,
        category="Web", source="Web", source_file="a.log", message="m", raw_line="r",
    )
    details = kw.pop("details", {})
    base.update(kw)
    ev = LogEvent(**base)
    ev.details.update(details)
    return ev


class ExactFieldMatchTests(unittest.TestCase):
    def test_ip_user_host_process_rule_event_match(self):
        self.assertTrue(is_allowlisted(_ev(ip="10.0.0.5"), {"ips": ["10.0.0.5"]}))
        self.assertTrue(is_allowlisted(_ev(user="svc"), {"users": ["SVC"]}))  # 大小写无关
        self.assertTrue(is_allowlisted(_ev(host="db01"), {"hosts": ["db01"]}))
        self.assertTrue(is_allowlisted(_ev(process="agent.exe"), {"processes": ["agent.exe"]}))
        self.assertTrue(is_allowlisted(_ev(rule_id="WEB-SCANNER-001"), {"rule_ids": ["WEB-SCANNER-001"]}))
        self.assertTrue(is_allowlisted(_ev(event_id="4625"), {"event_ids": ["4625"]}))

    def test_tag_and_source_type_match(self):
        self.assertTrue(is_allowlisted(_ev(tags=["web-baseline"]), {"tags": ["web-baseline"]}))
        self.assertTrue(is_allowlisted(_ev(details={"source_type": "waf"}), {"source_types": ["waf"]}))

    def test_no_match_returns_false(self):
        self.assertFalse(is_allowlisted(_ev(ip="1.2.3.4"), {"ips": ["10.0.0.5"]}))
        self.assertFalse(is_allowlisted(_ev(ip="1.2.3.4"), {}))


class ContainsMatchTests(unittest.TestCase):
    def test_path_user_agent_message_contains(self):
        self.assertTrue(is_allowlisted(_ev(details={"path": "/health/live"}), {"paths": ["/health"]}))
        self.assertTrue(is_allowlisted(_ev(details={"user_agent": "ELB-HealthChecker/2.0"}), {"user_agents": ["healthchecker"]}))
        self.assertTrue(is_allowlisted(_ev(message="routine backup ok"), {"messages": ["backup"]}))


class TrustedScannerTests(unittest.TestCase):
    def test_trusted_scanner_only_with_scanner_tag(self):
        al = {"trusted_scanners": ["10.0.0.9"]}
        self.assertTrue(is_allowlisted(_ev(ip="10.0.0.9", tags=["scanner"]), al))
        # 同 IP 但没有扫描类标签时不应被放行
        self.assertFalse(is_allowlisted(_ev(ip="10.0.0.9", tags=["web-attack"]), al))


class MaintenanceWindowTests(unittest.TestCase):
    def test_window_requires_time_and_scope(self):
        al = {"maintenance_windows": [
            {"start": "2024-03-15T09:00:00", "end": "2024-03-15T11:00:00", "hosts": ["db01"]}
        ]}
        self.assertTrue(is_allowlisted(_ev(timestamp="2024-03-15T10:00:00", host="db01"), al))
        # 时间在窗口外
        self.assertFalse(is_allowlisted(_ev(timestamp="2024-03-15T12:00:00", host="db01"), al))
        # 主机不在窗口范围
        self.assertFalse(is_allowlisted(_ev(timestamp="2024-03-15T10:00:00", host="web01"), al))


class SuppressionTests(unittest.TestCase):
    def test_suppression_requires_all_scope_to_match(self):
        al = {"suppressions": [{"ips": ["10.0.0.5"], "rule_ids": ["WEB-SCANNER-001"]}]}
        self.assertTrue(is_allowlisted(_ev(ip="10.0.0.5", rule_id="WEB-SCANNER-001"), al))
        # 同 IP 但规则不同 → 不抑制（AND 语义）
        self.assertFalse(is_allowlisted(_ev(ip="10.0.0.5", rule_id="WEB-SQLI-001"), al))

    def test_empty_suppression_never_matches(self):
        self.assertFalse(is_allowlisted(_ev(ip="10.0.0.5"), {"suppressions": [{}]}))


class ApplyAllowlistTests(unittest.TestCase):
    def test_apply_filters_and_counts_and_recomputes_stats(self):
        events = [_ev(ip="10.0.0.5", level=ThreatLevel.HIGH), _ev(ip="9.9.9.9", level=ThreatLevel.HIGH)]
        result = ParseResult(
            file_name="a.log", log_type="Web Access Log", events=events,
            stats=ParseStats(total=2), parse_time_ms=1.0, file_size_bytes=10,
        )
        filtered, suppressed = apply_allowlist([result], {"ips": ["10.0.0.5"]})
        self.assertEqual(suppressed, 1)
        self.assertEqual(len(filtered[0].events), 1)
        self.assertEqual(filtered[0].events[0].ip, "9.9.9.9")
        self.assertEqual(filtered[0].stats.total, 1)


class LoadAllowlistTests(unittest.TestCase):
    def _write(self, payload):
        path = Path(tempfile.mkdtemp()) / "al.json"
        path.write_text(_json.dumps(payload), encoding="utf-8")
        return str(path)

    def test_load_valid(self):
        al = load_allowlist(self._write({"ips": ["10.0.0.5"], "paths": "/health"}))
        self.assertEqual(al["ips"], ["10.0.0.5"])
        self.assertEqual(al["paths"], ["/health"])  # 字符串被规整为列表

    def test_unknown_field_rejected(self):
        with self.assertRaises(ValueError):
            load_allowlist(self._write({"bogus": ["x"]}))

    def test_wrong_value_type_rejected(self):
        with self.assertRaises(ValueError):
            load_allowlist(self._write({"ips": {"not": "a list"}}))

    def test_maintenance_windows_must_be_object_array(self):
        with self.assertRaises(ValueError):
            load_allowlist(self._write({"maintenance_windows": ["not-an-object"]}))

    def test_non_dict_root_rejected(self):
        with self.assertRaises(ValueError):
            load_allowlist(self._write(["not", "a", "dict"]))


if __name__ == "__main__":
    unittest.main()
