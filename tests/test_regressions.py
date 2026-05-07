import tempfile
import unittest
from pathlib import Path

from bla.allowlist import apply_allowlist
from bla.detection import run_detection
from bla.ioc import extract_iocs, format_ioc_report
from bla.output.html_report import generate_html_report
from bla.output.terminal import print_terminal_report
from bla.parsers.web_access import parse_web_access
from bla.parsers.windows_evtx import _parse_xml_event
from bla.utils.helpers import normalize_timestamp, set_syslog_year


class RegressionTests(unittest.TestCase):
    def test_web_payload_with_spaces_is_detected_as_sqli(self):
        content = (
            "1.1.1.1 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET /login.php?id=1 UNION SELECT NULL-- HTTP/1.1\" "
            "200 10 \"-\" \"Mozilla/5.0\"\n"
        )

        result = parse_web_access(content, "access.log")
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].rule_name, "SQL注入")

        summary = run_detection(result.events)
        self.assertTrue(any(alert.rule_name == "Web攻击: SQL注入" for alert in summary.alerts))

    def test_high_frequency_success_requests_create_volume_alert(self):
        content = "".join(
            "1.1.1.1 - - [15/Mar/2024:10:00:%02d +0800] "
            "\"GET /index.html HTTP/1.1\" 200 10 \"-\" \"Mozilla/5.0\"\n" % (i % 60)
            for i in range(120)
        )

        result = parse_web_access(content, "access.log")
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].rule_name, "自动化扫描/高频访问")

        summary = run_detection(result.events)
        self.assertTrue(any(alert.rule_id == "RECON-003" for alert in summary.alerts))

    def test_html_report_escapes_attacker_controlled_content_and_stays_offline(self):
        content = (
            "1.1.1.1 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET /search.php?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\" "
            "200 10 \"-\" \"Mozilla/5.0\"\n"
        )
        result = parse_web_access(content, "access.log")
        summary = run_detection(result.events)

        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.html"
            generate_html_report([result], summary, str(report_path))
            html = report_path.read_text(encoding="utf-8")

        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("cdn.jsdelivr", html)
        self.assertNotIn("new Chart", html)

    def test_windows_event_with_malformed_logon_type_is_not_dropped(self):
        xml = (
            "<Event><System><EventID>4625</EventID>"
            "<TimeCreated SystemTime=\"2024-03-15T01:02:03.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">bob</Data>"
            "<Data Name=\"IpAddress\">1.2.3.4</Data>"
            "<Data Name=\"LogonType\">-</Data></EventData></Event>"
        )

        event = _parse_xml_event(xml, "security.xml")
        self.assertIsNotNone(event)
        self.assertEqual(event.event_id, "4625")
        self.assertEqual(event.user, "bob")

    def test_syslog_year_can_be_overridden_for_historical_logs(self):
        try:
            set_syslog_year(2024)
            self.assertEqual(normalize_timestamp("Mar 15 09:00:01"), "2024-03-15T09:00:01")
        finally:
            set_syslog_year(None)

    def test_cn_hvv_profile_detects_common_domestic_exploit_traces(self):
        content = (
            "2.2.2.2 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET /index.action?redirect:%24%7B%23_memberAccess%5B%27allowStaticMethodAccess%27%5D=true%7D HTTP/1.1\" "
            "200 10 \"-\" \"curl/8.0\"\n"
            "2.2.2.3 - - [15/Mar/2024:10:01:00 +0800] "
            "\"POST /upload/shell.jsp?cmd=whoami HTTP/1.1\" 200 10 \"-\" \"Behinder\"\n"
        )

        result = parse_web_access(content, "access.log")
        summary = run_detection(result.events, profile="cn-hvv")

        self.assertTrue(any(alert.rule_id == "CN-HVV-001" for alert in summary.alerts))
        self.assertTrue(any("cn-hvv" in event.tags for event in result.events))

    def test_ioc_extraction_and_text_export(self):
        content = (
            "3.3.3.3 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET /upload/shell.jsp?cmd=whoami HTTP/1.1\" 200 10 "
            "\"http://evil.example/a\" \"Behinder\"\n"
        )
        result = parse_web_access(content, "access.log")

        iocs = extract_iocs(result.events)
        report = format_ioc_report(iocs)

        self.assertIn("3.3.3.3", iocs["ips"])
        self.assertIn("evil.example", iocs["domains"])
        self.assertIn("/upload/shell.jsp", iocs["file_paths"])
        self.assertIn("## IP", report)

    def test_allowlist_suppresses_trusted_noise_before_detection(self):
        content = (
            "10.0.0.5 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET /health HTTP/1.1\" 403 10 \"-\" \"ELB-HealthChecker\"\n"
            "9.9.9.9 - - [15/Mar/2024:10:01:00 +0800] "
            "\"GET /admin.php HTTP/1.1\" 403 10 \"-\" \"Mozilla/5.0\"\n"
        )
        result = parse_web_access(content, "access.log")

        filtered, suppressed = apply_allowlist([result], {
            "ips": ["10.0.0.5"],
            "paths": ["/health"],
            "user_agents": ["ELB-HealthChecker"],
        })

        self.assertEqual(suppressed, 1)
        self.assertEqual(len(filtered[0].events), 1)
        self.assertEqual(filtered[0].events[0].ip, "9.9.9.9")

    def test_terminal_report_can_cap_large_alert_lists(self):
        content = "".join(
            "%d.0.0.1 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET /wp-login.php HTTP/1.1\" 404 10 \"-\" \"Mozilla/5.0\"\n" % i
            for i in range(1, 12)
        )
        result = parse_web_access(content, "access.log")
        summary = run_detection(result.events)

        import io
        import sys
        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            print_terminal_report([result], summary, no_color=True, max_alerts=1)
        finally:
            sys.stdout = old_stdout

        self.assertIn("终端仅展示前 1 个告警", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
