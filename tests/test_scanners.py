"""Tests for scanner/User-Agent enrichment helpers."""
from _support import *  # noqa: F401,F403

from bla.detection.scanners import detect_scanner_tool, summarize_scanner_events


def _ev(**details):
    return LogEvent(
        id=gen_id("t"), timestamp="2024-03-15T10:00:00", level=ThreatLevel.HIGH,
        category="扫描器", source="Web", source_file="a.log", message="m", raw_line="r",
        details=details,
    )


class DetectScannerToolTests(unittest.TestCase):
    def test_known_tools(self):
        self.assertEqual(detect_scanner_tool("sqlmap/1.7"), "sqlmap")
        self.assertEqual(detect_scanner_tool("Mozilla nikto scan"), "nikto")
        self.assertEqual(detect_scanner_tool("curl/8.0"), "curl")
        self.assertEqual(detect_scanner_tool("python-requests/2.31"), "python-requests")
        self.assertEqual(detect_scanner_tool("Nmap Scripting Engine"), "nmap")

    def test_empty_or_benign_returns_blank(self):
        self.assertEqual(detect_scanner_tool(""), "")
        self.assertEqual(detect_scanner_tool(None), "")
        self.assertEqual(
            detect_scanner_tool("Mozilla/5.0 (Windows NT 10.0) Chrome/120"), ""
        )


class SummarizeScannerEventsTests(unittest.TestCase):
    def test_builds_evidence_lines(self):
        events = [
            _ev(scanner_tool="sqlmap", user_agent="sqlmap/1.7", method="GET", decoded_path="/a"),
            _ev(scanner_tool="sqlmap", user_agent="sqlmap/1.7", method="GET", decoded_path="/b"),
        ]
        evidence = summarize_scanner_events(events)
        joined = "\n".join(evidence)
        self.assertIn("扫描工具: sqlmap", joined)
        self.assertIn("User-Agent: sqlmap/1.7", joined)
        self.assertIn("请求方法: GET", joined)
        self.assertIn("典型路径: /a, /b", joined)

    def test_dedups_and_caps_paths(self):
        events = [_ev(path=f"/p{i}") for i in range(10)] + [_ev(path="/p0")]
        evidence = summarize_scanner_events(events, max_paths=3)
        path_line = next(line for line in evidence if line.startswith("典型路径"))
        self.assertEqual(path_line.count("/p"), 3)

    def test_empty_events_yield_no_evidence(self):
        self.assertEqual(summarize_scanner_events([]), [])


if __name__ == "__main__":
    unittest.main()
