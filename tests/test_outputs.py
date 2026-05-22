from _support import *

class OutputRegressionTests(unittest.TestCase):
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

    def test_html_report_escapes_windows_logon_summary_fields(self):
        xml = (
            "<Event><System><EventID>4625</EventID>"
            "<TimeCreated SystemTime=\"2024-03-15T01:02:03.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">&lt;img src=x onerror=alert(1)&gt;</Data>"
            "<Data Name=\"TargetDomainName\">ACME</Data>"
            "<Data Name=\"IpAddress\">1.2.3.4</Data>"
            "<Data Name=\"LogonType\">3</Data>"
            "<Data Name=\"FailureReason\">bad</Data></EventData></Event>"
        )
        result = parse_windows_xml(xml, "security.xml")
        summary = run_detection(result.events)

        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.html"
            generate_html_report([result], summary, str(report_path))
            html = report_path.read_text(encoding="utf-8")

        self.assertNotIn("<img src=x onerror=alert(1)>", html)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)

    def test_html_report_stat_cards_jump_to_timeline_filters(self):
        """HTML 统计卡片应作为可点击入口，跳到对应级别事件时间线。"""
        event = LogEvent(
            id="evt-critical",
            timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.CRITICAL,
            category="测试",
            source="fixture",
            source_file="events.log",
            message="critical timeline event",
            raw_line="critical timeline event",
        )
        result = ParseResult(
            "events.log", "Fixture", [event],
            ParseStats(total=1, critical=1),
        )
        summary = AnalysisSummary(
            risk_score=80,
            risk_level=ThreatLevel.CRITICAL,
            alerts=[],
            timeline=[
                TimelineEntry(
                    event_id=event.id,
                    timestamp=event.timestamp,
                    level=event.level,
                    category=event.category,
                    message=event.message,
                    source_file=event.source_file,
                )
            ],
            attack_chain=[],
            recommendations=[],
            total_events=1,
            files_analyzed=1,
        )

        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.html"
            generate_html_report([result], summary, str(report_path))
            html = report_path.read_text(encoding="utf-8")

        self.assertIn('class="stat-card stat-link"', html)
        self.assertIn('data-level="critical"', html)
        self.assertIn("jumpToEvents('critical')", html)
        self.assertIn('id="timelineSection"', html)
        self.assertIn('class="tl-entry" data-level="critical"', html)
        self.assertIn("function setTimelineFilter", html)
        self.assertIn("function filterTimeline", html)
        self.assertIn('class="brand-logo"', html)
        self.assertIn("data:image/png;base64,", html)
        self.assertNotIn("bla/output/assets/bla-logo.png", html)

    def test_csv_report_neutralizes_spreadsheet_formulas(self):
        event = LogEvent(
            id="evt-1",
            timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.HIGH,
            category="测试",
            source="fixture",
            source_file="events.log",
            message="=HYPERLINK(\"http://evil.test\")",
            raw_line="-2+3",
            user="+cmd",
            host="@host",
            process="\t=calc",
            details={"command": " @SUM(1+1)", "url": "https://example.test/path"},
        )
        result = ParseResult("events.log", "Fixture", [event], ParseStats(total=1))
        summary = AnalysisSummary(
            risk_score=0,
            risk_level=ThreatLevel.INFO,
            alerts=[],
            timeline=[],
            attack_chain=[],
            recommendations=[],
            total_events=1,
            files_analyzed=1,
        )

        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "events.csv"
            generate_csv_report([result], summary, str(csv_path))
            with open(csv_path, newline="", encoding="utf-8-sig") as f:
                row = next(csv.DictReader(f))

        self.assertEqual(row["message"], "'=HYPERLINK(\"http://evil.test\")")
        self.assertEqual(row["user"], "'+cmd")
        self.assertEqual(row["host"], "'@host")
        self.assertEqual(row["process"], "'\t=calc")
        self.assertEqual(row["command"], "' @SUM(1+1)")
        self.assertEqual(row["raw_line"], "'-2+3")
        self.assertEqual(row["raw_line_truncated"], "false")
        self.assertEqual(row["raw_line_length"], "4")
        self.assertEqual(row["url"], "https://example.test/path")

    def test_csv_report_marks_raw_line_truncation_and_redacts_obvious_secrets(self):
        event = LogEvent(
            id="evt-long",
            timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.INFO,
            category="测试",
            source="fixture",
            source_file="events.log",
            message="ok",
            raw_line="token=super-secret " + "x" * 260,
            details={"url": "/api?access_token=abc123456789"},
        )
        result = ParseResult("events.log", "Fixture", [event], ParseStats(total=1))
        summary = AnalysisSummary(
            risk_score=0,
            risk_level=ThreatLevel.INFO,
            alerts=[],
            timeline=[],
            attack_chain=[],
            recommendations=[],
            total_events=1,
            files_analyzed=1,
        )

        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "events.csv"
            generate_csv_report([result], summary, str(csv_path))
            with open(csv_path, newline="", encoding="utf-8-sig") as f:
                row = next(csv.DictReader(f))

        self.assertEqual(row["raw_line_truncated"], "true")
        self.assertEqual(row["raw_line_length"], str(len("token=<redacted> " + "x" * 260)))
        self.assertIn("token=<redacted>", row["raw_line"])
        self.assertNotIn("super-secret", row["raw_line"])
        self.assertEqual(row["url"], "/api?access_token=<redacted>")

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

    def test_terminal_report_can_cap_large_alert_lists(self):
        content = "".join(
            "%d.0.0.1 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET /wp-login.php HTTP/1.1\" 404 10 \"-\" \"Mozilla/5.0\"\n" % i
            for i in range(1, 12)
        )
        result = parse_web_access(content, "access.log")
        summary = run_detection(result.events)

        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            print_terminal_report([result], summary, no_color=True, max_alerts=1)
        finally:
            sys.stdout = old_stdout

        self.assertIn("终端仅展示前 1 个告警", buf.getvalue())

    def test_terminal_report_strips_attacker_controlled_sequences(self):
        marker = "\x1b]52;c;SGFja2Vk\x07\x1b[31m"
        event = LogEvent(
            id="evt-term-1",
            timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.HIGH,
            category="Web攻击",
            source="fixture",
            source_file="access.log",
            message=f"{marker}message",
            raw_line=f"raw {marker}",
            ip="198.51.100.20",
            details={
                "method": "GET",
                "decoded_path": f"/shell.jsp?x={marker}",
                "user_agent": f"ua {marker}",
                "referer": f"ref {marker}",
            },
            tags=["web-attack"],
            mitre_attack="T1190",
            rule_name="测试",
        )
        alert = DetectionAlert(
            id="alert-term-1",
            rule_id="WEB-TERM",
            rule_name=f"{marker}Web 控制序列",
            description=f"desc {marker}",
            level=ThreatLevel.HIGH,
            category="Web攻击",
            mitre_attack="T1190",
            mitre_phase="初始访问",
            affected_events=[event.id],
            evidence=[f"evidence {marker}"],
            recommendation=f"rec {marker}",
            timestamp=event.timestamp,
            confidence="high",
        )
        result = ParseResult("access.log", "Fixture", [event], ParseStats(total=1, high=1))
        summary = AnalysisSummary(
            risk_score=80,
            risk_level=ThreatLevel.HIGH,
            alerts=[alert],
            timeline=[],
            attack_chain=[],
            recommendations=[f"action {marker}"],
            total_events=1,
            files_analyzed=1,
        )

        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            print_terminal_report([result], summary, no_color=True, full_evidence=True, verbose=True)
        finally:
            sys.stdout = old_stdout

        text = buf.getvalue()
        self.assertNotIn("\x1b]52", text)
        self.assertNotIn("\x1b[31m", text)
        self.assertNotIn("\x07", text)

    def test_terminal_truncation_uses_display_width_for_cjk_text(self):
        from bla.output.terminal import _display_width, _truncate_text

        text = "攻击路径=/var/www/html/uploads/一句很长的中文证据说明"
        truncated = _truncate_text(text, 24)

        self.assertLessEqual(_display_width(truncated), 24)
        self.assertTrue(truncated.endswith("…"))
        self.assertNotIn("\n", truncated)

    def test_terminal_report_filters_placeholder_top_ip_and_shows_utc8(self):
        result = ParseResult(
            "security.xml",
            "Fixture",
            [],
            ParseStats(
                total=2,
                top_ips=[{"ip": "192.168.126.1", "count": 6}],
                top_local_ips=[{"ip": "-", "count": 233}],
                time_start="2024-02-26T15:01:13+00:00",
                time_end="2024-02-26T15:02:24+00:00",
            ),
        )
        summary = AnalysisSummary(
            risk_score=0,
            risk_level=ThreatLevel.INFO,
            alerts=[],
            timeline=[],
            attack_chain=[],
            recommendations=[],
            total_events=0,
            files_analyzed=1,
        )

        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            print_terminal_report([result], summary, no_color=True)
        finally:
            sys.stdout = old_stdout
        text = buf.getvalue()
        self.assertIn("2024-02-26 23:01:13 UTC+8", text)
        self.assertIn("UTC: 2024-02-26T15:01:13Z", text)
        self.assertIn("有效远程源 IP", text)
        self.assertIn("192.168.126.1", text)
        self.assertIn("本机/空来源", text)

    def test_iocs_filter_to_alert_related_events_only(self):
        """正常业务流量不应该污染 IOC 列表，只有告警涉及的事件才贡献 IOC。"""
        content = (
            # 1) 正常业务流量
            "10.0.0.1 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET /index.html HTTP/1.1\" 200 10 \"-\" \"Mozilla/5.0\"\n"
            # 2) Webshell 攻击（会触发 web-attack 告警）
            "9.9.9.9 - - [15/Mar/2024:10:01:00 +0800] "
            "\"POST /upload/shell.jsp?cmd=whoami HTTP/1.1\" 200 10 \"-\" \"Behinder\"\n"
        )
        result = parse_web_access(content, "access.log")
        summary = run_detection(result.events)

        iocs = extract_iocs(result.events, alerts=summary.alerts)
        self.assertIn("9.9.9.9", iocs["ips"])
        self.assertNotIn("10.0.0.1", iocs["ips"],
                         "业务流量 IP 不应该出现在告警过滤后的 IOC 中")

    def test_html_report_attack_chain_has_no_trailing_arrow(self):
        """攻击链 HTML 末尾不能多出一个孤立箭头。"""
        # 用 webshell + 显式凭据生成多阶段攻击
        web_content = (
            "9.9.9.9 - - [15/Mar/2024:10:01:00 +0800] "
            "\"POST /upload/shell.jsp?cmd=whoami HTTP/1.1\" 200 10 \"-\" \"Behinder\"\n"
        )
        result = parse_web_access(web_content, "access.log")
        summary = run_detection(result.events)
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.html"
            generate_html_report([result], summary, str(report_path))
            html = report_path.read_text(encoding="utf-8")
        # chain-wrapper 内 15 个 phase 之间应该恰好 14 个箭头（不是 15 个）
        chain_section = html.split('class="chain-wrapper"', 1)[1].split("</div>", 50)[0:50]
        chain_block = "".join(chain_section)
        self.assertEqual(chain_block.count('class="chain-arrow"'), 14)

    def test_sarif_report_is_valid_and_maps_levels(self):
        """SARIF 输出应当包含 runs/tool/rules/results，且严重告警 → "error"。"""
        content = (
            "9.9.9.9 - - [15/Mar/2024:10:01:00 +0800] "
            "\"POST /upload/shell.jsp?cmd=whoami HTTP/1.1\" 200 10 \"-\" \"Behinder\"\n"
        )
        result = parse_web_access(content, "access.log")
        summary = run_detection(result.events)

        with tempfile.TemporaryDirectory() as tmp:
            sarif_path = Path(tmp) / "report.sarif"
            generate_sarif_report([result], summary, str(sarif_path))
            data = _json.loads(sarif_path.read_text(encoding="utf-8"))

        self.assertEqual(data["version"], "2.1.0")
        self.assertGreaterEqual(len(data["runs"]), 1)
        run = data["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "BlueTeam Log Analyzer")
        self.assertGreaterEqual(len(run["results"]), 1)
        # 至少一个 result level 是 "error"（CRITICAL/HIGH 都映射到 error）
        self.assertTrue(any(r["level"] == "error" for r in run["results"]))

    def test_sarif_keeps_first_matching_source_file_for_cross_file_alert(self):
        event_a = LogEvent(
            id="e-a", timestamp="2024-03-15T10:00:00", level=ThreatLevel.HIGH,
            category="测试", source="fixture", source_file="first.log",
            message="first", raw_line="first",
        )
        event_b = LogEvent(
            id="e-b", timestamp="2024-03-15T10:01:00", level=ThreatLevel.HIGH,
            category="测试", source="fixture", source_file="second.log",
            message="second", raw_line="second",
        )
        alert = DetectionAlert(
            id="a-cross", rule_id="TEST-001", rule_name="跨文件告警",
            description="cross file", level=ThreatLevel.HIGH, category="测试",
            mitre_attack="T1190", mitre_phase="初始访问",
            affected_events=["e-a", "e-b"], evidence=[],
            recommendation="", timestamp="2024-03-15T10:01:00", confidence="high",
        )
        summary = AnalysisSummary(
            risk_score=0, risk_level=ThreatLevel.INFO, alerts=[alert],
            timeline=[], attack_chain=[], recommendations=[],
            total_events=2, files_analyzed=2,
        )
        result_a = ParseResult("first.log", "Fixture", [event_a], ParseStats(total=1))
        result_b = ParseResult("second.log", "Fixture", [event_b], ParseStats(total=1))

        with tempfile.TemporaryDirectory() as tmp:
            sarif_path = Path(tmp) / "report.sarif"
            generate_sarif_report([result_a, result_b], summary, str(sarif_path))
            data = _json.loads(sarif_path.read_text(encoding="utf-8"))

        uri = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "first.log")

    def test_ioc_drops_boring_paths_but_keeps_attack_paths(self):
        """IOC 路径列表只保留有意义的路径，过滤 / 和 /index.html 这类噪音。"""
        content = (
            "9.9.9.9 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET /download.php?file=../../etc/passwd HTTP/1.1\" 200 10 \"-\" \"curl/8\"\n"
        )
        result = parse_web_access(content, "access.log")
        summary = run_detection(result.events)
        iocs = extract_iocs(result.events, alerts=summary.alerts)
        self.assertTrue(any("etc/passwd" in p for p in iocs["file_paths"]),
                        "命中 LFI 的关键路径必须保留")
        self.assertNotIn("/", iocs["file_paths"], "根路径不应进 IOC")
        self.assertNotIn("/index", iocs["file_paths"])

    def test_ioc_rejects_invalid_ip_and_static_asset_prefixes(self):
        event = LogEvent(
            id="ioc-invalid",
            timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.HIGH,
            category="测试",
            source="fixture",
            source_file="access.log",
            message="GET /static/app.js from 999.999.999.999",
            raw_line="999.999.999.999 /static/app.js",
            ip="999.999.999.999",
        )

        iocs = extract_iocs([event])

        self.assertNotIn("999.999.999.999", iocs["ips"])
        self.assertNotIn("/static/app.js", iocs["file_paths"])

    def test_ioc_filters_default_domain_blocklist(self):
        """example.com / localhost 不应进入 IOC 域名列表。"""
        content = (
            "9.9.9.9 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET /shell.php?cmd=whoami HTTP/1.1\" 200 10 "
            "\"http://localhost/test\" \"curl http://example.com\"\n"
        )
        result = parse_web_access(content, "access.log")
        summary = run_detection(result.events)
        iocs = extract_iocs(result.events, alerts=summary.alerts)
        self.assertNotIn("example.com", iocs["domains"])
        self.assertNotIn("localhost", iocs["domains"])

    def test_report_bundle_generates_standard_outputs(self):
        """--out 背后的 bundle 输出应生成完整交付目录。"""
        content = (
            "9.9.9.9 - - [15/Mar/2024:10:01:00 +0800] "
            "\"POST /upload/shell.jsp?cmd=whoami HTTP/1.1\" 200 10 \"-\" \"Behinder\"\n"
        )
        result = parse_web_access(content, "access.log")
        summary = run_detection(result.events)
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "report"
            paths = generate_report_bundle([result], summary, str(out_dir))
            for key in ("html", "json", "csv", "ioc", "sarif", "manifest"):
                self.assertTrue(Path(paths[key]).exists(), key)
            manifest = _json.loads(Path(paths["manifest"]).read_text(encoding="utf-8"))
            self.assertEqual(Path(paths["html"]).name, "index.html")
            self.assertEqual(manifest["schema"], "bla-report-manifest-v1")
            self.assertEqual(len(manifest["outputs"]), 5)
            self.assertEqual(manifest["summary"]["alert_count"], len(summary.alerts))

    def test_json_report_contains_incident_case_view(self):
        """JSON 报告必须包含 incident，便于 explain/API/二次处理。"""
        base = Path(__file__).parent / "fixtures" / "p0"
        result = auto_parse(str(base / "hvv_chain.jsonl"))
        summary = run_detection(result.events, profile="cn-hvv")

        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            generate_json_report([result], summary, str(report_path))
            data = _json.loads(report_path.read_text(encoding="utf-8"))

        self.assertIn("incidents", data)
        self.assertEqual(len(data["incidents"]), len(summary.incidents))
        self.assertIn("next_logs", data["incidents"][0])
        self.assertEqual(data["summary"]["risk_score"], summary.risk_score)
        self.assertEqual(data["summary"]["incident_count"], len(summary.incidents))
        self.assertEqual(data["summary"]["alert_count"], len(summary.alerts))
        self.assertIn("by_level", data["summary"])

    def test_json_report_strips_controls_redacts_secrets_and_marks_timeline_truncation(self):
        marker = "\x1b]52;c;SGFja2Vk\x07\x1b[31m"
        event = LogEvent(
            id="evt-json",
            timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.HIGH,
            category="测试",
            source="fixture",
            source_file="events.log",
            message=f"{marker}password=hunter2",
            raw_line=f"Authorization: Bearer abcdefghijk{marker}",
            details={"cookie": "session_id=secret123456"},
        )
        result = ParseResult("events.log", "Fixture", [event], ParseStats(total=1, high=1))
        timeline = [
            TimelineEntry(
                timestamp=f"2024-03-15T10:{idx % 60:02d}:00",
                level=ThreatLevel.INFO,
                category="测试",
                message=f"item {idx}",
                event_id=f"e{idx}",
                source_file="events.log",
            )
            for idx in range(205)
        ]
        summary = AnalysisSummary(
            risk_score=0,
            risk_level=ThreatLevel.INFO,
            alerts=[],
            timeline=timeline,
            attack_chain=[],
            recommendations=[],
            total_events=1,
            files_analyzed=1,
        )

        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            generate_json_report([result], summary, str(report_path))
            data = _json.loads(report_path.read_text(encoding="utf-8"))

        text = _json.dumps(data, ensure_ascii=False)
        self.assertNotIn("\x1b]52", text)
        self.assertNotIn("\x1b[31m", text)
        self.assertNotIn("hunter2", text)
        self.assertNotIn("abcdefghijk", text)
        self.assertEqual(data["events"][0]["message"], "password=<redacted>")
        self.assertEqual(len(data["timeline"]), 200)
        self.assertTrue(data["truncation"]["timeline"]["truncated"])

    def test_html_report_renders_incident_killchain_chips(self):
        """HTML 报告 incident 卡片必须画出 mini kill chain，命中阶段 chip 高亮。"""
        from bla.detection.correlation import correlate_incidents
        from bla.models import LogEvent as _LE
        from bla.models import ParseResult, ParseStats

        events = [
            _LE(
                id="e1", timestamp="2026-05-08T10:00:00",
                level=ThreatLevel.CRITICAL, category="测试", source="t",
                source_file="t.log", message="m", raw_line="",
                ip="9.9.9.9", user="alice", host="h1",
                details={
                    "src_ip": "9.9.9.9", "account": "alice", "asset": "h1",
                    "event_family": "initial-access", "source_type": "waf",
                },
            )
        ]
        incidents = correlate_incidents(events, [])
        summary = AnalysisSummary(
            risk_score=80, risk_level=ThreatLevel.HIGH, alerts=[],
            timeline=[], attack_chain=[], recommendations=[],
            total_events=1, files_analyzed=1, incidents=incidents,
        )
        result = ParseResult(file_name="t.log", log_type="test",
                             events=events, stats=ParseStats(total=1))

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.html"
            generate_html_report([result], summary, str(path))
            html = path.read_text(encoding="utf-8")
        self.assertIn("incident-killchain", html)
        self.assertIn("kc-chip", html)
        self.assertIn("kc-hit", html, "命中阶段必须以高亮 chip 渲染")
        self.assertIn("kc-miss", html, "未命中阶段也要渲染（灰色）")

    def test_explain_markdown_format_renders_ticket_ready_doc(self):
        """explain --format markdown 应当产出可直接粘贴进工单的 Markdown。"""
        from bla_cli import _render_alert_markdown, _render_incident_markdown

        incident = {
            "id": "inc-001",
            "title": "测试案件",
            "level": "critical",
            "confidence": "high",
            "description": "9.9.9.9 攻击 web1",
            "affected_event_count": 5,
            "affected_alerts": ["a1", "a2"],
            "source_types": ["waf", "edr"],
            "attack_phases": ["初始访问", "主机失陷"],
            "source_ips": ["9.9.9.9"],
            "accounts": ["alice"],
            "assets": ["web1"],
            "evidence": ["日志源: waf, edr", "命中规则: WEB-SQLI"],
            "recommended_actions": ["隔离主机", "重置密码"],
            "next_logs": ["EDR 进程树"],
            "timeline": [
                {"timestamp": "2026-05-08T10:00:00", "level": "critical",
                 "source_file": "waf.log", "message": "SQL 注入命中"},
            ],
        }
        md = _render_incident_markdown(incident)
        self.assertIn("## 案件 inc-001：测试案件", md)
        self.assertIn("**级别**：critical", md)
        self.assertIn("**攻击阶段**：初始访问 → 主机失陷", md)
        self.assertIn("- [ ] 隔离主机", md)
        self.assertIn("| 时间 | 级别 | 来源 | 描述 |", md)
        self.assertIn("SQL 注入命中", md)

        alert_md = _render_alert_markdown({
            "id": "a1", "rule_id": "WEB-SQLI", "rule_name": "SQL注入",
            "level": "critical", "confidence": "high",
            "mitre_attack": "T1190", "mitre_phase": "初始访问",
            "affected_event_count": 1, "timestamp": "2026-05-08T10:00:00",
            "description": "...", "evidence": ["payload=union select"],
            "recommendation": "部署 WAF",
        })
        self.assertIn("## 告警 a1：SQL注入", alert_md)
        self.assertIn("**MITRE**：T1190 / 初始访问", alert_md)
        self.assertIn("- payload=union select", alert_md)
        self.assertIn("部署 WAF", alert_md)

    def test_explain_markdown_escapes_attacker_controlled_report_fields(self):
        from bla_cli import _render_alert_markdown

        marker = "\x1b]52;c;SGFja2Vk\x07\x1b[31m"
        md = _render_alert_markdown({
            "id": "a|1",
            "rule_id": "WEB|XSS",
            "rule_name": f"<script>alert(1)</script>{marker}",
            "level": "high",
            "confidence": "high",
            "mitre_attack": "T1190",
            "mitre_phase": "初始访问",
            "affected_event_count": 1,
            "timestamp": "2026-05-08T10:00:00",
            "description": "token=supersecret",
            "evidence": ["payload|<img src=x onerror=1>"],
            "recommendation": "Cookie: abcdef123456",
        })

        self.assertNotIn("\x1b]52", md)
        self.assertNotIn("<script>", md)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", md)
        self.assertIn("a\\|1", md)
        self.assertIn("payload\\|&lt;img src=x onerror=1&gt;", md)
        self.assertIn("token=&lt;redacted&gt;", md)
        self.assertIn("Cookie=&lt;redacted&gt;", md)
