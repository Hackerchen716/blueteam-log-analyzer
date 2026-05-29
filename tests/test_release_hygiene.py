from _support import *


class ReleaseHygieneRegressionTests(unittest.TestCase):
    def test_builtin_rule_metadata_validates_cleanly(self):
        """内置 YAML 规则必须具备可维护的元数据标准。"""
        result = validate_web_attack_rules([])

        self.assertGreaterEqual(result["raw_rules"], 3)
        self.assertEqual(result["errors"], 0)
        self.assertEqual(result["warnings"], 0)

    def test_custom_rule_validation_warns_on_redos_prone_regex(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules_path = Path(tmp) / "rules.yaml"
            rules_path.write_text(
                """
web_attacks:
  - id: WEB-REDOS-001
    name: ReDoS candidate
    severity: medium
    confidence: medium
    category: Web攻击
    mitre: T1190
    tags: [web-attack]
    source_types: [web]
    evidence_fields: [url]
    false_positive_hints: [test]
    remediation: tighten regex
    patterns:
      - '(a+)+$'
""",
                encoding="utf-8",
            )

            result = validate_web_attack_rules([tmp])

        self.assertEqual(result["errors"], 0)
        self.assertGreaterEqual(result["warnings"], 1)
        self.assertTrue(any("灾难性回溯" in item["message"] for item in result["issues"]))

    def test_version_surfaces_are_consistent(self):
        repo = Path(__file__).parents[1]
        completed = subprocess.run(
            [sys.executable, "bla_cli.py", "--version"],
            cwd=repo,
            text=True,
            encoding="utf-8",
            errors="replace",
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
            manifest_path = Path(tmp) / "manifest.json"
            generate_json_report([], summary, str(json_path))
            generate_sarif_report([], summary, str(sarif_path))
            generate_manifest([], summary, str(manifest_path))
            report = _json.loads(json_path.read_text(encoding="utf-8"))
            sarif = _json.loads(sarif_path.read_text(encoding="utf-8"))
            manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(report["meta"]["version"], __version__)
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["version"], __version__)
        self.assertEqual(manifest["meta"]["version"], __version__)

    def test_benchmark_memory_profiling_is_explicit(self):
        repo = Path(__file__).parents[1]
        completed = subprocess.run(
            [sys.executable, "bla_cli.py", "benchmark", "--help"],
            cwd=repo,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=True,
        )

        self.assertIn("--memory", completed.stdout)
        self.assertIn("tracemalloc", completed.stdout)

    def test_remote_log_help_exposes_collector_boundaries(self):
        repo = Path(__file__).parents[1]
        completed = subprocess.run(
            [sys.executable, "bla_cli.py", "remote-log", "--help"],
            cwd=repo,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=True,
        )

        self.assertIn("--tail", completed.stdout)
        self.assertIn("--grep", completed.stdout)
        self.assertIn("--audit-json", completed.stdout)
        self.assertIn("--geoip-cache", completed.stdout)
        self.assertIn("--json-events-limit", completed.stdout)

    def test_cli_accepts_low_exit_threshold(self):
        repo = Path(__file__).parents[1]
        completed = subprocess.run(
            [
                sys.executable,
                "bla_cli.py",
                "sample_logs/access.log",
                "--exit-on",
                "low",
                "--no-color",
                "--max-alerts",
                "0",
            ],
            cwd=repo,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )

        self.assertNotEqual(completed.returncode, 2, completed.stderr)

    def test_cli_report_write_failure_redacts_terminal_output(self):
        repo = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            bad_output = Path(tmp) / "\x1b]52;c;SGVsbG8=\x07token=super-secret"
            bad_output.mkdir()
            completed = subprocess.run(
                [
                    sys.executable,
                    "bla_cli.py",
                    "sample_logs/access.log",
                    "--json",
                    str(bad_output),
                    "--exit-on",
                    "none",
                    "--no-color",
                    "--max-alerts",
                    "0",
                ],
                cwd=repo,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )

        terminal_text = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 1)
        self.assertNotIn("\x1b", terminal_text)
        self.assertNotIn("SGVsbG8", terminal_text)
        self.assertNotIn("super-secret", terminal_text)
        self.assertIn("token=<redacted>", terminal_text)
        self.assertIn("报告写入失败", terminal_text)

    def test_validate_rules_output_redacts_untrusted_rule_metadata(self):
        repo = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = Path(tmp) / "\x1b]52;c;SGVsbG8=\x07token=super-secret"
            rules_dir.mkdir()
            (rules_dir / "rules.yaml").write_text(
                """
web_attacks:
  - id: WEB-BAD
    name: Bad rule
    severity: medium
    confidence: medium
    category: Web攻击
    mitre: T1190
    tags: [web-attack]
    patterns:
      - '(a+)+$'
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "bla_cli.py",
                    "validate-rules",
                    "--rules",
                    str(rules_dir),
                    "--strict-metadata",
                ],
                cwd=repo,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )

        terminal_text = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 1)
        self.assertNotIn("\x1b", terminal_text)
        self.assertNotIn("SGVsbG8", terminal_text)
        self.assertNotIn("super-secret", terminal_text)
        self.assertIn("token=<redacted>", terminal_text)
        self.assertIn("规则校验结果", terminal_text)

    def test_explain_failure_paths_redact_terminal_output(self):
        repo = Path(__file__).parents[1]
        bad_id = "\x1b]52;c;SGVsbG8=\x07 token=super-secret"
        with tempfile.TemporaryDirectory() as tmp:
            bad_report = Path(tmp) / "\x1b]52;c;SGVsbG8=\x07-token=super-secret.json"
            missing = subprocess.run(
                [
                    sys.executable,
                    "bla_cli.py",
                    "explain",
                    bad_id,
                    "--report",
                    str(bad_report),
                ],
                cwd=repo,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )

            empty_report = Path(tmp) / "report.json"
            empty_report.write_text('{"alerts":[],"incidents":[]}', encoding="utf-8")
            not_found = subprocess.run(
                [
                    sys.executable,
                    "bla_cli.py",
                    "explain",
                    bad_id,
                    "--report",
                    str(empty_report),
                ],
                cwd=repo,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )

        self.assertEqual(missing.returncode, 2)
        self.assertEqual(not_found.returncode, 1)
        for terminal_text in (
            missing.stdout + missing.stderr,
            not_found.stdout + not_found.stderr,
        ):
            self.assertNotIn("\x1b", terminal_text)
            self.assertNotIn("SGVsbG8", terminal_text)
            self.assertNotIn("super-secret", terminal_text)
            self.assertIn("token=<redacted>", terminal_text)
        self.assertIn("无法读取报告", missing.stderr)
        self.assertIn("报告中未找到 ID", not_found.stderr)

    def test_argparse_errors_redact_terminal_output(self):
        repo = Path(__file__).parents[1]
        bad_value = "\x1b]52;c;SGVsbG8=\x07-token=super-secret"
        cases = [
            [
                sys.executable,
                "bla_cli.py",
                "sample_logs/access.log",
                "--exit-on",
                bad_value,
            ],
            [
                sys.executable,
                "bla_cli.py",
                "remote-log",
                "web01",
                "/var/log/auth.log",
                "--profile",
                bad_value,
            ],
        ]

        for argv in cases:
            completed = subprocess.run(
                argv,
                cwd=repo,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
            terminal_text = completed.stdout + completed.stderr
            self.assertEqual(completed.returncode, 2)
            self.assertNotIn("\x1b", terminal_text)
            self.assertNotIn("SGVsbG8", terminal_text)
            self.assertNotIn("super-secret", terminal_text)
            self.assertIn("token=<redacted>", terminal_text)
            self.assertIn("invalid choice", terminal_text)

    def test_fatal_traceback_redacts_terminal_output(self):
        import runpy
        import bla.cli.main as cli_main

        repo = Path(__file__).parents[1]
        bad_value = "\x1b]52;c;SGVsbG8=\x07-token=super-secret"
        original_main = cli_main.main
        stderr = io.StringIO()

        def boom():
            raise RuntimeError(f"/tmp/{bad_value}")

        try:
            cli_main.main = boom
            with mock.patch("sys.stderr", stderr):
                with self.assertRaises(SystemExit) as raised:
                    runpy.run_path(str(repo / "bla_cli.py"), run_name="__main__")
        finally:
            cli_main.main = original_main

        terminal_text = stderr.getvalue()
        self.assertEqual(raised.exception.code, 1)
        self.assertNotIn("\x1b", terminal_text)
        self.assertNotIn("SGVsbG8", terminal_text)
        self.assertNotIn("super-secret", terminal_text)
        self.assertIn("token=<redacted>", terminal_text)
        self.assertIn("Traceback", terminal_text)

    def test_release_check_script_and_setup_version_are_safe(self):
        repo = Path(__file__).parents[1]
        setup_text = (repo / "setup.py").read_text(encoding="utf-8")
        pyproject_text = (repo / "pyproject.toml").read_text(encoding="utf-8")
        cli_text = (repo / "bla_cli.py").read_text(encoding="utf-8")
        release_check_text = (repo / "scripts" / "release_check.py").read_text(encoding="utf-8")

        self.assertNotIn("exec(", setup_text)
        self.assertIn('bla = "bla.cli.main:main"', pyproject_text)
        self.assertNotIn("8.8.8.", cli_text)
        self.assertIn("world-countries.geojson", release_check_text)
        self.assertIn("shell_history.py", release_check_text)
        self.assertIn("_run_v141_feature_smoke", release_check_text)
        self.assertIn("_run_v142_hardening_smoke", release_check_text)
        self.assertIn("攻击源地理分布", release_check_text)
        self.assertIn("Shell 凭据访问轨迹", release_check_text)
        self.assertIn("access_token=<redacted>", release_check_text)
        self.assertIn("缺少地理数据", release_check_text)
        self.assertIn("未知实体", release_check_text)

        completed = subprocess.run(
            [sys.executable, "scripts/release_check.py", "--help"],
            cwd=repo,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=True,
        )
        self.assertIn("--build", completed.stdout)
