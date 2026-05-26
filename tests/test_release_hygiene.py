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

    def test_release_check_script_and_setup_version_are_safe(self):
        repo = Path(__file__).parents[1]
        setup_text = (repo / "setup.py").read_text(encoding="utf-8")
        cli_text = (repo / "bla_cli.py").read_text(encoding="utf-8")
        release_check_text = (repo / "scripts" / "release_check.py").read_text(encoding="utf-8")

        self.assertNotIn("exec(", setup_text)
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
