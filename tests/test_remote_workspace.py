from _support import *
import shlex

class RemoteWorkspaceRegressionTests(unittest.TestCase):
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

            def fetch_file(self, remote_path, local_path, cwd, **kwargs):
                self.fetches.append((remote_path, cwd, kwargs))
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
            self.assertTrue((Path(tmp) / "case" / "manifest.json").exists())
            data = _json.loads(report.read_text(encoding="utf-8"))

        self.assertEqual(fake.fetches[0][0:2], ("access.log", "/var/log/nginx"))
        self.assertIn("max_bytes", fake.fetches[0][2])
        self.assertGreaterEqual(len(data["alerts"]), 1)
        self.assertEqual(data["files"][0]["name"], "web01:/var/log/nginx/access.log")
        self.assertEqual(data["events"][0]["source_file"], "web01:/var/log/nginx/access.log")
        self.assertNotIn("python", " ".join(fake.commands).lower())
        self.assertIn("开始本地分析", output.getvalue())

    def test_remote_workspace_bla_exit_on_high_matches_cli_behavior(self):
        class FakeSSH:
            target = "web01"

            def fetch_file(self, remote_path, local_path, cwd, **kwargs):
                Path(local_path).write_text(
                    "9.9.9.9 - - [15/Mar/2024:10:01:00 +0800] "
                    "\"GET /download.php?file=../../etc/passwd HTTP/1.1\" 200 10 \"-\" \"curl/8\"\n",
                    encoding="utf-8",
                )

        fake = FakeSSH()
        with tempfile.TemporaryDirectory() as tmp, mock.patch("sys.stdout", io.StringIO()):
            workspace = RemoteWorkspace(fake, initial_cwd="/var/log/nginx", print_fn=lambda *a, **k: print(*a, **k))
            code = workspace.execute_line(f"bla access.log --out {tmp}/case --exit-on high --no-color")

        self.assertEqual(code, 1)

    def test_remote_workspace_bla_accepts_low_exit_and_json_limits(self):
        class FakeSSH:
            target = "web01"

            def fetch_file(self, remote_path, local_path, cwd, **kwargs):
                Path(local_path).write_text(
                    "9.9.9.9 - - [15/Mar/2024:10:01:00 +0800] "
                    "\"GET /download.php?file=../../etc/passwd HTTP/1.1\" 200 10 \"-\" \"curl/8\"\n"
                    "9.9.9.9 - - [15/Mar/2024:10:01:01 +0800] "
                    "\"GET /.env HTTP/1.1\" 404 10 \"-\" \"curl/8\"\n",
                    encoding="utf-8",
                )

        fake = FakeSSH()
        with tempfile.TemporaryDirectory() as tmp, mock.patch("sys.stdout", io.StringIO()):
            workspace = RemoteWorkspace(fake, initial_cwd="/var/log/nginx", print_fn=lambda *a, **k: print(*a, **k))
            code = workspace.execute_line(
                f"bla access.log --json {tmp}/report.json --exit-on low "
                "--json-events-limit 1 --raw-line-limit 12 --no-color"
            )
            data = _json.loads((Path(tmp) / "report.json").read_text(encoding="utf-8"))

        self.assertEqual(code, 1)
        self.assertEqual(len(data["events"]), 1)
        self.assertEqual(data["truncation"]["events"]["returned"], 1)
        self.assertTrue(data["events"][0]["raw_line_truncated"])
        self.assertGreater(data["events"][0]["raw_line_length"], 12)
        self.assertLessEqual(len(data["events"][0]["raw_line"]), 12)

    def test_remote_workspace_report_write_error_redacts_terminal_output(self):
        class FakeSSH:
            target = "web01"

            def fetch_file(self, remote_path, local_path, cwd, **kwargs):
                Path(local_path).write_text(
                    "9.9.9.9 - - [15/Mar/2024:10:01:00 +0800] "
                    "\"GET /download.php?file=../../etc/passwd HTTP/1.1\" 200 10 \"-\" \"curl/8\"\n",
                    encoding="utf-8",
                )

        fake = FakeSSH()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            bad_output = Path(tmp) / BAD_FILESYSTEM_SEGMENT
            bad_output.mkdir()
            workspace = RemoteWorkspace(fake, initial_cwd="/var/log/nginx", print_fn=lambda *a, **k: print(*a, **k))
            code = workspace.execute_line(
                "bla access.log --json "
                f"{shlex.quote(str(bad_output))} --exit-on none --no-color --max-alerts 0"
            )

        terminal_text = stdout.getvalue() + stderr.getvalue()
        self.assertEqual(code, 1)
        self.assertNotIn("\x1b", terminal_text)
        self.assertNotIn("SGVsbG8", terminal_text)
        self.assertNotIn("super-secret", terminal_text)
        self.assertIn("token=<redacted>", terminal_text)
        self.assertIn("报告写入失败", terminal_text)

    def test_remote_workspace_argparse_error_redacts_terminal_output(self):
        class FakeSSH:
            target = "web01"

        bad_value = "\x1b]52;c;SGVsbG8=\x07-token=super-secret"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            workspace = RemoteWorkspace(FakeSSH(), initial_cwd="/var/log", print_fn=lambda *a, **k: print(*a, **k))
            code = workspace.execute_line(
                "bla auth.log --exit-on "
                f"{shlex.quote(bad_value)}"
            )

        terminal_text = stdout.getvalue() + stderr.getvalue()
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", terminal_text)
        self.assertNotIn("SGVsbG8", terminal_text)
        self.assertNotIn("super-secret", terminal_text)
        self.assertIn("token=<redacted>", terminal_text)
        self.assertIn("invalid choice", terminal_text)

    def test_remote_workspace_ls_argument_error_redacts_terminal_output(self):
        class FakeSSH:
            target = "web01"

        bad_value = "--\x1b]52;c;SGVsbG8=\x07-token=super-secret"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            workspace = RemoteWorkspace(FakeSSH(), initial_cwd="/var/log", print_fn=lambda *a, **k: print(*a, **k))
            code = workspace.execute_line(f"ls {shlex.quote(bad_value)}")

        terminal_text = stdout.getvalue() + stderr.getvalue()
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", terminal_text)
        self.assertNotIn("SGVsbG8", terminal_text)
        self.assertNotIn("super-secret", terminal_text)
        self.assertIn("token=<redacted>", terminal_text)
        self.assertIn("不支持的 ls 参数", terminal_text)

    def test_remote_workspace_pwd_redacts_terminal_output(self):
        class FakeSSH:
            target = "web01"

        bad_cwd = "/var/log/\x1b]52;c;SGVsbG8=\x07-token=super-secret"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            workspace = RemoteWorkspace(FakeSSH(), initial_cwd=bad_cwd, print_fn=lambda *a, **k: print(*a, **k))
            code = workspace.execute_line("pwd")

        terminal_text = stdout.getvalue() + stderr.getvalue()
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", terminal_text)
        self.assertNotIn("SGVsbG8", terminal_text)
        self.assertNotIn("super-secret", terminal_text)
        self.assertIn("token=<redacted>", terminal_text)
        self.assertIn("/var/log/", terminal_text)

    def test_remote_workspace_bla_accepts_rdp_filter(self):
        class FakeSSH:
            target = "win01"

            def fetch_file(self, remote_path, local_path, cwd, **kwargs):
                Path(local_path).write_text(
                    "<Events>"
                    "<Event><System><EventID>4624</EventID>"
                    "<TimeCreated SystemTime=\"2024-03-15T01:01:00.000Z\"/>"
                    "<Computer>win01</Computer><Channel>Security</Channel></System>"
                    "<EventData><Data Name=\"TargetUserName\">local</Data>"
                    "<Data Name=\"LogonType\">10</Data></EventData></Event>"
                    "<Event><System><EventID>4624</EventID>"
                    "<TimeCreated SystemTime=\"2024-03-15T01:02:00.000Z\"/>"
                    "<Computer>win01</Computer><Channel>Security</Channel></System>"
                    "<EventData><Data Name=\"TargetUserName\">rdpuser</Data>"
                    "<Data Name=\"IpAddress\">203.0.113.5</Data>"
                    "<Data Name=\"LogonType\">10</Data></EventData></Event>"
                    "</Events>",
                    encoding="utf-8",
                )

        fake = FakeSSH()
        with tempfile.TemporaryDirectory() as tmp, mock.patch("sys.stdout", io.StringIO()):
            workspace = RemoteWorkspace(fake, initial_cwd="/var/log", print_fn=lambda *a, **k: print(*a, **k))
            code = workspace.execute_line(f"bla Security.xml --rdp --json {tmp}/report.json --exit-on none --no-color")
            data = _json.loads((Path(tmp) / "report.json").read_text(encoding="utf-8"))

        self.assertEqual(code, 0)
        self.assertEqual(len(data["events"]), 1)
        self.assertEqual(data["events"][0]["details"]["source_ip"], "203.0.113.5")
        self.assertEqual(data["events"][0]["source_file"], "win01:/var/log/Security.xml")

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

            def capture_command(self, command, local_path, cwd, **kwargs):
                self.captures.append((command, cwd, kwargs))
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
        self.assertEqual(fake.captures[0][0:2], ("journalctl -u ssh -n 5000 --no-pager -o short", "/var/log"))
        self.assertIn("max_bytes", fake.captures[0][2])
        self.assertEqual(data["files"][0]["name"], "web01:journalctl:ssh")
        self.assertEqual(data["events"][0]["source_file"], "web01:journalctl:ssh")
        self.assertEqual(data["events"][0]["category"], "SSH")

    def test_remote_workspace_can_tail_grep_and_write_collection_audit(self):
        class FakeSSH:
            target = "web01"

            def __init__(self):
                self.captures = []

            def capture_command(self, command, local_path, cwd, **kwargs):
                self.captures.append((command, cwd, kwargs))
                Path(local_path).write_text(
                    "Mar 15 10:01:00 web01 sshd[123]: "
                    "Failed password for root from 9.9.9.9 port 22 ssh2\n",
                    encoding="utf-8",
                )

        fake = FakeSSH()
        with tempfile.TemporaryDirectory() as tmp, mock.patch("sys.stdout", io.StringIO()):
            workspace = RemoteWorkspace(fake, initial_cwd="/var/log", print_fn=lambda *a, **k: print(*a, **k))
            code = workspace.execute_line(
                f"bla auth.log --tail 200 --grep Failed --out {tmp}/case "
                f"--audit-json {tmp}/audit.json --exit-on none --no-color"
            )
            report = _json.loads((Path(tmp) / "case" / "report.json").read_text(encoding="utf-8"))
            manifest = _json.loads((Path(tmp) / "case" / "manifest.json").read_text(encoding="utf-8"))
            audit = _json.loads((Path(tmp) / "audit.json").read_text(encoding="utf-8"))

        self.assertEqual(code, 0)
        self.assertIn("tail -n 200 -- auth.log", fake.captures[0][0])
        self.assertIn("grep -F -e Failed", fake.captures[0][0])
        self.assertEqual(fake.captures[0][1], "/var/log")
        self.assertEqual(report["files"][0]["name"], "web01:/var/log/auth.log")
        self.assertEqual(manifest["remote_collection"][0]["method"], "file-tail-grep")
        self.assertEqual(manifest["remote_collection"][0]["tail_lines"], 200)
        self.assertEqual(manifest["remote_collection"][0]["grep_patterns"], ["Failed"])
        self.assertEqual(audit["schema"], "bla-remote-collection-audit-v1")
        self.assertEqual(audit["collection"][0]["remote_label"], "web01:/var/log/auth.log")

    def test_remote_workspace_audit_json_sanitizes_local_name(self):
        class FakeSSH:
            target = "web01"

            def capture_command(self, command, local_path, cwd, **kwargs):
                Path(local_path).write_text(
                    "Mar 15 10:01:00 web01 sshd[123]: "
                    "Failed password for root from 9.9.9.9 port 22 ssh2\n",
                    encoding="utf-8",
                )

        remote_path = f"/var/log/{BAD_FILESYSTEM_SEGMENT}.log"
        grep_value = "token=super-secret"
        fake = FakeSSH()
        with tempfile.TemporaryDirectory() as tmp, mock.patch("sys.stdout", io.StringIO()):
            workspace = RemoteWorkspace(fake, initial_cwd="/var/log", print_fn=lambda *a, **k: print(*a, **k))
            code = workspace.execute_line(
                "bla "
                f"{shlex.quote(remote_path)} --tail 10 --grep {shlex.quote(grep_value)} "
                f"--out {tmp}/case --audit-json {tmp}/audit.json --exit-on none --no-color --max-alerts 0"
            )
            audit = _json.loads((Path(tmp) / "audit.json").read_text(encoding="utf-8"))
            manifest = _json.loads((Path(tmp) / "case" / "manifest.json").read_text(encoding="utf-8"))

        audit_text = _json.dumps(audit, ensure_ascii=False)
        manifest_text = _json.dumps(manifest, ensure_ascii=False)
        self.assertEqual(code, 0)
        for text in (audit_text, manifest_text):
            self.assertNotIn("\x1b", text)
            self.assertNotIn("SGVsbG8", text)
            self.assertNotIn("super-secret", text)
            self.assertIn("token=<redacted>", text)
        self.assertEqual(audit["collection"][0]["local_name"], "token=<redacted>")
        self.assertEqual(audit["collection"][0]["grep_patterns"], ["token=<redacted>"])
        self.assertEqual(manifest["remote_collection"][0]["local_name"], "token=<redacted>")

    def test_ssh_client_rejects_target_option_injection_and_inserts_separator(self):
        with self.assertRaises(ValueError):
            SSHClient("-oProxyCommand=sh")

        client = SSHClient("user@example.test", port=2222, identity_file="/tmp/key")
        args = client._base_args()

        self.assertIn("--", args)
        self.assertEqual(args[-2:], ["--", "user@example.test"])

    def test_ssh_client_fetch_file_caps_actual_stream_after_size_check(self):
        client = SSHClient("user@example.test")
        calls = []

        def fake_run(args, **kwargs):
            calls.append(args)
            if len(calls) == 1:
                return subprocess.CompletedProcess(args, 0, stdout=b"3\n", stderr=b"")
            kwargs["stdout"].write(b"abcdef")
            return subprocess.CompletedProcess(args, 0, stderr=b"")

        with tempfile.TemporaryDirectory() as tmp, mock.patch("subprocess.run", side_effect=fake_run):
            local_path = Path(tmp) / "auth.log"
            with self.assertRaisesRegex(RuntimeError, "超过上限"):
                client.fetch_file("auth.log", str(local_path), "/var/log", max_bytes=5)

            self.assertFalse(local_path.exists())

        self.assertIn("head -c 6", calls[1][-1])

    def test_remote_workspace_strips_remote_terminal_sequences(self):
        marker = "\x1b]52;c;SGFja2Vk\x07\x1b[31m"

        class FakeSSH:
            target = f"web01{marker}"

            def run(self, command, timeout=60):
                return type("Result", (), {
                    "returncode": 0,
                    "stdout": f"auth.log{marker}\n".encode(),
                    "stderr": b"",
                    "text": f"auth.log{marker}\n",
                    "error_text": "",
                })()

        output = io.StringIO()
        workspace = RemoteWorkspace(FakeSSH(), initial_cwd="/", print_fn=lambda *a, **k: print(*a, **k))
        with mock.patch("sys.stdout", output):
            self.assertEqual(workspace.execute_line("ls"), 0)

        text = output.getvalue()
        self.assertNotIn("\x1b]52", text)
        self.assertNotIn("\x1b[31m", text)
        self.assertNotIn("\x07", text)
