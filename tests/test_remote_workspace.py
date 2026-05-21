from _support import *

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
