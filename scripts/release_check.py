#!/usr/bin/env python3
"""Local release quality checks for BLA.

The script keeps the human release checklist executable: it verifies version
surfaces, runs the normal regression suite, exercises release-critical CLI
commands, and optionally inspects built distributions.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
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
        _assert("bla/remote/ssh_workspace.py" in names, "wheel is missing bla/remote/ssh_workspace.py")
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
            "/bla_cli.py",
            "/scripts/release_check.py",
            "/sample_logs/auth.log",
            "/sample_logs/windows_rdp_sample.xml",
            "/tests/fixtures/p0/hvv_chain.jsonl",
        ]
        for suffix in suffixes:
            _assert(any(name.endswith(suffix) for name in names), f"sdist is missing {suffix}")


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

    if args.build:
        _check_distribution(version)

    print("release-check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
