"""Interactive SSH workspace.

The remote side only needs a normal shell and common read-only utilities. BLA
keeps parsing, detection, correlation, and report generation on the local host.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, List, Optional, Sequence

from ..core import AnalysisError, AnalysisOptions, AnalysisOutputs, run_analysis, write_reports
from ..models import ThreatLevel
from ..output import print_terminal_report
from ..parsers import list_parser_names
from ..utils.helpers import strip_terminal_control

PrintFn = Callable[..., None]

_EXIT_THRESHOLDS = {
    "critical": ThreatLevel.CRITICAL.score,
    "high": ThreatLevel.HIGH.score,
    "medium": ThreatLevel.MEDIUM.score,
}
DEFAULT_REMOTE_MAX_BYTES = 256 * 1024 * 1024
DEFAULT_REMOTE_COMMAND_TIMEOUT = 120


@dataclass
class RemoteCommandResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""

    @property
    def text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")

    @property
    def error_text(self) -> str:
        return self.stderr.decode("utf-8", errors="replace")


class SSHClient:
    """Small OpenSSH wrapper with no Python dependency on the target host."""

    def __init__(
        self,
        target: str,
        port: Optional[int] = None,
        identity_file: Optional[str] = None,
        connect_timeout: int = 10,
    ) -> None:
        if not _is_safe_ssh_target(target):
            raise ValueError("SSH 目标不能以 '-' 开头；请使用 user@host、IP 或 ~/.ssh/config 主机别名")
        self.target = target
        self.port = port
        self.identity_file = identity_file
        self.connect_timeout = connect_timeout

    def run(self, command: str, timeout: Optional[int] = 60) -> RemoteCommandResult:
        args = self._base_args()
        args.append(command)
        completed = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return RemoteCommandResult(completed.returncode, completed.stdout, completed.stderr)

    def fetch_file(
        self,
        remote_path: str,
        local_path: str,
        cwd: str,
        max_bytes: int = DEFAULT_REMOTE_MAX_BYTES,
        timeout: Optional[int] = DEFAULT_REMOTE_COMMAND_TIMEOUT,
    ) -> None:
        size_cmd = _remote_cd_command(cwd, f"test -f {_qp(remote_path)} && wc -c < {_qp(remote_path)}")
        size_result = self.run(size_cmd, timeout=timeout)
        if size_result.returncode != 0:
            err = size_result.error_text.strip()
            raise RuntimeError(err or f"无法读取远程文件: {remote_path}")
        try:
            size = int(size_result.text.strip().splitlines()[-1])
        except (ValueError, IndexError):
            size = 0
        if max_bytes > 0 and size > max_bytes:
            raise RuntimeError(f"远程文件过大: {size} bytes，超过上限 {max_bytes} bytes")

        read_cmd = f"test -f {_qp(remote_path)} && cat -- {_qp(remote_path)}"
        if max_bytes > 0:
            read_cmd = f"({read_cmd}) | head -c {max_bytes + 1}"
        remote_cmd = _remote_cd_command(cwd, read_cmd)
        args = self._base_args()
        args.append(remote_cmd)
        with open(local_path, "wb") as out:
            completed = subprocess.run(
                args,
                stdout=out,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        if completed.returncode != 0:
            err = completed.stderr.decode("utf-8", errors="replace").strip()
            try:
                os.unlink(local_path)
            except OSError:
                pass
            raise RuntimeError(err or f"无法读取远程文件: {remote_path}")
        if max_bytes > 0 and os.path.getsize(local_path) > max_bytes:
            try:
                os.unlink(local_path)
            except OSError:
                pass
            raise RuntimeError(f"远程文件过大: 超过上限 {max_bytes} bytes: {remote_path}")

    def capture_command(
        self,
        command: str,
        local_path: str,
        cwd: str,
        timeout: Optional[int] = DEFAULT_REMOTE_COMMAND_TIMEOUT,
        max_bytes: int = DEFAULT_REMOTE_MAX_BYTES,
    ) -> None:
        capped_command = command
        if max_bytes > 0:
            capped_command = f"({command}) | head -c {max_bytes + 1}"
        remote_cmd = _remote_cd_command(cwd, capped_command)
        args = self._base_args()
        args.append(remote_cmd)
        with open(local_path, "wb") as out:
            completed = subprocess.run(
                args,
                stdout=out,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        if completed.returncode != 0:
            err = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(err or f"远程命令失败: {command}")
        if max_bytes > 0 and os.path.getsize(local_path) > max_bytes:
            try:
                os.unlink(local_path)
            except OSError:
                pass
            raise RuntimeError(f"远程命令输出超过上限 {max_bytes} bytes: {command}")

    def _base_args(self) -> List[str]:
        args = [
            "ssh",
            "-o",
            f"ConnectTimeout={self.connect_timeout}",
            "-o",
            "BatchMode=no",
        ]
        if self.port:
            args.extend(["-p", str(self.port)])
        if self.identity_file:
            args.extend(["-i", self.identity_file])
        args.append("--")
        args.append(self.target)
        return args


class RemoteWorkspace:
    """A tiny shell-like remote workspace for log-first incident response."""

    def __init__(
        self,
        client: SSHClient,
        initial_cwd: str = ".",
        print_fn: Optional[PrintFn] = None,
        max_fetch_bytes: int = DEFAULT_REMOTE_MAX_BYTES,
        command_timeout: int = DEFAULT_REMOTE_COMMAND_TIMEOUT,
    ) -> None:
        self.client = client
        self.cwd = initial_cwd or "."
        self.print = print_fn if print_fn is not None else print
        self.max_fetch_bytes = max_fetch_bytes
        self.command_timeout = command_timeout

    def start(self) -> None:
        self.resolve_cwd()
        self.print(f"已连接 {_display_text(self.client.target)}，远程目标无需安装 Python/pip/BLA。")
        self.print("输入 help 查看命令；在远程目录中直接执行 bla access.log 即可本地分析。")
        while True:
            try:
                line = input(f"bla@{_display_text(self.client.target)}:{_display_text(self.cwd)}$ ")
            except EOFError:
                self.print("")
                return
            except KeyboardInterrupt:
                self.print("")
                continue
            if self.execute_line(line) == 130:
                return

    def execute_line(self, line: str) -> int:
        line = line.strip()
        if not line:
            return 0
        try:
            parts = _split_workspace_line(line)
        except ValueError as e:
            self.print(f"解析命令失败: {e}", file=sys.stderr)
            return 2
        if not parts:
            return 0

        command, args = parts[0], parts[1:]
        if command in {"exit", "quit"}:
            return 130
        if command == "help":
            self._print_help()
            return 0
        if command == "pwd":
            self.print(self.cwd)
            return 0
        if command == "cd":
            return self._cmd_cd(args)
        if command == "ls":
            return self._cmd_ls(args)
        if command == "tail":
            return self._cmd_tail(args)
        if command == "find":
            return self._cmd_find(args)
        if command == "bla":
            return self._cmd_bla(args)
        if command == "collect":
            self.print("collect 暂未开放；请使用 bla FILE 或 bla journalctl:UNIT 拉回远程日志并在本机分析。")
            return 0

        self.print(f"不支持远程任意命令: {_display_text(command)}。可用命令: help, ls, cd, pwd, find, tail, bla, exit")
        return 2

    def resolve_cwd(self) -> str:
        self.cwd = self._resolve_remote_cwd(self.cwd)
        return self.cwd

    def run_bla(self, args: Sequence[str]) -> int:
        return self._cmd_bla(args)

    def _cmd_cd(self, args: Sequence[str]) -> int:
        target = args[0] if args else "."
        result = self.client.run(_remote_cd_command(self.cwd, f"cd {_qp(target)} && pwd -P"))
        if result.returncode != 0:
            self._print_remote_error(result)
            return result.returncode
        new_cwd = result.text.strip().splitlines()[-1] if result.text.strip() else ""
        if not new_cwd:
            self.print("远程目录解析失败", file=sys.stderr)
            return 1
        self.cwd = new_cwd
        return 0

    def _cmd_ls(self, args: Sequence[str]) -> int:
        flags = []
        paths = []
        for item in args:
            if item.startswith("-"):
                if item not in {"-l", "-a", "-h", "-la", "-al", "-lh", "-lah", "-alh"}:
                    self.print(f"不支持的 ls 参数: {item}", file=sys.stderr)
                    return 2
                flags.append(item)
            else:
                paths.append(item)
        flag_text = " ".join(flags) if flags else "-lah"
        target = paths[0] if paths else "."
        result = self.client.run(_remote_cd_command(self.cwd, f"ls {flag_text} -- {_qp(target)}"))
        return self._print_result(result)

    def _cmd_tail(self, args: Sequence[str]) -> int:
        if not args:
            self.print("用法: tail FILE [N]", file=sys.stderr)
            return 2
        path = args[0]
        count = 80
        if len(args) > 1:
            try:
                count = max(1, min(1000, int(args[1])))
            except ValueError:
                self.print("tail 行数必须是数字", file=sys.stderr)
                return 2
        result = self.client.run(_remote_cd_command(self.cwd, f"tail -n {count} -- {_qp(path)}"))
        return self._print_result(result)

    def _cmd_find(self, args: Sequence[str]) -> int:
        base = "."
        pattern = "*"
        if len(args) == 1:
            pattern = args[0]
        elif len(args) >= 2:
            base, pattern = args[0], args[1]
        result = self.client.run(
            _remote_cd_command(self.cwd, f"find {_qp(base)} -maxdepth 3 -type f -name {_q(pattern)} | sort | head -200")
        )
        return self._print_result(result)

    def _cmd_bla(self, args: Sequence[str]) -> int:
        parser = argparse.ArgumentParser(prog="bla", add_help=True)
        parser.add_argument("paths", nargs="+", help="远程日志文件路径")
        parser.add_argument("--tail", type=int, help="仅采集每个远程文件最后 N 行后分析")
        parser.add_argument("--grep", action="append", metavar="TEXT", help="仅保留包含关键词的行，可重复指定")
        parser.add_argument("--audit-json", metavar="FILE", help="写出远程采集审计记录 JSON")
        parser.add_argument("--out", metavar="DIR", help="本地标准报告目录（含 manifest.json）")
        parser.add_argument("--html", metavar="FILE", help="本地 HTML 报告")
        parser.add_argument("--json", metavar="FILE", help="本地 JSON 报告")
        parser.add_argument("--csv", metavar="FILE", help="本地 CSV 事件列表")
        parser.add_argument("--ioc", metavar="FILE", help="本地 IOC 清单")
        parser.add_argument("--sarif", metavar="FILE", help="本地 SARIF 报告")
        parser.add_argument("--profile", choices=("default", "cn-hvv"), default="default")
        parser.add_argument("--type", choices=["auto"] + list_parser_names(), default="auto")
        parser.add_argument("--exit-on", choices=("none", "critical", "high", "medium"), default="critical")
        parser.add_argument("--rules", action="append", metavar="DIR")
        parser.add_argument("--allowlist", metavar="FILE")
        parser.add_argument("--config", metavar="FILE")
        parser.add_argument("--max-alerts", type=int, default=50)
        parser.add_argument("--full", "--no-truncate", "--evidence", dest="full_evidence", action="store_true")
        parser.add_argument("--no-color", action="store_true")
        parser.add_argument("--syslog-year", type=int)
        parser.add_argument("--rdp", action="store_true", help="仅保留带远程来源 IP 的 Windows 4624/4625 登录事件")
        try:
            parsed = parser.parse_args(list(args))
        except SystemExit as e:
            return int(e.code or 0)
        if parsed.max_alerts < 0:
            self.print("--max-alerts 必须大于等于 0", file=sys.stderr)
            return 2
        if parsed.tail is not None and not (1 <= parsed.tail <= 100000):
            self.print("--tail 必须在 1 到 100000 之间", file=sys.stderr)
            return 2
        if any(not str(item or "").strip() for item in (parsed.grep or [])):
            self.print("--grep 不能为空", file=sys.stderr)
            return 2
        if parsed.syslog_year is not None and not (1970 <= parsed.syslog_year <= 2100):
            self.print("--syslog-year 必须在 1970 到 2100 之间", file=sys.stderr)
            return 2

        with tempfile.TemporaryDirectory(prefix="bla-remote-") as tmp:
            local_paths = []
            labels = {}
            collection_records = []
            for remote_item in parsed.paths:
                try:
                    local_path, label, collection_record = self._materialize_remote_source(
                        remote_item,
                        tmp,
                        tail_lines=parsed.tail,
                        grep_patterns=parsed.grep or [],
                    )
                except RuntimeError as e:
                    self.print(f"读取远程输入失败: {remote_item}: {e}", file=sys.stderr)
                    return 1
                local_paths.append(local_path)
                labels[Path(local_path).name] = label
                collection_records.append(collection_record)

            self.print(f"\n开始本地分析 {len(local_paths)} 个远程输入...\n")
            try:
                run_result = run_analysis(
                    AnalysisOptions(
                        paths=local_paths,
                        profile=parsed.profile,
                        parser_name=None if parsed.type == "auto" else parsed.type,
                        config_path=parsed.config,
                        rule_dirs=parsed.rules or [],
                        allowlist_path=parsed.allowlist,
                        syslog_year=parsed.syslog_year,
                        rdp_only=parsed.rdp,
                    ),
                    quiet=False,
                    print_fn=self.print,
                )
            except AnalysisError as e:
                self.print(f"分析失败: {e}", file=sys.stderr)
                return 1
            except Exception as e:
                self.print(f"分析流程失败: {e}", file=sys.stderr)
                return 1

            self._annotate_remote_sources(run_result.parse_results, labels)
            if run_result.parse_errors:
                self.print(f"有 {len(run_result.parse_errors)} 个输入解析失败，已从本次分析结果中排除:", file=sys.stderr)
                for item in run_result.parse_errors[:10]:
                    self.print(f"  - {item}", file=sys.stderr)
                if len(run_result.parse_errors) > 10:
                    self.print(f"  ... 还有 {len(run_result.parse_errors) - 10} 个失败输入未展示", file=sys.stderr)
            self.print(f"\n解析完成，共 {run_result.summary.total_events} 条事件")
            self.print(f"检测完成，发现 {len(run_result.summary.alerts)} 个告警\n")
            print_terminal_report(
                run_result.parse_results,
                run_result.summary,
                verbose=False,
                no_color=parsed.no_color,
                max_alerts=parsed.max_alerts,
                full_evidence=parsed.full_evidence,
            )
            try:
                write_reports(
                    run_result.parse_results,
                    run_result.summary,
                    AnalysisOutputs(
                        html=parsed.html,
                        json=parsed.json,
                        csv=parsed.csv,
                        ioc=parsed.ioc,
                        sarif=parsed.sarif,
                        bundle_dir=parsed.out,
                    ),
                    manifest_context=_remote_manifest_context(
                        parsed,
                        local_paths,
                        labels,
                        self.client.target,
                        self.cwd,
                        self.max_fetch_bytes,
                        self.command_timeout,
                        run_result.parse_errors,
                        run_result.suppressed_events,
                        collection_records,
                    ),
                )
                if parsed.audit_json:
                    _write_remote_collection_audit(
                        parsed.audit_json,
                        self.client.target,
                        self.cwd,
                        self.max_fetch_bytes,
                        self.command_timeout,
                        collection_records,
                        run_result.parse_errors,
                        run_result.suppressed_events,
                    )
            except OSError as e:
                self.print(f"报告写入失败: {e}", file=sys.stderr)
                return 1
            return _exit_code_for_alerts(run_result.summary.alerts, parsed.exit_on)

    def _materialize_remote_source(
        self,
        remote_item: str,
        tmp: str,
        tail_lines: Optional[int] = None,
        grep_patterns: Optional[Sequence[str]] = None,
    ) -> tuple[str, str, dict]:
        grep_patterns = list(grep_patterns or [])
        if remote_item.startswith("journalctl:"):
            unit = remote_item.split(":", 1)[1].strip()
            if not unit:
                raise RuntimeError("journalctl: 后面需要服务名，例如 journalctl:ssh")
            safe_unit = "".join(ch if ch.isalnum() or ch in "._@-" else "_" for ch in unit)
            local_path = os.path.join(tmp, f"journalctl-{safe_unit}.log")
            method = _collection_method("journalctl", tail_lines, grep_patterns)
            command = _remote_journalctl_command(unit, tail_lines, grep_patterns)
            self.client.capture_command(
                command,
                local_path,
                self.cwd,
                timeout=self.command_timeout,
                max_bytes=self.max_fetch_bytes,
            )
            label = _display_text(f"{self.client.target}:journalctl:{unit}")
            return local_path, label, _remote_collection_record(
                local_path,
                label,
                self.client.target,
                self.cwd,
                f"journalctl:{unit}",
                method,
                tail_lines,
                grep_patterns,
                self.max_fetch_bytes,
                self.command_timeout,
            )

        display_path = self._display_path(remote_item)
        basename = PurePosixPath(display_path).name or "remote.log"
        local_path = _unique_path(tmp, basename)
        if tail_lines is not None or grep_patterns:
            method = _collection_method("file", tail_lines, grep_patterns)
            self.client.capture_command(
                _remote_file_capture_command(remote_item, tail_lines, grep_patterns),
                local_path,
                self.cwd,
                max_bytes=self.max_fetch_bytes,
                timeout=self.command_timeout,
            )
        else:
            method = "file"
            self.client.fetch_file(
                remote_item,
                local_path,
                self.cwd,
                max_bytes=self.max_fetch_bytes,
                timeout=self.command_timeout,
            )
        label = _display_text(f"{self.client.target}:{display_path}")
        return local_path, label, _remote_collection_record(
            local_path,
            label,
            self.client.target,
            self.cwd,
            display_path,
            method,
            tail_lines,
            grep_patterns,
            self.max_fetch_bytes,
            self.command_timeout,
        )

    def _annotate_remote_sources(self, parse_results, labels: dict[str, str]) -> None:
        for result in parse_results:
            original_name = result.file_name
            label = labels.get(original_name)
            if not label:
                continue
            result.file_name = label
            for event in result.events:
                if event.source_file == original_name:
                    event.source_file = label
                if event.source == original_name:
                    event.source = label

    def _resolve_remote_cwd(self, target: str) -> str:
        result = self.client.run(f"cd {_qp(target)} && pwd -P")
        if result.returncode != 0:
            raise RuntimeError(result.error_text.strip() or f"无法进入远程目录: {target}")
        cwd = result.text.strip().splitlines()[-1] if result.text.strip() else ""
        if not cwd:
            raise RuntimeError("远程 pwd 未返回目录")
        return cwd

    def _display_path(self, path: str) -> str:
        if path.startswith("/"):
            return path
        if self.cwd == "/":
            return "/" + path
        return self.cwd.rstrip("/") + "/" + path

    def _print_help(self) -> None:
        self.print(
            "\n".join([
                "Remote Workspace 命令:",
                "  ls [PATH]                 查看远程目录",
                "  cd PATH                   切换远程目录",
                "  pwd                       显示远程当前目录",
                "  find [PATH] [PATTERN]     查找远程日志文件，默认当前目录、最多 3 层",
                "  tail FILE [N]             查看远程文件最后 N 行，默认 80",
                "  bla FILE [--out DIR]      拉回远程文件并在本机分析",
                "  bla FILE --tail N --grep TEXT  采集远程文件子集并在本机分析",
                "  bla FILE --rdp            仅保留 LogonType=10 且带远程来源 IP 的 Windows 登录事件",
                "  bla journalctl:ssh        拉回远程 journalctl 输出并在本机分析",
                "  exit                      退出",
            ])
        )

    def _print_result(self, result: RemoteCommandResult) -> int:
        if result.stdout:
            self.print(_display_text(result.text.rstrip()))
        if result.returncode != 0:
            self._print_remote_error(result)
        return result.returncode

    def _print_remote_error(self, result: RemoteCommandResult) -> None:
        message = result.error_text.strip() or result.text.strip() or f"远程命令失败，退出码 {result.returncode}"
        message = _display_text(message)
        self.print(message, file=sys.stderr)


def _q(value: str) -> str:
    return shlex.quote(value)


def _display_text(value: object) -> str:
    return strip_terminal_control(value)


def _is_safe_ssh_target(value: str) -> bool:
    return bool(str(value or "").strip()) and not str(value).lstrip().startswith("-")


def _remote_manifest_context(
    parsed: argparse.Namespace,
    local_paths: Sequence[str],
    labels: dict[str, str],
    target: str,
    cwd: str,
    max_fetch_bytes: int,
    command_timeout: int,
    parse_errors: Sequence[str],
    suppressed_events: int,
    collection_records: Optional[Sequence[dict]] = None,
) -> dict:
    return {
        "inputs": [_remote_input_manifest_record(path, labels) for path in local_paths],
        "options": {
            "profile": parsed.profile,
            "parser": parsed.type,
            "rules": parsed.rules or [],
            "allowlist": parsed.allowlist,
            "config": parsed.config,
            "exit_on": parsed.exit_on,
            "syslog_year": parsed.syslog_year,
            "rdp_only": parsed.rdp,
            "max_alerts": parsed.max_alerts,
            "full_evidence": bool(parsed.full_evidence),
        },
        "remote": {
            "target": target,
            "cwd": cwd,
            "max_fetch_bytes": max_fetch_bytes,
            "command_timeout": command_timeout,
        },
        "remote_collection": list(collection_records or []),
        "parse_errors": list(parse_errors),
        "suppressed_events": suppressed_events,
    }


def _remote_input_manifest_record(path: str, labels: dict[str, str]) -> dict:
    name = Path(path).name
    record = {
        "remote_label": labels.get(name, name),
        "local_name": name,
        "size_bytes": 0,
        "sha256": "",
    }
    try:
        record["size_bytes"] = os.path.getsize(path)
        record["sha256"] = _sha256_file(path)
    except OSError:
        pass
    return record


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _remote_file_capture_command(
    remote_path: str,
    tail_lines: Optional[int],
    grep_patterns: Sequence[str],
) -> str:
    read_cmd = f"cat -- {_qp(remote_path)}"
    if tail_lines is not None:
        read_cmd = f"tail -n {tail_lines} -- {_qp(remote_path)}"
    if not grep_patterns:
        return f"test -r {_qp(remote_path)} && {read_cmd}"
    pipeline = _append_fixed_grep(read_cmd, grep_patterns)
    return f"test -r {_qp(remote_path)} && {{ {pipeline}; status=$?; test $status -eq 0 -o $status -eq 1; }}"


def _remote_journalctl_command(unit: str, tail_lines: Optional[int], grep_patterns: Sequence[str]) -> str:
    line_count = tail_lines if tail_lines is not None else 5000
    command = f"journalctl -u {_q(unit)} -n {line_count} --no-pager -o short"
    if not grep_patterns:
        return command
    pipeline = _append_fixed_grep(command, grep_patterns)
    return f"{{ {pipeline}; status=$?; test $status -eq 0 -o $status -eq 1; }}"


def _append_fixed_grep(command: str, grep_patterns: Sequence[str]) -> str:
    for pattern in grep_patterns:
        command = f"({command}) | grep -F -e {_q(pattern)}"
    return command


def _collection_method(base: str, tail_lines: Optional[int], grep_patterns: Sequence[str]) -> str:
    suffixes = []
    if tail_lines is not None:
        suffixes.append("tail")
    if grep_patterns:
        suffixes.append("grep")
    if not suffixes:
        return base
    return "-".join([base, *suffixes])


def _remote_collection_record(
    local_path: str,
    label: str,
    target: str,
    cwd: str,
    remote_path: str,
    method: str,
    tail_lines: Optional[int],
    grep_patterns: Sequence[str],
    max_bytes: int,
    command_timeout: int,
) -> dict:
    record = {
        "source": "remote",
        "target": _display_text(target),
        "cwd": _display_text(cwd),
        "remote_path": _display_text(remote_path),
        "remote_label": _display_text(label),
        "local_name": Path(local_path).name,
        "method": method,
        "tail_lines": tail_lines,
        "grep_patterns": [_display_text(item) for item in grep_patterns],
        "max_bytes": max_bytes,
        "command_timeout": command_timeout,
        "size_bytes": 0,
        "sha256": "",
    }
    try:
        record["size_bytes"] = os.path.getsize(local_path)
        record["sha256"] = _sha256_file(local_path)
    except OSError:
        pass
    return record


def _write_remote_collection_audit(
    output_path: str,
    target: str,
    cwd: str,
    max_bytes: int,
    command_timeout: int,
    collection_records: Sequence[dict],
    parse_errors: Sequence[str],
    suppressed_events: int,
) -> None:
    audit = {
        "schema": "bla-remote-collection-audit-v1",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "remote": {
            "target": _display_text(target),
            "cwd": _display_text(cwd),
            "max_fetch_bytes": max_bytes,
            "command_timeout": command_timeout,
        },
        "collection": list(collection_records),
        "parse_errors": [_display_text(item) for item in parse_errors],
        "suppressed_events": suppressed_events,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(audit, f, ensure_ascii=False, indent=2)


def _split_workspace_line(line: str) -> List[str]:
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    lexer.escape = ""
    return list(lexer)


def _qp(value: str) -> str:
    if value == "~":
        return "~"
    if value.startswith("~/"):
        rest = value[2:]
        if all(ch.isalnum() or ch in "._/-" for ch in rest):
            return "~/" + rest
    return _q(value)


def _remote_cd_command(cwd: str, command: str) -> str:
    return f"cd {_qp(cwd)} && {command}"


def _exit_code_for_alerts(alerts, exit_on: str) -> int:
    threshold = _EXIT_THRESHOLDS.get(exit_on)
    if threshold is None:
        return 0
    return 1 if any(alert.level.score >= threshold for alert in alerts) else 0


def _unique_path(directory: str, basename: str) -> str:
    candidate = Path(directory) / basename
    if not candidate.exists():
        return str(candidate)
    stem = candidate.stem
    suffix = candidate.suffix
    for idx in range(2, 1000):
        next_candidate = Path(directory) / f"{stem}-{idx}{suffix}"
        if not next_candidate.exists():
            return str(next_candidate)
    raise RuntimeError(f"临时文件命名冲突: {basename}")
