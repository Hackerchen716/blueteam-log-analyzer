#!/usr/bin/env python3
"""Backward-compatible CLI shim for ``python bla_cli.py`` and old imports."""
from __future__ import annotations

import sys

from bla.cli import main as _main_module
from bla.utils.helpers import print_sanitized_traceback, sanitize_report_text

for _name in dir(_main_module):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_main_module, _name)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  用户中断", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ 致命错误: {sanitize_report_text(e)}", file=sys.stderr)
        print_sanitized_traceback(e, file=sys.stderr)
        sys.exit(1)
