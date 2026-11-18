"""Entry point for `python -m reconone`.

The scan stack now depends on httpx + anyio (hard requirement). Importing `cli` pulls them
in, so a missing install surfaces here as a traceback before any argument parsing. Catch it
once and print the command that fixes it.
"""
from __future__ import annotations

import sys


def _run() -> int:
    try:
        from .cli import main
    except ImportError as exc:                 # pragma: no cover - exercised on a bare env
        print("reconone 缺少必需依赖（httpx、anyio）。", file=sys.stderr)
        print(f"  无法导入：{exc.name or exc}", file=sys.stderr)
        print("  安装：python -m pip install -r requirements.txt", file=sys.stderr)
        return 4
    return main()


if __name__ == "__main__":
    raise SystemExit(_run())
