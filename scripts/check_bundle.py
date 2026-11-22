#!/usr/bin/env python3
"""检查打包产物里是不是真带上了前端资源。

PyInstaller 会把数据文件压进可执行文件里，肉眼从包里看不出来，
所以读它的归档目录，按名字核对。
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

REQUIRED = [
    "passcrack/ui/assets/index.html",
    "passcrack/ui/assets/app.js",
    "passcrack/ui/assets/style.css",
]


def list_entries(binary: Path) -> list[str]:
    from PyInstaller.archive.readers import CArchiveReader

    reader = CArchiveReader(str(binary))
    # Windows 上归档里的路径是反斜杠，统一成斜杠再比
    return [name.replace("\\", "/") for name in reader.toc]


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: check_bundle.py <可执行文件>")
        return 2
    binary = Path(sys.argv[1])
    if not binary.exists():
        print(f"找不到文件: {binary}")
        return 1

    try:
        names = list_entries(binary)
    except Exception as exc:
        print(f"读不了归档: {type(exc).__name__}: {exc}")
        return 1

    problems = []
    for want in REQUIRED:
        if not any(name.endswith(want) for name in names):
            problems.append(f"少了 {want}")

    print(f"归档条目 {len(names)} 个")
    if problems:
        print("打包内容不对：")
        for p in problems:
            print("  -", p)
        return 1
    print("前端资源都在")
    return 0


if __name__ == "__main__":
    # Windows 的控制台默认代码页装不下中文，输出前先放宽编码
    with contextlib.suppress(Exception):
        for _stream in (sys.stdout, sys.stderr):
            _stream.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
