#!/usr/bin/env python3
"""检查发布说明。

发布说明必须：
  · 有当前版本的段落
  · 带免责声明

每次发 Release 的正文就是 release-notes.md，所以这里的检查等于给
「免责申明拉满」上了道闸。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTES = ROOT / "release-notes.md"

REQUIRED = ["免责", "授权", "法律责任"]


def main() -> int:
    if not NOTES.exists():
        print("找不到 release-notes.md")
        return 1
    text = NOTES.read_text(encoding="utf-8")
    problems = []

    for phrase in REQUIRED:
        if phrase not in text:
            problems.append(f"发布说明里没有「{phrase}」")

    versions = re.findall(r"^##\s*passcrack\s+v?([0-9][^\s-]*)", text, re.M)
    if not versions:
        problems.append("发布说明里没有 passcrack 的版本段落")
    elif len(versions) > 1:
        problems.append(f"发布说明里有 {len(versions)} 个版本段落，一次只发一个版本")

    if problems:
        print("发布说明有问题：")
        for p in problems:
            print("  -", p)
        return 1

    print(f"发布说明没问题，版本 {versions[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
