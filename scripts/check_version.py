#!/usr/bin/env python3
"""检查版本号是不是处处一致。

tag、pyproject.toml、__init__.py、release-notes.md 四处必须是同一个版本，
少一处就会导致「打出来的包说自己是谁的版本」这种尴尬事。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def pyproject_version() -> str | None:
    text = _read(ROOT / "pyproject.toml")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    return m.group(1) if m else None


def package_version() -> str | None:
    text = _read(ROOT / "src" / "passcrack" / "__init__.py")
    m = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    return m.group(1) if m else None


def notes_version() -> str | None:
    text = _read(ROOT / "release-notes.md")
    m = re.search(r"^##\s*passcrack\s+v?([0-9][^\s-]*)", text, re.M)
    return m.group(1) if m else None


def main() -> int:
    tag = sys.argv[1] if len(sys.argv) > 1 else ""
    expected = tag[1:] if tag.startswith("v") else tag

    values = {
        "pyproject.toml": pyproject_version(),
        "src/passcrack/__init__.py": package_version(),
        "release-notes.md": notes_version(),
    }
    if expected:
        values["tag"] = expected

    problems = []
    for name, value in values.items():
        if value is None:
            problems.append(f"{name}: 没找到版本号")
        elif expected and value != expected:
            problems.append(f"{name}: 是 {value}，应该是 {expected}")

    if problems:
        print("版本号对不上：")
        for p in problems:
            print("  -", p)
        return 1

    print("版本号一致:", ", ".join(f"{k}={v}" for k, v in values.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
