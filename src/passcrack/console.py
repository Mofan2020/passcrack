"""Windows 下的控制台输出适配。

打包成无黑框的 exe 之后，命令行模式仍然要能打印结果。做法是附上父进程
的console，再把标准流重新绑到 CONOUT$。

中文 Windows 的控制台默认代码页装不下免责声明里的制表符号，所以先试探
当前编码能不能写出那串字符，装不下才切到 UTF-8，不是无条件强改。
"""

from __future__ import annotations

import sys

# 用来试探编码的一组字符：中文、制表符、长破折号
_PROBE = "免责声明——═║"


def attach_parent_console() -> bool:
    """附上父进程的 console。成功返回 True。"""
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        ATTACH_PARENT_PROCESS = -1
        if not ctypes.windll.kernel32.AttachConsole(ATTACH_PARENT_PROCESS):
            return False
        sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace")
        sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace")
        return True
    except Exception:
        return False


def _can_encode(text: str) -> bool:
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        text.encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def _force_utf8() -> None:
    """把控制台切到 UTF-8，并给流加 errors='replace' 兜底。"""
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def setup() -> None:
    """命令行启动前调用一次。"""
    if sys.platform != "win32":
        return
    if not _can_encode(_PROBE):
        _force_utf8()
