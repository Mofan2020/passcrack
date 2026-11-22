"""命令行入口。

不带任何参数时启动图形界面；带了参数就走命令行。
命令行模式每次运行都先打印免责声明。
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Sequence

from . import __version__, console
from .core import archives, candidates
from .core import ftp as ftp_mod
from .core import wifi as wifi_mod
from .core.engine import SearchJob, human_duration, human_rate
from .disclaimer import LONG, SHORT


def _print_banner() -> None:
    print(LONG)
    print()
    print(f"passcrack {__version__}")
    print("-" * 70)


def _common_candidate_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--wordlist", action="append", default=[], metavar="FILE",
                   help="字典文件，可重复指定")
    p.add_argument("--rule", action="append", default=[], metavar="NAME",
                   help="对字典条目套用规则，可重复指定")
    p.add_argument("--mask", action="append", default=[], metavar="PATTERN",
                   help="掩码展开，例如 ?l?l?l?l?d")
    p.add_argument("--no-builtin", action="store_true", help="不使用内置常用口令表")
    p.add_argument("--workers", type=int, default=0, help="并行进程数，0 表示自动")
    p.add_argument("--chunk", type=int, default=512, help="每批送多少个候选去校验")


def _make_candidates(args: argparse.Namespace):
    rules = args.rule or []
    for r in rules:
        if r not in candidates.RULES:
            raise SystemExit(f"未知规则: {r}\n可用规则: {', '.join(sorted(candidates.RULES))}")
    return candidates.build_candidates(
        builtin=not args.no_builtin,
        wordlists=args.wordlist,
        rules=rules,
        masks=args.mask,
    )


def _progress_printer(label: str):
    state = {"last": 0.0}

    def report(prog) -> None:
        now = time.monotonic()
        if prog.finished:
            return
        if now - state["last"] < 0.5:
            return
        state["last"] = now
        print(f"\r  {label} 已试 {prog.tried} 个，{human_rate(prog.rate)}，"
              f"用时 {human_duration(prog.elapsed)}", end="", flush=True)

    return report


def _run_job(job: SearchJob, label: str) -> int:
    print(f"  {label}开始…")
    prog = job.run()
    print("\r" + " " * 78 + "\r", end="")
    if prog.found:
        print(f"  找到了，口令是: {prog.found}")
        print(f"  共试了约 {prog.tried} 个候选，用时 {human_duration(prog.elapsed)}")
        return 0
    if prog.cancelled:
        print("  已取消")
        return 2
    print(f"  没找到。共试了约 {prog.tried} 个候选，用时 {human_duration(prog.elapsed)}")
    for err in prog.errors[:5]:
        print(f"  出错: {err}")
    return 1


# ----------------------------------------------------------------------
# 子命令
# ----------------------------------------------------------------------
def cmd_ftp(args: argparse.Namespace) -> int:
    if not args.host:
        raise SystemExit("FTP 模式必须提供服务器地址（--host）")
    if not args.user:
        raise SystemExit("FTP 模式必须提供用户名（--user）")
    target = ftp_mod.FtpTarget(
        host=args.host,
        username=args.user,
        port=args.port,
        implicit_tls=args.tls,
        delay=args.delay,
        max_attempts=args.max_attempts,
    )
    if args.saved_only:
        pw = _saved_ftp(args.host, args.user)
        if pw:
            print(f"  本机保存的密码: {pw}")
            return 0
        print("  本机没有找到这个服务器的已保存密码")
        return 1

    print(f"  目标: {target.describe()}")
    try:
        banner = ftp_mod.probe(target)
    except ConnectionError as exc:
        print(f"  {exc}")
        return 1
    if banner:
        print(f"  服务器: {banner.strip()}")

    cands = _make_candidates(args)
    job = SearchJob(
        cands,
        checker=_ftp_checker(target),
        workers=args.workers,
        chunk_size=args.chunk,
        use_processes=False,
        on_progress=_progress_printer("FTP"),
    )
    try:
        return _run_job(job, "FTP 恢复")
    except ftp_mod.AttemptLimitReached as exc:
        print(f"  服务端拒绝继续尝试: {exc}")
        return 3


def _ftp_checker(target: ftp_mod.FtpTarget):
    def checker(batch):
        return ftp_mod.check_batch(batch, target)
    return checker


def _saved_ftp(host: str, user: str) -> str | None:
    from .osint import saved
    cred = saved.find_ftp_password(host, user)
    return cred.password if cred else None


def cmd_wifi(args: argparse.Namespace) -> int:
    if not args.ssid:
        raise SystemExit("WiFi 模式必须提供 SSID（--ssid）")
    if args.saved_only:
        from .osint import saved
        pw = saved.find_wifi_password(args.ssid)
        if pw:
            print(f"  本机保存的密码: {pw}")
            return 0
        print("  本机没有找到这个 SSID 的已保存密码")
        return 1

    if not args.capture:
        raise SystemExit("WiFi 模式需要抓包文件（--capture），或用 --saved-only 查本机保存的密码")

    handshakes = wifi_mod.load_handshakes(args.capture, args.ssid)
    if not handshakes:
        print("  抓包里没有找到可用的握手")
        return 1
    for line in wifi_mod.describe(handshakes):
        print(f"  {line}")
    sae = [h for h in handshakes if h.sae]
    if sae:
        print("  检测到 WPA3 SAE 握手，纯 Python 跑不动，请用 hashcat 或 hcxtools")
        return 4

    if args.hashcat:
        hit = wifi_mod.delegate_to_hashcat(args.capture, args.wordlist[0] if args.wordlist else "")
        if hit:
            print(f"  hashcat 找到了，口令是: {hit}")
            return 0
        print("  hashcat 没找到")

    cands = _make_candidates(args)
    job = SearchJob(
        cands,
        checker=_wifi_checker(handshakes),
        workers=args.workers,
        chunk_size=max(1, min(args.chunk, 8)),
        use_processes=True,
        on_progress=_progress_printer("WiFi"),
    )
    return _run_job(job, "WiFi 恢复")


def _wifi_checker(handshakes):
    def checker(batch):
        return wifi_mod.check_batch(batch, handshakes)
    return checker


def cmd_archive(args: argparse.Namespace) -> int:
    path = os.path.abspath(os.path.expanduser(args.file))
    if not os.path.isfile(path):
        raise SystemExit(f"文件不存在: {path}")
    fmt = archives.detect_format(path)
    print(f"  文件: {path}")
    print(f"  格式: {fmt}")
    if fmt == "unknown":
        print("  不认识的格式")
        return 1

    cands = _make_candidates(args)
    job = SearchJob(
        cands,
        checker=_archive_checker(path),
        workers=args.workers,
        chunk_size=max(1, min(args.chunk, 64)),
        use_processes=True,
        on_progress=_progress_printer("压缩包"),
    )
    return _run_job(job, "压缩包恢复")


def _archive_checker(path: str):
    def checker(batch):
        return archives.check_batch(batch, path)
    return checker


def cmd_saved(args: argparse.Namespace) -> int:
    from .osint import saved
    if not args.host and not args.ssid:
        raise SystemExit("请用 --host 或 --ssid 指定要查的目标")
    if args.host:
        cred = saved.find_ftp_password(args.host, args.user or "")
        if cred:
            print(f"  FTP {args.host} 账户 {cred.account}: {cred.password}")
            return 0
        print(f"  没有找到 {args.host} 的已保存密码")
    if args.ssid:
        pw = saved.find_wifi_password(args.ssid)
        if pw:
            print(f"  WiFi {args.ssid}: {pw}")
            return 0
        print(f"  没有找到 {args.ssid} 的已保存密码")
    return 1


def cmd_rules(_args: argparse.Namespace) -> int:
    print("可用规则:")
    for name, desc in sorted(candidates.RULES.items()):
        print(f"  {name:<16} {desc}")
    print()
    print("掩码符号: ?l 小写 ?u 大写 ?d 数字 ?s 符号 ?S 常用符号 ?a 字母")
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"passcrack {__version__}")
    return 0


# ----------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="passcrack",
        description="口令恢复工具（仅限自有或已授权的系统）",
        epilog=SHORT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"passcrack {__version__}")
    sub = p.add_subparsers(dest="command")

    ftp_p = sub.add_parser("ftp", help="FTP 口令恢复")
    ftp_p.add_argument("--host", required=False, help="服务器地址")
    ftp_p.add_argument("--user", required=False, help="用户名")
    ftp_p.add_argument("--port", type=int, default=21, help="端口，默认 21")
    ftp_p.add_argument("--tls", action="store_true", help="隐式 FTPS（990）")
    ftp_p.add_argument("--delay", type=float, default=0.5, help="每次尝试间隔秒，默认 0.5")
    ftp_p.add_argument("--max-attempts", type=int, default=0, help="最大尝试次数，0 表示不限")
    ftp_p.add_argument("--saved-only", action="store_true", help="只查本机已保存的密码，不做在线尝试")
    _common_candidate_args(ftp_p)
    ftp_p.set_defaults(func=cmd_ftp)

    wifi_p = sub.add_parser("wifi", help="WiFi 口令恢复")
    wifi_p.add_argument("--ssid", required=False, help="SSID")
    wifi_p.add_argument("--capture", help="抓包文件（.hc22000 / .pcap / .cap）")
    wifi_p.add_argument("--saved-only", action="store_true", help="只查本机已保存的密码")
    wifi_p.add_argument("--hashcat", action="store_true", help="优先交给 hashcat 处理")
    _common_candidate_args(wifi_p)
    wifi_p.set_defaults(func=cmd_wifi)

    arc_p = sub.add_parser("archive", help="压缩包口令恢复")
    arc_p.add_argument("--file", required=True, help="压缩包路径")
    _common_candidate_args(arc_p)
    arc_p.set_defaults(func=cmd_archive)

    saved_p = sub.add_parser("saved", help="查本机已保存的凭据")
    saved_p.add_argument("--host", help="FTP 服务器地址")
    saved_p.add_argument("--user", help="用户名")
    saved_p.add_argument("--ssid", help="WiFi SSID")
    saved_p.set_defaults(func=cmd_saved)

    rules_p = sub.add_parser("rules", help="列出可用规则与掩码符号")
    rules_p.set_defaults(func=cmd_rules)

    ver_p = sub.add_parser("version", help="显示版本号")
    ver_p.set_defaults(func=cmd_version)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if not args_list:
        # 不带参数就开图形界面
        from .ui.app import launch
        return launch()

    parser = build_parser()
    args = parser.parse_args(args_list)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1

    # Windows 上打包成无黑框 exe 之后，命令行模式要接上父进程的 console
    console.attach_parent_console()
    console.setup()

    _print_banner()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n  已中断")
        return 130
