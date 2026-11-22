"""FTP 口令恢复。

必须提供服务器地址与用户名。本模块只对用户显式给出的那一个服务器工作，
没有扫描、没有枚举目标。

除了在线尝试，还能从本机已保存的凭据里找回密码（见 osint 模块），
那才是大多数情况下真正管用的路子。
"""

from __future__ import annotations

import ftplib
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Sequence

FTP_ERRORS = tuple(ftplib.all_errors) + (socket.timeout,)


@dataclass
class FtpTarget:
    host: str
    username: str
    port: int = 21
    implicit_tls: bool = False
    timeout: float = 10.0
    delay: float = 0.5
    max_attempts: int = 0
    banner: str = ""
    errors: list[str] = field(default_factory=list)

    def describe(self) -> str:
        scheme = "ftps" if self.implicit_tls else "ftp"
        return f"{scheme}://{self.username}@{self.host}:{self.port}"


class AttemptLimitReached(Exception):
    """尝试次数达到上限，或者服务端明确拒绝继续。"""


def _connect(target: FtpTarget) -> ftplib.FTP:
    """建立连接。implicit_tls 直接走 FTPS，否则普通 FTP。"""
    if target.implicit_tls:
        ctx = ssl.create_default_context()
        ftp = ftplib.FTP_TLS(timeout=target.timeout, context=ctx)
        ftp.connect(target.host, target.port)
        return ftp
    ftp = ftplib.FTP(timeout=target.timeout)
    ftp.connect(target.host, target.port)
    return ftp


def probe(target: FtpTarget) -> str:
    """连接一次，拿到服务器横幅，顺便确认能连上。"""
    ftp: ftplib.FTP | None = None
    try:
        ftp = _connect(target)
        target.banner = ftp.getwelcome() or ""
        return target.banner
    except ftplib.error_perm as exc:
        # 匿名登录被拒也算连上了
        target.banner = str(exc)
        return target.banner
    except FTP_ERRORS as exc:
        raise ConnectionError(f"连不上 {target.host}:{target.port}：{exc}") from exc
    finally:
        if ftp is not None:
            try:
                ftp.close()
            except Exception:
                pass


def try_login(target: FtpTarget, password: str) -> bool:
    """用给定口令登录一次。成功返回 True。"""
    ftp: ftplib.FTP | None = None
    try:
        ftp = _connect(target)
        ftp.login(target.username, password)
        if isinstance(ftp, ftplib.FTP_TLS) and not target.implicit_tls:
            # 显式 TLS：登录成功后再升级
            try:
                ftp.prot_p()
            except Exception:
                pass
        return True
    except ftplib.error_perm as exc:
        msg = str(exc)
        if "530" in msg:
            return False
        if "421" in msg or "too many" in msg.lower() or "locked" in msg.lower():
            raise AttemptLimitReached(msg) from exc
        return False
    except ftplib.error_temp as exc:
        msg = str(exc)
        if "421" in msg:
            raise AttemptLimitReached(msg) from exc
        return False
    except (OSError, socket.timeout, ssl.SSLError) as exc:
        raise ConnectionError(f"连接 {target.host}:{target.port} 出错：{exc}") from exc
    finally:
        if ftp is not None:
            try:
                ftp.quit()
            except Exception:
                try:
                    ftp.close()
                except Exception:
                    pass


def check_batch(candidates: Sequence[str], target: FtpTarget) -> str | None:
    """一批候选里找出能登录的口令。"""
    for cand in candidates:
        if target.max_attempts and target.max_attempts <= 0:
            raise AttemptLimitReached("已达到设定的最大尝试次数")
        try:
            if try_login(target, cand):
                return cand
        except AttemptLimitReached:
            raise
        except ConnectionError as exc:
            target.errors.append(str(exc))
            raise
        if target.delay:
            time.sleep(target.delay)
        if target.max_attempts:
            target.max_attempts -= 1
    return None


def verify(target: FtpTarget, password: str) -> bool:
    return try_login(target, password)
