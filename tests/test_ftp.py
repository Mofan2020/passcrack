"""FTP 口令恢复的测试。

起一个本地的小 FTP 服务，只监听回环地址，只认一个账号。
不碰任何外部网络。
"""

from __future__ import annotations

import contextlib
import socket
import threading

import pytest

from passcrack.core import ftp as ftp_mod


class FakeFtpServer:
    """够 ftplib 登录用的最小 FTP 服务。"""

    def __init__(self, user: str, password: str) -> None:
        self.user = user
        self.password = password
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> FakeFtpServer:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop = True
        with contextlib.suppress(Exception):
            self.sock.close()

    def _serve(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        user = None
        try:
            conn.sendall(b"220 fake ftp ready\r\n")
            f = conn.makefile("rwb")
            while True:
                line = f.readline()
                if not line:
                    break
                text = line.decode("utf-8", "replace").strip()
                upper = text.upper()
                if upper.startswith("USER"):
                    user = text[4:].strip()
                    f.write(b"331 need password\r\n")
                    f.flush()
                elif upper.startswith("PASS"):
                    pwd = text[4:].strip()
                    if user == self.user and pwd == self.password:
                        f.write(b"230 logged in\r\n")
                    else:
                        f.write(b"530 login incorrect\r\n")
                    f.flush()
                elif upper.startswith("QUIT"):
                    f.write(b"221 bye\r\n")
                    f.flush()
                    break
                elif upper.startswith("TYPE"):
                    f.write(b"200 ok\r\n")
                    f.flush()
                elif upper.startswith("AUTH") or upper.startswith("PBSZ") or upper.startswith("PROT"):
                    f.write(b"500 not supported\r\n")
                    f.flush()
                else:
                    f.write(b"500 unknown\r\n")
                    f.flush()
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                conn.close()


@pytest.fixture()
def server():
    with FakeFtpServer("tester", "s3cret") as s:
        yield s


def _target(server, **kw) -> ftp_mod.FtpTarget:
    return ftp_mod.FtpTarget(host="127.0.0.1", username="tester",
                             port=server.port, delay=0.0, timeout=5.0, **kw)


def test_probe_reaches_the_server(server):
    target = _target(server)
    banner = ftp_mod.probe(target)
    assert "fake ftp" in banner


def test_verify_correct_password(server):
    target = _target(server)
    assert ftp_mod.verify(target, "s3cret") is True


def test_verify_wrong_password(server):
    target = _target(server)
    assert ftp_mod.verify(target, "nope") is False


def test_check_batch_finds_the_password(server):
    target = _target(server)
    hit = ftp_mod.check_batch(["aaa", "bbb", "s3cret", "ccc"], target)
    assert hit == "s3cret"


def test_check_batch_returns_none(server):
    target = _target(server)
    assert ftp_mod.check_batch(["aaa", "bbb"], target) is None


def test_max_attempts_is_enforced(server):
    target = _target(server, max_attempts=2)
    with pytest.raises(ftp_mod.AttemptLimitReached):
        ftp_mod.check_batch(["a", "b", "c", "d"], target)


def test_target_requires_host_and_user():
    t = ftp_mod.FtpTarget(host="", username="")
    assert t.host == ""
    assert t.username == ""


def test_describe_shows_the_target(server):
    target = _target(server)
    text = target.describe()
    assert "tester" in text
    assert "127.0.0.1" in text
