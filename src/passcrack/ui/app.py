"""图形界面入口。

用 pywebview 起一个本地窗口，前端是随包发布的静态页面。
界面和命令行共用同一套核心模块，功能一致。
"""

from __future__ import annotations

import os
import sys
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any

from .. import __version__
from ..core import archives, candidates
from ..core import ftp as ftp_mod
from ..core import wifi as wifi_mod
from ..core.engine import SearchJob
from ..disclaimer import LONG, SHORT, UI_ACK_TEXT

ASSETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")


@dataclass
class Job:
    id: str
    kind: str
    label: str
    state: str = "running"          # running / done / failed / cancelled
    tried: int = 0
    rate: float = 0.0
    elapsed: float = 0.0
    found: str | None = None
    message: str = ""
    errors: list[str] = field(default_factory=list)
    job: SearchJob | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "id": self.id,
                "kind": self.kind,
                "label": self.label,
                "state": self.state,
                "tried": self.tried,
                "rate": round(self.rate, 1),
                "elapsed": round(self.elapsed, 1),
                "found": self.found,
                "message": self.message,
                "errors": list(self.errors[:8]),
            }


class Api:
    """暴露给前端调用的方法。"""

    def __init__(self) -> None:
        self.jobs: dict[str, Job] = {}
        self.window = None

    def attach_window(self, window) -> None:
        self.window = window

    # ---------------- 基本信息 ----------------
    def info(self) -> dict[str, Any]:
        return {
            "version": __version__,
            "platform": sys.platform,
            "disclaimer": LONG,
            "short": SHORT,
            "ack": UI_ACK_TEXT,
            "rules": sorted(candidates.RULES.items()),
            "tools": wifi_mod.external_tools(),
        }

    # ---------------- 文件选择 ----------------
    def pick_file(self) -> list[str]:
        """弹系统文件选择框，返回选中的路径列表。"""
        if self.window is None:
            return []
        try:
            import webview
        except ImportError:
            return []
        result = self.window.create_file_dialog(
            webview.OPEN_DIALOG, allow_multiple=False, file_types=("All files (*.*)",)
        )
        if not result:
            return []
        if isinstance(result, str | tuple):
            return list(result) if isinstance(result, tuple) else [result]
        return list(result)

    # ---------------- 本机已保存的凭据 ----------------
    def saved_ftp(self, host: str, username: str = "") -> str | None:
        return _saved_ftp(host, username)

    def saved_wifi(self, ssid: str) -> str | None:
        return _saved_wifi(ssid)

    # ---------------- 任务 ----------------
    def _new_job(self, kind: str, label: str) -> Job:
        jid = uuid.uuid4().hex[:12]
        job = Job(id=jid, kind=kind, label=label)
        self.jobs[jid] = job
        # 只留最近 20 个任务的记录
        if len(self.jobs) > 20:
            for k in list(self.jobs)[:-20]:
                self.jobs.pop(k, None)
        return job

    def _candidates(self, params: dict[str, Any]):
        rules = params.get("rules") or []
        bad = [r for r in rules if r not in candidates.RULES]
        if bad:
            raise ValueError("未知规则: " + ", ".join(bad))
        wordlists = params.get("wordlists") or []
        for w in wordlists:
            if not os.path.isfile(os.path.expanduser(w)):
                raise ValueError(f"字典文件不存在: {w}")
        return candidates.build_candidates(
            builtin=bool(params.get("builtin", True)),
            wordlists=[os.path.expanduser(w) for w in wordlists],
            rules=rules,
            masks=params.get("masks") or [],
        )

    def _run(self, job: Job, maker) -> None:
        try:
            search = maker()
            job.job = search

            def on_progress(prog) -> None:
                with job.lock:
                    job.tried = prog.tried
                    job.rate = prog.rate
                    job.elapsed = prog.elapsed

            search.on_progress = on_progress
            prog = search.run()
            with job.lock:
                job.tried = prog.tried
                job.rate = prog.rate
                job.elapsed = prog.elapsed
                job.errors = list(prog.errors)
                if prog.found:
                    job.found = prog.found
                    job.state = "done"
                    job.message = "找到了"
                elif prog.cancelled:
                    job.state = "cancelled"
                    job.message = "已取消"
                else:
                    job.state = "done"
                    job.message = "没有匹配的候选"
        except Exception as exc:
            with job.lock:
                job.state = "failed"
                job.message = f"{type(exc).__name__}: {exc}"

    def start_ftp(self, params: dict[str, Any]) -> str:
        host = (params.get("host") or "").strip()
        user = (params.get("user") or "").strip()
        if not host:
            raise ValueError("必须填写服务器地址")
        if not user:
            raise ValueError("必须填写用户名")
        target = ftp_mod.FtpTarget(
            host=host,
            username=user,
            port=int(params.get("port") or 21),
            implicit_tls=bool(params.get("tls")),
            delay=float(params.get("delay") or 0.5),
            max_attempts=int(params.get("max_attempts") or 0),
        )
        if params.get("saved_only"):
            job = self._new_job("ftp", "本机已保存的 FTP 密码")
            pw = _saved_ftp(host, user)
            with job.lock:
                if pw:
                    job.found = pw
                    job.state = "done"
                    job.message = "已找到"
                else:
                    job.state = "done"
                    job.message = "本机没有保存这个服务器的密码"
            return job.id

        try:
            banner = ftp_mod.probe(target)
        except ConnectionError as exc:
            raise ValueError(str(exc)) from exc

        cands = self._candidates(params)
        job = self._new_job("ftp", f"FTP {target.describe()}  {banner.strip()}")

        def maker() -> SearchJob:
            return SearchJob(
                cands,
                checker=lambda batch: ftp_mod.check_batch(batch, target),
                workers=int(params.get("workers") or 0),
                chunk_size=int(params.get("chunk") or 512),
                use_processes=False,
            )

        threading.Thread(target=self._run, args=(job, maker), daemon=True).start()
        return job.id

    def start_wifi(self, params: dict[str, Any]) -> str:
        ssid = (params.get("ssid") or "").strip()
        if not ssid:
            raise ValueError("必须填写 SSID")
        if params.get("saved_only"):
            job = self._new_job("wifi", "本机已保存的 WiFi 密码")
            pw = _saved_wifi(ssid)
            with job.lock:
                if pw:
                    job.found = pw
                    job.state = "done"
                    job.message = "已找到"
                else:
                    job.state = "done"
                    job.message = "本机没有保存这个 SSID 的密码"
            return job.id

        capture = (params.get("capture") or "").strip()
        if not capture:
            raise ValueError("必须选择抓包文件，或者改用「只查本机已保存」")
        capture = os.path.abspath(os.path.expanduser(capture))
        if not os.path.isfile(capture):
            raise ValueError(f"抓包文件不存在: {capture}")

        handshakes = wifi_mod.load_handshakes(capture, ssid)
        if not handshakes:
            raise ValueError("抓包里没有找到可用的握手")
        if any(h.sae for h in handshakes):
            raise ValueError("检测到 WPA3 SAE 握手，纯 Python 跑不动，请用 hashcat 或 hcxtools")

        cands = self._candidates(params)
        summary = "；".join(wifi_mod.describe(handshakes))
        job = self._new_job("wifi", f"WiFi {ssid}  {summary}")

        def maker() -> SearchJob:
            return SearchJob(
                cands,
                checker=lambda batch: wifi_mod.check_batch(batch, handshakes),
                workers=int(params.get("workers") or 0),
                chunk_size=8,
                use_processes=True,
            )

        threading.Thread(target=self._run, args=(job, maker), daemon=True).start()
        return job.id

    def start_archive(self, params: dict[str, Any]) -> str:
        path = (params.get("file") or "").strip()
        if not path:
            raise ValueError("必须选择压缩包")
        path = os.path.abspath(os.path.expanduser(path))
        if not os.path.isfile(path):
            raise ValueError(f"文件不存在: {path}")
        fmt = archives.detect_format(path)
        if fmt == "unknown":
            raise ValueError("不认识的压缩包格式")
        cands = self._candidates(params)
        job = self._new_job("archive", f"压缩包 {os.path.basename(path)}  格式 {fmt}")

        def maker() -> SearchJob:
            return SearchJob(
                cands,
                checker=lambda batch: archives.check_batch(batch, path),
                workers=int(params.get("workers") or 0),
                chunk_size=32,
                use_processes=True,
            )

        threading.Thread(target=self._run, args=(job, maker), daemon=True).start()
        return job.id

    def status(self, job_id: str) -> dict[str, Any]:
        job = self.jobs.get(job_id)
        if job is None:
            return {"state": "unknown", "message": "任务不存在"}
        return job.snapshot()

    def cancel(self, job_id: str) -> bool:
        job = self.jobs.get(job_id)
        if job is None or job.job is None:
            return False
        job.job.cancel()
        return True

    def open_in_finder(self, path: str) -> bool:
        """在文件管理器里定位文件。"""
        path = os.path.abspath(os.path.expanduser(path))
        if not os.path.exists(path):
            return False
        try:
            if sys.platform == "darwin":
                os.system(f'open -R "{path}"')
            elif sys.platform == "win32":
                os.startfile(os.path.dirname(path))  # type: ignore[attr-defined]
            else:
                return False
        except Exception:
            return False
        return True


def _saved_ftp(host: str, user: str) -> str | None:
    from ..osint import saved
    cred = saved.find_ftp_password(host, user)
    return cred.password if cred else None


def _saved_wifi(ssid: str) -> str | None:
    from ..osint import saved
    return saved.find_wifi_password(ssid)


def launch() -> int:
    """启动图形界面。"""
    try:
        import webview
    except ImportError:
        print("缺少 pywebview，先装一下: pip install pywebview", file=sys.stderr)
        return 1

    api = Api()
    window = webview.create_window(
        "passcrack",
        os.path.join(ASSETS, "index.html"),
        js_api=api,
        width=1080,
        height=760,
        min_size=(900, 640),
        background_color="#f5f5f7",
    )
    api.attach_window(window)
    webview.start(debug=False)
    return 0
