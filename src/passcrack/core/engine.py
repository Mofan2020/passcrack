"""搜索引擎：候选口令流 → 并行校验 → 进度与取消。

CPU 密集的任务（压缩包、WiFi）走进程池，I/O 密集的（FTP）走线程池。
父进程负责产生候选并按块分发，子进程只管校验一块，
这样口令空间再大也不会把内存撑爆，进度也能实时报。
"""

from __future__ import annotations

import multiprocessing as mp
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, ThreadPoolExecutor, wait
from dataclasses import dataclass, field

# 一个批次里最多放多少个候选口令
DEFAULT_CHUNK = 512

# 批次校验函数：收到一批候选，返回命中的那个（或 None）
BatchChecker = Callable[[Sequence[str]], "str | None"]


@dataclass
class Progress:
    tried: int = 0
    rate: float = 0.0
    elapsed: float = 0.0
    current: str | None = None
    found: str | None = None
    finished: bool = False
    cancelled: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def eta(self) -> float | None:
        if self.rate <= 0 or self.found:
            return None
        return None


class SearchJob:
    """一次搜索任务。

    checker 必须是可 pickle 的（进程池需要），因此用模块级函数加 partial，
    不要传绑定方法。
    """

    def __init__(
        self,
        candidates: Iterable[str],
        checker: BatchChecker,
        workers: int = 0,
        chunk_size: int = DEFAULT_CHUNK,
        use_processes: bool = True,
        on_progress: Callable[[Progress], None] | None = None,
    ) -> None:
        self.candidates = candidates
        self.checker = checker
        self.workers = workers or self._default_workers(use_processes)
        self.chunk_size = max(1, chunk_size)
        self.use_processes = use_processes
        self.on_progress = on_progress
        self._cancelled = False
        self._lock = mp.Lock()

    @staticmethod
    def _default_workers(use_processes: bool) -> int:
        n = mp.cpu_count() or 2
        if use_processes:
            return max(1, n - 1)
        return max(1, min(8, n))

    def cancel(self) -> None:
        self._cancelled = True

    # ------------------------------------------------------------------
    def _batches(self) -> Iterable[list[str]]:
        batch: list[str] = []
        for c in self.candidates:
            batch.append(c)
            if len(batch) >= self.chunk_size:
                yield batch
                batch = []
                if self._cancelled:
                    return
        if batch:
            yield batch

    def run(self) -> Progress:
        prog = Progress()
        t0 = time.monotonic()
        prog.elapsed = 0.0

        pool: ProcessPoolExecutor | ThreadPoolExecutor
        if self.use_processes:
            ctx = mp.get_context("spawn")
            pool = ProcessPoolExecutor(max_workers=self.workers, mp_context=ctx)
        else:
            pool = ThreadPoolExecutor(max_workers=self.workers)

        pending: set[Future] = set()
        stop = False
        try:
            for batch in self._batches():
                if self._cancelled:
                    break
                fut = pool.submit(self.checker, batch)
                pending.add(fut)
                # 同时在跑的任务别太多，否则父进程会堆积内存
                while len(pending) >= self.workers * 2:
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    for f in done:
                        try:
                            hit = f.result()
                        except Exception as exc:  # 单块失败不应该拖垮整个任务
                            prog.errors.append(f"{type(exc).__name__}: {exc}")
                            continue
                        if hit:
                            prog.found = hit
                            stop = True
                    if stop:
                        break
                if stop:
                    break
                prog.elapsed = time.monotonic() - t0
                prog.rate = prog.tried / prog.elapsed if prog.elapsed > 0 else 0.0
                if self.on_progress:
                    self.on_progress(prog)

            # 收尾：等剩下的跑完
            if not stop:
                while pending:
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    for f in done:
                        try:
                            hit = f.result()
                        except Exception as exc:
                            prog.errors.append(f"{type(exc).__name__}: {exc}")
                            continue
                        prog.tried += self.chunk_size
                        if hit:
                            prog.found = hit
                            stop = True
                            break
                    if stop:
                        break
        finally:
            for f in list(pending):
                f.cancel()
            pool.shutdown(wait=False, cancel_futures=True)

        prog.elapsed = time.monotonic() - t0
        prog.rate = prog.tried / prog.elapsed if prog.elapsed > 0 else 0.0
        prog.cancelled = self._cancelled
        prog.finished = True
        if self.on_progress:
            self.on_progress(prog)
        return prog


def human_rate(rate: float) -> str:
    if rate >= 1_000_000:
        return f"{rate / 1_000_000:.2f}M/s"
    if rate >= 1000:
        return f"{rate / 1000:.1f}k/s"
    return f"{rate:.0f}/s"


def human_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m}:{s:02d}"
