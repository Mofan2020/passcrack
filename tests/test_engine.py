"""搜索引擎的测试。"""

from __future__ import annotations

from passcrack.core.engine import SearchJob, human_duration, human_rate


def _checker(candidates):
    for c in candidates:
        if c == "needle":
            return c
    return None


def test_finds_the_candidate():
    job = SearchJob(iter(["aaa", "bbb", "needle", "ccc"]), _checker,
                    workers=1, chunk_size=2, use_processes=False)
    prog = job.run()
    assert prog.found == "needle"
    assert prog.finished is True


def test_reports_not_found():
    job = SearchJob(iter(["aaa", "bbb"]), _checker, workers=1, chunk_size=2,
                    use_processes=False)
    prog = job.run()
    assert prog.found is None
    assert prog.tried >= 2


def test_cancellation_stops_early():
    def cancel_after(prog):
        job.cancel()

    job = SearchJob(iter(f"c{i}" for i in range(100000)), _checker,
                    workers=1, chunk_size=10, use_processes=False,
                    on_progress=cancel_after)
    prog = job.run()
    assert prog.cancelled is True
    assert prog.tried < 100000


def test_progress_callback_is_called():
    seen = []
    job = SearchJob(iter(["a", "b", "c", "d"]), _checker, workers=1, chunk_size=1,
                    use_processes=False, on_progress=lambda p: seen.append(p.tried))
    job.run()
    assert seen


def test_errors_are_captured_not_raised():
    def boom(candidates):
        raise ValueError("炸了")

    job = SearchJob(iter(["a", "b"]), boom, workers=1, chunk_size=2, use_processes=False)
    prog = job.run()
    assert prog.found is None
    assert prog.errors


def test_human_rate():
    assert human_rate(0) == "0/s"
    assert "M/s" in human_rate(2_500_000)
    assert "k/s" in human_rate(2500)
    assert human_rate(12) == "12/s"


def test_human_duration():
    assert human_duration(0) == "0:00"
    assert human_duration(61) == "1:01"
    assert human_duration(3661) == "1:01:01"
