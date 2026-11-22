"""图形界面后端接口的测试。不开窗口，只测参数校验与任务分发。"""

from __future__ import annotations

import pytest

from passcrack.ui.app import Api


def test_info_carries_version_and_disclaimer():
    info = Api().info()
    assert info["version"]
    assert "免责" in info["disclaimer"]
    assert info["rules"]


def test_ftp_without_host_is_rejected():
    with pytest.raises(ValueError):
        Api().start_ftp({"user": "someone"})


def test_ftp_without_user_is_rejected():
    with pytest.raises(ValueError):
        Api().start_ftp({"host": "127.0.0.1"})


def test_wifi_without_ssid_is_rejected():
    with pytest.raises(ValueError):
        Api().start_wifi({"capture": "x.hc22000"})


def test_wifi_without_capture_is_rejected():
    with pytest.raises(ValueError):
        Api().start_wifi({"ssid": "Net"})


def test_wifi_with_missing_capture_file_is_rejected():
    with pytest.raises(ValueError):
        Api().start_wifi({"ssid": "Net", "capture": "/nonexistent/x.hc22000"})


def test_archive_without_file_is_rejected():
    with pytest.raises(ValueError):
        Api().start_archive({})


def test_archive_with_missing_file_is_rejected():
    with pytest.raises(ValueError):
        Api().start_archive({"file": "/nonexistent/x.zip"})


def test_archive_with_unknown_format_is_rejected(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"not an archive at all")
    with pytest.raises(ValueError):
        Api().start_archive({"file": str(p)})


def test_status_of_unknown_job():
    snap = Api().status("nope")
    assert snap["state"] == "unknown"


def test_cancel_of_unknown_job():
    assert Api().cancel("nope") is False


def test_saved_ftp_returns_none_for_unknown_host():
    assert Api().saved_ftp("no-such-host.invalid", "nobody") in (None, "")
