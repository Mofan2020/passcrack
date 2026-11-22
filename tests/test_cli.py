"""命令行入口的测试。"""

from __future__ import annotations

import pytest

from passcrack import cli


def test_no_arguments_launches_the_gui(monkeypatch):
    called = {}

    def fake_launch():
        called["yes"] = True
        return 0

    monkeypatch.setattr("passcrack.ui.app.launch", fake_launch)
    assert cli.main([]) == 0
    assert called.get("yes") is True


def test_version_subcommand(capsys):
    assert cli.main(["version"]) == 0
    assert "passcrack" in capsys.readouterr().out


def test_rules_subcommand_lists_rules(capsys):
    assert cli.main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "digits" in out
    assert "leet" in out


def test_ftp_without_host_is_rejected():
    with pytest.raises(SystemExit):
        cli.main(["ftp", "--user", "someone"])


def test_ftp_without_user_is_rejected():
    with pytest.raises(SystemExit):
        cli.main(["ftp", "--host", "127.0.0.1"])


def test_wifi_without_ssid_is_rejected():
    with pytest.raises(SystemExit):
        cli.main(["wifi", "--capture", "x.hc22000"])


def test_archive_requires_a_file():
    with pytest.raises(SystemExit):
        cli.main(["archive"])


def test_unknown_rule_is_rejected():
    with pytest.raises(SystemExit):
        cli.main(["archive", "--file", "x.zip", "--rule", "nope"])


def test_saved_without_target_is_rejected():
    with pytest.raises(SystemExit):
        cli.main(["saved"])


def test_help_exits_with_zero():
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
