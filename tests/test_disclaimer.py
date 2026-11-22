"""免责声明的守卫测试。

用户要求「无论 CLI 还是 UI，免责申明给我拉满」，所以这里把几个入口
都钉住：以后谁动了文案或者漏了某个入口，这里会红。
"""

from __future__ import annotations

import io
import os
from contextlib import redirect_stdout

from passcrack import disclaimer
from passcrack.cli import _print_banner
from passcrack.ui.app import ASSETS, Api

REQUIRED_PHRASES = [
    "授权",
    "法律责任",
    "未经授权",
    "不包含",
    "不提供",
]


def test_long_disclaimer_covers_the_required_points():
    for phrase in REQUIRED_PHRASES:
        assert phrase in disclaimer.LONG, phrase


def test_long_disclaimer_is_long_enough():
    # 「拉满」的意思是：光短声明不够用
    assert len(disclaimer.LONG) > 600


def test_short_disclaimer_mentions_authorization():
    assert "授权" in disclaimer.SHORT
    assert "法律责任" in disclaimer.SHORT


def test_cli_banner_prints_the_full_disclaimer():
    buf = io.StringIO()
    with redirect_stdout(buf):
        _print_banner()
    text = buf.getvalue()
    assert "免责声明" in text
    for phrase in REQUIRED_PHRASES:
        assert phrase in text, phrase


def _read_asset(name: str) -> str:
    with open(os.path.join(ASSETS, name), encoding="utf-8") as fh:
        return fh.read()


def test_ui_html_shows_a_disclaimer_banner():
    html = _read_asset("index.html")
    assert "免责" in html


def test_ui_js_shows_a_disclaimer_banner():
    js = _read_asset("app.js")
    assert "disclaimer" in js


def test_ui_api_exposes_the_disclaimer():
    info = Api().info()
    assert info["disclaimer"] == disclaimer.LONG
    assert info["short"] == disclaimer.SHORT
    assert "授权" in info["ack"]


def test_ui_requires_the_acknowledgement_before_running():
    html = _read_asset("index.html")
    js = _read_asset("app.js")
    assert 'id="ack"' in html
    assert '$("#ack").checked' in js
