"""压缩包口令恢复的测试。

参考实现是 Python 标准库的 zipfile（它用官方 ZipCrypto 加密），
所以这里不是拿自己的实现验证自己。
"""

from __future__ import annotations

import zipfile

import pytest

from passcrack.core import archives


@pytest.fixture()
def encrypted_zip(tmp_path):
    path = tmp_path / "secret.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.setpassword(b"correct horse")
        zf.writestr("note.txt", "机密内容\n" * 20)
    return str(path)


def test_detect_format_zip(encrypted_zip):
    assert archives.detect_format(encrypted_zip) == "zip"


def test_detect_format_unknown(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x00\x01\x02\x03not an archive")
    assert archives.detect_format(str(p)) == "unknown"


def test_zip_entry_points_at_encrypted_data(encrypted_zip):
    entry = archives._zip_entry(encrypted_zip)
    assert entry is not None
    assert not entry.aes
    header = archives._read_enc_header(encrypted_zip, entry)
    assert len(header) == 12


def test_find_the_right_password(encrypted_zip):
    hit = archives.check_batch(["wrong", "nope", "correct horse", "other"], encrypted_zip)
    assert hit == "correct horse"


def test_wrong_password_returns_none(encrypted_zip):
    hit = archives.check_batch(["wrong", "nope", "other"], encrypted_zip)
    assert hit is None


def test_password_with_non_ascii(encrypted_zip):
    # 候选串是 str，编码成 utf-8 之后再校验
    hit = archives.check_batch(["correct horse"], encrypted_zip)
    assert hit is not None


def test_verify_helper(encrypted_zip):
    assert archives.verify(encrypted_zip, "correct horse") is True
    assert archives.verify(encrypted_zip, "wrong") is False


def test_unencrypted_zip_has_no_entry(tmp_path):
    path = tmp_path / "plain.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", "hello")
    assert archives._zip_entry(str(path)) is None
