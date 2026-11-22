"""压缩包口令恢复的测试。

加密的 zip 用的是 Info-ZIP 生成的固定样本（tests/fixtures），不是自己
加密出来的。这样测的是跟另一个实现对不对得上，而不是自己验自己。
"""

from __future__ import annotations

import os
import zipfile

import pytest

from passcrack.core import archives

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
ENCRYPTED_ZIP = os.path.join(FIXTURES, "secret-zipcrypto.zip")
FIXTURE_PASSWORD = "correct horse"


@pytest.fixture()
def encrypted_zip():
    if not os.path.exists(ENCRYPTED_ZIP):
        pytest.skip("缺少加密 zip 样本")
    return ENCRYPTED_ZIP


def test_detect_format_zip(encrypted_zip):
    assert archives.detect_format(encrypted_zip) == "zip"


def test_detect_format_unknown(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x00\x01\x02\x03not an archive")
    assert archives.detect_format(str(p)) == "unknown"


def test_fixture_is_really_encrypted(encrypted_zip):
    with zipfile.ZipFile(encrypted_zip) as zf:
        info = zf.infolist()[0]
    assert info.flag_bits & 0x1, "样本应当是加密的"
    assert info.compress_type == zipfile.ZIP_STORED


def test_zip_entry_points_at_encrypted_data(encrypted_zip):
    entry = archives._zip_entry(encrypted_zip)
    assert entry is not None
    assert not entry.aes
    header = archives._read_enc_header(encrypted_zip, entry)
    assert len(header) == 12


def test_find_the_right_password(encrypted_zip):
    hit = archives.check_batch(["wrong", "nope", FIXTURE_PASSWORD, "other"], encrypted_zip)
    assert hit == FIXTURE_PASSWORD


def test_wrong_password_returns_none(encrypted_zip):
    hit = archives.check_batch(["wrong", "nope", "other"], encrypted_zip)
    assert hit is None


def test_empty_candidate_list(encrypted_zip):
    assert archives.check_batch([], encrypted_zip) is None


def test_verify_helper(encrypted_zip):
    assert archives.verify(encrypted_zip, FIXTURE_PASSWORD) is True
    assert archives.verify(encrypted_zip, "wrong") is False


def test_unencrypted_zip_has_no_entry(tmp_path):
    path = tmp_path / "plain.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", "hello")
    assert archives._zip_entry(str(path)) is None


def test_check_batch_raises_on_unknown_format(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"not an archive")
    with pytest.raises(ValueError):
        archives.check_batch(["a"], str(p))
