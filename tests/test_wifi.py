"""WiFi 口令恢复的测试。

握手数据在测试里按 802.11i 的公式独立构造，不调用被测模块的推导函数，
免得自己算自己、自己验自己。
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from passcrack.core import wifi

PASSPHRASE = "my wifi secret"
SSID = "TestNet"
BSSID = bytes.fromhex("001122334455")
STA = bytes.fromhex("66778899aabb")


def _prf512(key: bytes, label: bytes, data: bytes, outlen: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < outlen:
        out += hmac.new(key, label + b"\x00" + data + bytes([counter]), hashlib.sha1).digest()
        counter += 1
    return out[:outlen]


def _ptk(pmk: bytes) -> bytes:
    data = b"".join(sorted([BSSID, STA])) + b"".join(sorted([ANONCE, SNONCE]))
    return _prf512(pmk, b"Pairwise key expansion", data, 64)


def _eapol_frame(anonce: bytes, snonce: bytes, mic: bytes) -> bytes:
    """构造一条 EAPOL-Key 帧。MIC 位于偏移 80。"""
    body = bytearray()
    body += bytes([0x03])              # EAPOL-Key
    body += struct.pack(">H", 92)      # body 长度
    body += bytes([0x02])              # key descriptor: RSN
    body += struct.pack(">H", 0x010A)  # key info: 消息 2，带 MIC
    body += struct.pack(">H", 16)      # key length
    body += b"\x00" * 8                # replay counter
    body += snonce
    body += anonce
    body += mic
    return bytes(body)


ANONCE = bytes(range(32))
SNONCE = bytes(range(32, 64))


def _make_handshake() -> wifi.Handshake:
    pmk = hashlib.pbkdf2_hmac("sha1", PASSPHRASE.encode(), SSID.encode(), 4096, 32)
    ptk = _ptk(pmk)
    blank = _eapol_frame(ANONCE, SNONCE, b"\x00" * 16)
    mic = hmac.new(ptk[:16], blank, hashlib.sha1).digest()[:16]
    frame = _eapol_frame(ANONCE, SNONCE, mic)
    return wifi.Handshake(
        ssid=SSID,
        bssid=BSSID,
        sta=STA,
        anonce=ANONCE,
        snonce=SNONCE,
        eapol2=frame,
    )


def test_correct_passphrase_is_found():
    hs = _make_handshake()
    assert wifi.check_candidate(hs, PASSPHRASE) is True


def test_wrong_passphrase_is_rejected():
    hs = _make_handshake()
    assert wifi.check_candidate(hs, "not it") is False


def test_check_batch_returns_the_hit():
    hs = _make_handshake()
    hit = wifi.check_batch(["aaa", "bbb", PASSPHRASE, "ccc"], [hs])
    assert hit == PASSPHRASE


def test_check_batch_returns_none_when_nothing_matches():
    hs = _make_handshake()
    assert wifi.check_batch(["aaa", "bbb"], [hs]) is None


def test_ssid_matters():
    hs = _make_handshake()
    hs.ssid = "OtherNet"
    assert wifi.check_candidate(hs, PASSPHRASE) is False


def test_parse_hc22000_pmkid_record(tmp_path):
    pmkid = "00112233445566778899aabbccddeeff"
    p = tmp_path / "a.hc22000"
    p.write_text(f"WIFI*{SSID.encode().hex()}*{BSSID.hex()}*{STA.hex()}*{pmkid}\n",
                 encoding="utf-8")
    handshakes = wifi.parse_hc22000(str(p))
    assert len(handshakes) == 1
    hs = handshakes[0]
    assert hs.ssid == SSID
    assert hs.pmkid == bytes.fromhex(pmkid)
    assert hs.usable is True


def test_parse_hc22000_eapol_record(tmp_path):
    hs_src = _make_handshake()
    frame = hs_src.eapol2 or b""
    payload = struct.pack(">H", len(frame)).hex() + frame.hex()
    p = tmp_path / "b.hc22000"
    p.write_text(f"WIFI*{SSID.encode().hex()}*{BSSID.hex()}*{STA.hex()}*{payload}\n",
                 encoding="utf-8")
    handshakes = wifi.parse_hc22000(str(p))
    assert len(handshakes) == 1
    hs = handshakes[0]
    assert hs.ssid == SSID
    assert hs.anonce == ANONCE
    assert hs.snonce == SNONCE
    assert hs.eapol2 is not None
    assert wifi.check_candidate(hs, PASSPHRASE) is True


def test_load_handshakes_dispatches_on_extension(tmp_path):
    p = tmp_path / "c.hc22000"
    p.write_text(f"WIFI*{SSID.encode().hex()}*{BSSID.hex()}*{STA.hex()}*\n", encoding="utf-8")
    handshakes = wifi.load_handshakes(str(p), "Filled")
    assert handshakes[0].ssid == "Filled"


def test_describe_mentions_ssid():
    hs = _make_handshake()
    text = wifi.describe([hs])[0]
    assert SSID in text
    assert "四次握手" in text


def test_pmkid_check_uses_the_same_pmk():
    """PMKID 记录也要能验出来。"""
    pmk = hashlib.pbkdf2_hmac("sha1", PASSPHRASE.encode(), SSID.encode(), 4096, 32)
    data = b"PMK Name" + BSSID + STA + b"\x00" * 8 + struct.pack("<Q", 0)
    pmkid = hmac.new(pmk, data, hashlib.sha1).digest()[:16]
    hs = wifi.Handshake(ssid=SSID, bssid=BSSID, sta=STA, pmkid=pmkid)
    assert wifi.check_candidate(hs, PASSPHRASE) is True
    assert wifi.check_candidate(hs, "wrong") is False
