"""WiFi 口令恢复（WPA2 / WPA3）。

支持两种抓包输入：

  .hc22000   hcxtools 的通用格式，一行一条记录
  .pcap/.cap 原始抓包，自己解析出 EAPOL 握手

校验方式：

  WPA2 四次握手   用 PBKDF2 推出 PMK，再算 PTK 与 MIC，跟抓包里的 MIC 比对。
                  这是可以离线完成的原生实现。
  WPA2 PMKID      被动抓到的 PMKID，验证同样只靠 PBKDF2。
  WPA3 SAE        密码猜测本身需要跑 SAE 协议，Python 实现不现实，
                  检测到之后交给 hcxtools / hashcat 处理。

纯 Python 的 PBKDF2 比 hashcat 慢两个数量级，这是语言限制，
所以这里在检测到外部工具时优先交给外部工具。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from typing import Iterable, Sequence

PBKDF2_ROUNDS = 4096


@dataclass
class Handshake:
    """一条握手记录。"""

    ssid: str
    bssid: bytes = b"\x00" * 6
    sta: bytes = b"\x00" * 6
    anonce: bytes = b""
    snonce: bytes = b""
    eapol2: bytes | None = None
    eapol3: bytes | None = None
    pmkid: bytes | None = None
    sae: bool = False
    source: str = ""

    @property
    def usable(self) -> bool:
        if self.sae:
            return False
        if self.pmkid:
            return True
        if self.eapol2 and self.anonce and self.snonce:
            return True
        return False


# ----------------------------------------------------------------------
# 密码学原语
# ----------------------------------------------------------------------
def derive_pmk(passphrase: str, ssid: str) -> bytes:
    """PBKDF2-HMAC-SHA1，4096 轮，32 字节。"""
    return hashlib.pbkdf2_hmac(
        "sha1", passphrase.encode("utf-8"), ssid.encode("utf-8"), PBKDF2_ROUNDS, 32
    )


def _prf512(key: bytes, label: bytes, data: bytes, outlen: int) -> bytes:
    """802.11 的 PRF，用 HMAC-SHA1 迭代。"""
    out = bytearray()
    counter = 0
    while len(out) < outlen:
        out += hmac.new(key, label + b"\x00" + data + bytes([counter]), hashlib.sha1).digest()
        counter += 1
    return bytes(out[:outlen])


def derive_ptk(pmk: bytes, aa: bytes, spa: bytes, anonce: bytes, snonce: bytes) -> bytes:
    """PTK = PRF-512(PMK, "Pairwise key expansion", min||max 的地址与 nonce)。"""
    data = b"".join(sorted([aa, spa])) + b"".join(sorted([anonce, snonce]))
    return _prf512(pmk, b"Pairwise key expansion", data, 64)


def compute_mic(ptk: bytes, eapol: bytes) -> bytes:
    """算 EAPOL-Key 帧的 MIC。帧里 MIC 字段要置零后再算。"""
    frame = bytearray(eapol)
    frame[80:96] = b"\x00" * 16
    return hmac.new(ptk[:16], bytes(frame), hashlib.sha1).digest()[:16]


def compute_pmkid(pmk: bytes, aa: bytes, spa: bytes, na: bytes, spi: int) -> bytes:
    """PMKID = Trunc(HMAC-SHA1(PMK, "PMK Name" || AA || SPA || NA || SPI))。"""
    data = b"PMK Name" + aa + spa + na + struct.pack("<Q", spi)
    return hmac.new(pmk, data, hashlib.sha1).digest()[:16]


# ----------------------------------------------------------------------
# hc22000 解析
# ----------------------------------------------------------------------
def _hexbytes(s: str) -> bytes:
    s = s.strip()
    if len(s) % 2:
        s = "0" + s
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


def parse_hc22000(path: str) -> list[Handshake]:
    """解析 hcxtools 的 hc22000 文件。"""
    out: list[Handshake] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("*")
            if len(parts) < 5 or parts[0] != "WIFI":
                continue
            _, ssid_hex, bssid_hex, sta_hex, payload = parts[:5]
            ssid = _decode_ssid(ssid_hex)
            hs = Handshake(
                ssid=ssid,
                bssid=_hexbytes(bssid_hex),
                sta=_hexbytes(sta_hex),
                source=path,
            )
            if len(hs.bssid) != 6:
                hs.bssid = b"\x00" * 6
            if len(hs.sta) != 6:
                hs.sta = b"\x00" * 6
            # payload 可能是 PMKID（32 个十六进制字符），也可能是 EAPOL
            if len(payload) == 32 and _hexbytes(payload):
                hs.pmkid = _hexbytes(payload)
            else:
                _parse_eapol_payload(hs, payload)
            out.append(hs)
    return out


def _decode_ssid(raw: str) -> str:
    """hc22000 里 SSID 是十六进制；少数工具直接写原文。"""
    b = _hexbytes(raw)
    if b:
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            return b.decode("utf-8", "replace")
    return raw


def _parse_eapol_payload(hs: Handshake, payload: str) -> None:
    """解析 hc22000 的 EAPOL 字段。

    里面最多四段，每段是 2 字节长度加 EAPOL 帧。EAPOL 帧的第一个字节
    是类型：0x03 是 EAPOL-Key，0x04 是 EAPOL-ASF alert。
    """
    try:
        blob = bytes.fromhex(payload)
    except ValueError:
        return
    i = 0
    msgs: list[bytes] = []
    while i + 2 <= len(blob):
        ln = struct.unpack(">H", blob[i:i + 2])[0]
        i += 2
        if i + ln > len(blob):
            break
        msgs.append(blob[i:i + ln])
        i += ln
    for idx, m in enumerate(msgs):
        if not m or m[0] != 0x03:
            continue
        # 帧结构：type(1) len(2) desc(1) keyinfo(2) keylen(2) replay(8)
        #          snonce(32) anonce(32) mic(16)
        if len(m) < 96:
            continue
        key_info = struct.unpack(">H", m[4:6])[0]
        snonce = m[16:48]
        anonce = m[48:80]
        # key_info 的第 3 位是「有 MIC」，第 2 位是「是消息 1」
        has_mic = bool(key_info & 0x0100)
        is_msg1 = bool(key_info & 0x0400)
        if idx == 0 and is_msg1 and not has_mic:
            continue
        if anonce.strip(b"\x00"):
            hs.anonce = anonce
        if snonce.strip(b"\x00"):
            hs.snonce = snonce
        if has_mic:
            if hs.eapol2 is None:
                hs.eapol2 = m
            elif hs.eapol3 is None:
                hs.eapol3 = m
        else:
            # 没有 MIC 的那段通常是客户端发出的消息 1，用来取 nonce
            if hs.eapol3 is None and hs.eapol2 is not None:
                hs.eapol3 = m
    if hs.eapol2 is not None and not hs.anonce:
        hs.anonce = hs.eapol2[48:80]
    if hs.eapol2 is not None and not hs.snonce:
        hs.snonce = hs.eapol2[16:48]


# ----------------------------------------------------------------------
# pcap 解析
# ----------------------------------------------------------------------
PCAP_MAGICS = {
    0xA1B2C3D4: ("<", 1),
    0xD4C3B2A1: (">", 1),
    0xA1B23C4D: ("<", 2),
    0x4D3CB2A1: (">", 2),
}

EAPOL_KEY_INFO = {
    0x008A: "M1",  # AP -> STA, 认证
    0x010A: "M2",  # STA -> AP, 认证
    0x008B: "M1",  # AP -> STA, 关联
    0x010B: "M2",  # STA -> AP, 关联
    0x008C: "M1",  # AP -> STA, 4 次握手
    0x010C: "M2",  # STA -> AP, 4 次握手
    0x008D: "M3",  # AP -> STA, 4 次握手
    0x010D: "M4",  # STA -> AP, 4 次握手
}


def parse_pcap(path: str) -> list[Handshake]:
    """从 pcap 里抽出 EAPOL 握手。"""
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 24:
        raise ValueError("抓包文件太短")
    magic = struct.unpack("<I", data[:4])[0]
    if magic not in PCAP_MAGICS:
        magic = struct.unpack(">I", data[:4])[0]
        if magic not in PCAP_MAGICS:
            raise ValueError("不是 pcap 文件（也可能是 pcapng，请先转成 pcap）")
    endian, _ = PCAP_MAGICS[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    frames: list[bytes] = []
    while off + 16 <= len(data):
        _, _, caplen, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if off + caplen > len(data):
            break
        frames.append(data[off:off + caplen])
        off += caplen

    ssids: dict[bytes, str] = {}
    eapols: list[tuple[bytes, bytes, bytes]] = []  # (src, dst, frame)
    for raw in frames:
        payload = raw
        if linktype == 127:  # radiotap
            if len(raw) < 4:
                continue
            rtlen = struct.unpack("<H", raw[2:4])[0]
            payload = raw[rtlen:]
        elif linktype == 105:  # 802.11
            pass
        elif linktype == 1:  # ethernet
            if len(raw) < 14:
                continue
            ethertype = struct.unpack(">H", raw[12:14])[0]
            if ethertype != 0x888E:
                continue
            payload = raw[14:]
            src = raw[6:12]
            dst = raw[0:6]
            eapols.append((src, dst, payload))
            continue
        else:
            continue

        if linktype == 105:
            if len(payload) < 24:
                continue
            fc = payload[0]
            fc_type = (fc >> 2) & 0x3
            fc_sub = fc & 0xF
            addr1 = payload[4:10]
            addr2 = payload[10:16]
            addr3 = payload[16:22]
            if fc_type == 0:  # 管理帧
                if fc_sub in (0x05, 0x08):  # beacon / probe response
                    sid = _ssid_from_beacon(payload[24:])
                    if sid:
                        ssids[addr2] = sid
                continue
            if fc_type != 2:  # 只看数据帧
                continue
            qos = bool(fc & 0x08)
            hdr = 24 + (2 if qos else 0)
            if len(payload) < hdr + 4:
                continue
            # 找 LLC/SNAP 里的 EAPOL
            llc = payload[hdr:]
            if len(llc) < 8 or llc[0:3] != b"\xaa\xaa\x03":
                continue
            if struct.unpack(">H", llc[6:8])[0] != 0x888E:
                continue
            eapols.append((addr2, addr3, llc[8:]))

    # 把 EAPOL 按 (BSSID, STA) 归类
    buckets: dict[tuple[bytes, bytes], list[bytes]] = {}
    for src, dst, frame in eapols:
        if len(frame) < 1 or frame[0] != 0x03:
            continue
        # BSSID 始终是三个地址里不等于 STA 的那个，这里用 src/dst 两种都存一份
        buckets.setdefault((dst, src), []).append(frame)
        buckets.setdefault((src, dst), []).append(frame)

    out: list[Handshake] = []
    seen: set[tuple[bytes, bytes, bytes]] = set()
    for (bssid, sta), frames in buckets.items():
        frames = sorted(set(frames), key=len, reverse=True)
        hs = Handshake(ssid=ssids.get(bssid, ""), bssid=bssid, sta=sta, source=path)
        for f in frames:
            if len(f) < 96:
                continue
            key_info = struct.unpack(">H", f[4:6])[0]
            has_mic = bool(key_info & 0x0100)
            is_msg1 = bool(key_info & 0x0400)
            if f[48:80].strip(b"\x00"):
                hs.anonce = f[48:80]
            if f[16:48].strip(b"\x00"):
                hs.snonce = f[16:48]
            if has_mic:
                if hs.eapol2 is None:
                    hs.eapol2 = f
                elif hs.eapol3 is None:
                    hs.eapol3 = f
            elif is_msg1 and hs.eapol3 is None:
                hs.eapol3 = f
        if hs.usable:
            key = (hs.bssid, hs.sta, hs.anonce)
            if key not in seen:
                seen.add(key)
                out.append(hs)
    return out


def _ssid_from_beacon(body: bytes) -> str | None:
    """从 beacon/probe 的信息元素里找 SSID。"""
    i = 0
    while i + 2 <= len(body):
        eid = body[i]
        elen = body[i + 1]
        data = body[i + 2:i + 2 + elen]
        if eid == 0:
            try:
                return data.decode("utf-8", "replace")
            except Exception:
                return None
        i += 2 + elen
    return None


# ----------------------------------------------------------------------
# 校验
# ----------------------------------------------------------------------
def check_candidate(hs: Handshake, candidate: str) -> bool:
    """一个口令对一条握手是否成立。"""
    pmk = derive_pmk(candidate, hs.ssid)
    if hs.pmkid:
        for spi in (0, 1, int.from_bytes(hs.pmkid[:8], "little")):
            if compute_pmkid(pmk, hs.bssid, hs.sta, hs.anonce, spi) == hs.pmkid:
                return True
        return False
    if hs.eapol2 is None or not hs.anonce or not hs.snonce:
        return False
    ptk = derive_ptk(pmk, hs.bssid, hs.sta, hs.anonce, hs.snonce)
    if compute_mic(ptk, hs.eapol2) == hs.eapol2[80:96]:
        return True
    if hs.eapol3 is not None and len(hs.eapol3) >= 96:
        if compute_mic(ptk, hs.eapol3) == hs.eapol3[80:96]:
            return True
    return False


def check_batch(candidates: Sequence[str], handshakes: Sequence[Handshake]) -> str | None:
    """一批候选里找出能通过握手的口令。"""
    for cand in candidates:
        for hs in handshakes:
            if check_candidate(hs, cand):
                return cand
    return None


def load_handshakes(path: str, ssid: str = "") -> list[Handshake]:
    """按扩展名选解析器。抓包里没有 SSID 时用传入的补上。"""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".hc22000", ".hcx", ".txt"):
        hs_list = parse_hc22000(path)
    else:
        hs_list = parse_pcap(path)
    if ssid:
        for hs in hs_list:
            if not hs.ssid or hs.ssid == ssid:
                hs.ssid = ssid
    return hs_list


# ----------------------------------------------------------------------
# 外部工具
# ----------------------------------------------------------------------
def external_tools() -> dict[str, str | None]:
    return {
        "hashcat": shutil.which("hashcat"),
        "hcxpcapngtool": shutil.which("hcxpcapngtool"),
        "john": shutil.which("john"),
    }


def delegate_to_hashcat(capture: str, wordlist: str, ssid: str = "") -> str | None:
    """把抓包交给 hashcat 跑（mode 22000）。没有 hashcat 就返回 None。"""
    hc = shutil.which("hashcat")
    if not hc:
        return None
    cmd = [hc, "-m", "22000", "-a", "0", "--quiet", capture]
    if wordlist:
        cmd.append(wordlist)
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=3600)
    except Exception:
        return None
    out = (r.stdout or b"").decode("utf-8", "replace")
    for line in out.splitlines():
        if ":" in line:
            candidate = line.split(":", 1)[1].strip()
            if candidate:
                return candidate
    return None


def suggest_capture_convert(capture: str) -> str | None:
    """hcxtools 的 hcxpcapngtool 能把 pcapng 转成 hc22000。"""
    tool = shutil.which("hcxpcapngtool")
    if not tool:
        return None
    out = capture + ".hc22000"
    try:
        subprocess.run([tool, "-o", out, capture], capture_output=True, timeout=600)
    except Exception:
        return None
    return out if os.path.exists(out) else None


def describe(handshakes: Iterable[Handshake]) -> list[str]:
    """给界面/命令行看的握手摘要。"""
    lines = []
    for hs in handshakes:
        kind = "SAE(WPA3)" if hs.sae else ("PMKID" if hs.pmkid else "四次握手")
        lines.append(
            "SSID=%s  BSSID=%s  STA=%s  方式=%s"
            % (hs.ssid or "?", hs.bssid.hex(":"), hs.sta.hex(":"), kind)
        )
    return lines
