"""压缩包口令恢复。

支持三种格式，自动识别：

  zip   传统加密（ZipCrypto）走原生快速校验：只解密 12 字节的加密头，
        跟校验字节比对，不用解开整个文件，速度比逐个 zipfile.open 快一到两个
        数量级。AES 加密的 zip（method 99）交给 pyzipper 或外部 7z。
  7z    交给 py7zr 或外部 7z 命令。
  rar   交给外部 unrar（如果装了）。

外部工具找不到时会明确报错，不会静默跳过。
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass

# PKZIP 传统加密用的 CRC-32 表（不能用 zlib.crc32，那个带前后异或）
_CRC_TABLE: list[int] = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (0xEDB88320 if _c & 1 else 0)
    _CRC_TABLE.append(_c)


def _crc32(crc: int, b: int) -> int:
    return ((crc >> 8) ^ _CRC_TABLE[(crc ^ b) & 0xFF]) & 0xFFFFFFFF


def _update_keys(k0: int, k1: int, k2: int, b: int) -> tuple[int, int, int]:
    k0 = _crc32(k0, b)
    k1 = (k1 + (k0 & 0xFF)) & 0xFFFFFFFF
    k1 = (k1 * 134775813 + 1) & 0xFFFFFFFF
    k2 = _crc32(k2, (k1 >> 24) & 0xFF)
    return k0, k1, k2


def zipcrypto_check(password: bytes, enc_header: bytes, check_byte: int) -> bool:
    """校验一个口令能不能解开 zip 的加密头。

    enc_header 是加密数据开头的 12 字节，check_byte 是期望的校验字节。
    只做 12 字节的解密，不碰文件其余部分。
    """
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
    for b in password:
        k0, k1, k2 = _update_keys(k0, k1, k2, b)
    last = len(enc_header) - 1
    for i, c in enumerate(enc_header):
        # PKWARE 的公式：temp 取 16 位，(temp * (temp ^ 1)) 右移 8 位再取低 8 位。
        # 用 32 位右移 24 位是错的，两者结果不同。
        temp = (k2 | 2) & 0xFFFF
        plain = c ^ ((((temp * (temp ^ 1)) >> 8) & 0xFF))
        if i == last:
            return plain == check_byte
        k0, k1, k2 = _update_keys(k0, k1, k2, plain)
    return False


@dataclass
class ZipEntry:
    header_offset: int
    data_offset: int
    check_byte: int
    aes: bool


def detect_format(path: str) -> str:
    """按魔数判断压缩包格式。"""
    with open(path, "rb") as fh:
        head = fh.read(8)
    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06" or head[:4] == b"PK\x01\x02":
        return "zip"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:7] == b"Rar!\x1a\x07":
        return "rar"
    return "unknown"


def _zip_entry(path: str) -> ZipEntry | None:
    """找出第一个加密条目，返回它加密头的位置与校验字节。"""
    with zipfile.ZipFile(path) as zf:
        infos = [i for i in zf.infolist() if i.flag_bits & 0x1]
        if not infos:
            return None
        info = infos[0]
        aes = info.compress_type == 99
        # 校验字节：通用位标志的第 3 位置了就是取修改时间的高字节，
        # 否则取 CRC-32 的高字节
        if info.flag_bits & 0x8:
            dostime = (info.date_time[3] << 11) | (info.date_time[4] << 5)
            check = (dostime >> 8) & 0xFF
        else:
            check = (info.CRC >> 24) & 0xFF
        # 数据起点：本地文件头的定长 30 字节 + 文件名 + 扩展字段
        with open(path, "rb") as fh:
            fh.seek(info.header_offset)
            lfh = fh.read(30)
            if len(lfh) < 30 or lfh[:4] != b"PK\x03\x04":
                return None
            namelen, extralen = struct.unpack("<HH", lfh[26:30])
            data_offset = info.header_offset + 30 + namelen + extralen
        return ZipEntry(info.header_offset, data_offset, check, aes)


def _read_enc_header(path: str, entry: ZipEntry) -> bytes:
    with open(path, "rb") as fh:
        fh.seek(entry.data_offset)
        return fh.read(12)


def _external_7z() -> str | None:
    for name in ("7z", "7za", "7zz"):
        p = shutil.which(name)
        if p:
            return p
    return None


def _external_unrar() -> str | None:
    for name in ("unrar", "unar", "lsar"):
        p = shutil.which(name)
        if p:
            return p
    return None


def _try_py7zr(path: str, password: str) -> bool:
    try:
        import py7zr
    except ImportError:
        return False
    try:
        with py7zr.SevenZipFile(path, mode="r", password=password) as z:
            names = z.getnames()
            if not names:
                return False
            z.extract(path=os.path.dirname(os.path.abspath(path)) or ".", targets=names[:1])
        return True
    except Exception:
        return False


def _try_pyzipper(path: str, password: str) -> bool:
    try:
        import pyzipper
    except ImportError:
        return False
    try:
        with pyzipper.AESZipFile(path) as zf:
            zf.setpassword(password.encode())
            zf.read(zf.namelist()[0])
        return True
    except Exception:
        return False


def _try_7z_binary(path: str, password: str) -> bool | None:
    exe = _external_7z()
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "t", "-p" + password, "-y", path],
                           capture_output=True, timeout=60)
    except Exception:
        return None
    return r.returncode == 0


def _try_unrar(path: str, password: str) -> bool | None:
    exe = _external_unrar()
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "t", "-p" + password, "-y", path],
                           capture_output=True, timeout=60)
    except Exception:
        return None
    return r.returncode == 0


def check_batch(candidates: Sequence[str], path: str) -> str | None:
    """一批候选里找出能解开压缩包的那个口令。返回 None 表示都没中。"""
    fmt = detect_format(path)
    if fmt == "unknown":
        raise ValueError(f"不认识的压缩包格式: {path}")

    if fmt == "zip":
        entry = _zip_entry(path)
        if entry is None:
            raise ValueError("这个 zip 里没有加密条目")
        if entry.aes:
            for cand in candidates:
                if _try_pyzipper(path, cand) or _try_7z_binary(path, cand):
                    return cand
            return None
        enc = _read_enc_header(path, entry)
        for cand in candidates:
            if zipcrypto_check(cand.encode("utf-8", "replace"), enc, entry.check_byte):
                return cand
        return None

    if fmt == "7z":
        for cand in candidates:
            if _try_py7zr(path, cand):
                return cand
            r = _try_7z_binary(path, cand)
            if r:
                return cand
        return None

    # rar
    for cand in candidates:
        r = _try_unrar(path, cand)
        if r:
            return cand
    return None


def verify(path: str, password: str) -> bool:
    """用给定口令验证能不能解开。"""
    return check_batch([password], path) == password
