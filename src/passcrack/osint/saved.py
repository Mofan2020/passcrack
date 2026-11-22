"""从操作系统里读取已保存的凭据。

这是最实用的恢复路径：自己的 FTP 客户端、WiFi、邮件客户端都会把密码
存进系统凭据库，拿到它比在线暴力尝试快得多，也温和得多。

实现一律走系统正式 API（macOS Security.framework、Windows Credential
Manager 与 wlanapi），不解析命令输出，避免本地化差异带来的误判。
"""

from __future__ import annotations

import ctypes
import ctypes.util
import sys
from dataclasses import dataclass

OS_KEYCHAIN_ERR = -25300


@dataclass
class SavedCredential:
    service: str
    account: str
    password: str
    kind: str = ""


def is_macos() -> bool:
    return sys.platform == "darwin"


def is_windows() -> bool:
    return sys.platform == "win32"


# ----------------------------------------------------------------------
# macOS
# ----------------------------------------------------------------------
def _load_security():
    path = "/System/Library/Frameworks/Security.framework/Security"
    return ctypes.cdll.LoadLibrary(path)


def macos_find_generic(service: str, account: str | None = None) -> SavedCredential | None:
    """按服务名与账户名找钥匙串里的通用口令。"""
    lib = _load_security()
    lib.SecKeychainFindGenericPassword.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p,
        ctypes.c_uint32, ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    lib.SecKeychainFindGenericPassword.restype = ctypes.c_int32
    lib.SecKeychainItemFreeContent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.SecKeychainItemFreeContent.restype = ctypes.c_int32

    pwd_len = ctypes.c_uint32(0)
    pwd_data = ctypes.c_void_p()
    item = ctypes.c_void_p()
    svc = service.encode("utf-8")
    acc = account.encode("utf-8") if account else None
    status = lib.SecKeychainFindGenericPassword(
        None, len(svc), svc,
        len(acc) if acc else 0, acc,
        ctypes.byref(pwd_len), ctypes.byref(pwd_data), ctypes.byref(item),
    )
    if status != 0:
        return None
    try:
        raw = ctypes.string_at(pwd_data, pwd_len.value)
        return SavedCredential(service=service, account=account or "", password=raw.decode("utf-8", "replace"))
    finally:
        lib.SecKeychainItemFreeContent(None, pwd_data)


def macos_find_internet(server: str, account: str | None = None) -> SavedCredential | None:
    """按服务器名找钥匙串里的互联网口令（FTP、SMTP 之类）。"""
    lib = _load_security()
    lib.SecKeychainFindInternetPassword.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p,
        ctypes.c_uint32, ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    lib.SecKeychainFindInternetPassword.restype = ctypes.c_int32
    lib.SecKeychainItemFreeContent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.SecKeychainItemFreeContent.restype = ctypes.c_int32

    pwd_len = ctypes.c_uint32(0)
    pwd_data = ctypes.c_void_p()
    item = ctypes.c_void_p()
    srv = server.encode("utf-8")
    acc = account.encode("utf-8") if account else None
    status = lib.SecKeychainFindInternetPassword(
        None, len(srv), srv,
        len(acc) if acc else 0, acc,
        ctypes.byref(pwd_len), ctypes.byref(pwd_data), ctypes.byref(item),
    )
    if status != 0:
        return None
    try:
        raw = ctypes.string_at(pwd_data, pwd_len.value)
        return SavedCredential(service=server, account=account or "", password=raw.decode("utf-8", "replace"))
    finally:
        lib.SecKeychainItemFreeContent(None, pwd_data)


def macos_wifi_password(ssid: str) -> str | None:
    """macOS 把 WiFi 口令存在钥匙串里，服务名是 AirPort Network Password。"""
    cred = macos_find_generic("AirPort Network Password", ssid)
    if cred:
        return cred.password
    cred = macos_find_generic("AirPort Network Password")
    if cred and cred.account == ssid:
        return cred.password
    return None


# ----------------------------------------------------------------------
# Windows
# ----------------------------------------------------------------------
class CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("TargetName", ctypes.c_wchar_p),
        ("Comment", ctypes.c_wchar_p),
        ("LastWritten", ctypes.c_uint64),
        ("CredentialBlobSize", ctypes.c_uint32),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", ctypes.c_uint32),
        ("AttributeCount", ctypes.c_uint32),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", ctypes.c_wchar_p),
        ("UserName", ctypes.c_wchar_p),
    ]


def windows_read_credential(target_name: str) -> SavedCredential | None:
    """按目标名读 Windows 凭据管理器里的通用凭据。"""
    advapi = ctypes.windll.advapi32
    pcred = ctypes.POINTER(CREDENTIALW)()
    found = advapi.CredReadW(target_name, 1, 0, ctypes.byref(pcred))
    if not found:
        return None
    try:
        c = pcred.contents
        blob = ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize)
        return SavedCredential(service=target_name, account=c.UserName or "",
                               password=blob.decode("utf-16-le", "replace").rstrip("\x00"))
    finally:
        advapi.CredFree(pcred)


def windows_enumerate(prefix: str = "") -> list[SavedCredential]:
    """列出凭据管理器里的通用凭据。"""
    advapi = ctypes.windll.advapi32
    pcred = ctypes.POINTER(CREDENTIALW)()
    count = ctypes.c_uint32(0)
    if not advapi.CredEnumerateW("Generic", 0, ctypes.byref(count), ctypes.byref(pcred)):
        return []
    out: list[SavedCredential] = []
    try:
        for i in range(count.value):
            c = pcred[i]
            if prefix and not (c.TargetName or "").lower().startswith(prefix.lower()):
                continue
            blob = ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize)
            out.append(SavedCredential(service=c.TargetName or "", account=c.UserName or "",
                                       password=blob.decode("utf-16-le", "replace").rstrip("\x00")))
    finally:
        advapi.CredFree(pcred)
    return out


WLAN_PROFILE_GET_PLAINTEXT_KEY = 0x00000008


def windows_wifi_password(ssid: str) -> str | None:
    """读 Windows WLAN 配置里的明文口令（需要管理员权限）。"""
    import uuid

    wlan = ctypes.windll.wlanapi
    wlanapi = ctypes.windll.wlanapi

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_ulong),
            ("Data2", ctypes.c_ushort),
            ("Data3", ctypes.c_ushort),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    WLAN_INTERFACE_INFO_LIST = ctypes.Structure  # 占位，下面用动态结构

    # 先用简单办法：枚举接口拿到 GUID，再取配置
    class WLAN_INTERFACE_INFO(ctypes.Structure):
        _fields_ = [
            ("InterfaceGuid", GUID),
            ("strInterfaceDescription", ctypes.c_wchar * 256),
            ("isState", ctypes.c_uint32),
        ]

    class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
        _fields_ = [
            ("dwNumberOfItems", ctypes.c_uint32),
            ("dwIndex", ctypes.c_uint32),
            ("InterfaceInfo", WLAN_INTERFACE_INFO * 1),
        ]

    handle = ctypes.c_void_p()
    neg = ctypes.c_int32()
    if wlanapi.WlanOpenHandle(2, None, ctypes.byref(handle), None) != 0:
        return None
    try:
        iflist = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        if wlanapi.WlanEnumInterfaces(handle, None, ctypes.byref(iflist)) != 0:
            return None
        try:
            n = iflist.contents.dwNumberOfItems
            base = ctypes.addressof(iflist.contents.InterfaceInfo)
            size = ctypes.sizeof(WLAN_INTERFACE_INFO)
            for i in range(n):
                info = ctypes.cast(base + i * size, ctypes.POINTER(WLAN_INTERFACE_INFO)).contents
                guid_str = str(uuid.UUID(bytes_le=bytes(info.InterfaceGuid)))
                pdata = ctypes.c_void_p()
                pstr = ctypes.c_wchar_p()
                dwsize = ctypes.c_uint32(0)
                ptype = ctypes.c_int32()
                rc = wlanapi.WlanGetProfile(handle, ctypes.byref(info.InterfaceGuid),
                                           ssid, None,
                                           WLAN_PROFILE_GET_PLAINTEXT_KEY,
                                           ctypes.byref(pstr), ctypes.byref(pdata),
                                           ctypes.byref(dwsize), ctypes.byref(ptype), None)
                if rc != 0:
                    continue
                try:
                    xml = ctypes.wstring_at(pstr) if pstr else ""
                    pw = _extract_wlan_key(xml)
                    if pw:
                        return pw
                finally:
                    if pdata:
                        wlanapi.WlanFreeMemory(pdata)
        finally:
            wlanapi.WlanFreeMemory(iflist)
    finally:
        wlanapi.WlanCloseHandle(handle, None)
    return None


def _extract_wlan_key(xml: str) -> str | None:
    """从 WLAN 配置 XML 里取 <keyMaterial>。"""
    tag = "<keyMaterial>"
    start = xml.find(tag)
    if start < 0:
        return None
    start += len(tag)
    end = xml.find("</keyMaterial>", start)
    if end < 0:
        return None
    return xml[start:end]


# ----------------------------------------------------------------------
# 统一入口
# ----------------------------------------------------------------------
def find_ftp_password(host: str, username: str = "") -> SavedCredential | None:
    """找本机保存的 FTP 密码。"""
    if is_macos():
        cred = macos_find_internet(host, username or None)
        if cred:
            return cred
        for svc in (f"ftp://{host}", host):
            cred = macos_find_generic(svc, username or None)
            if cred:
                return cred
        return None
    if is_windows():
        for target in (f"ftp://{host}", host, f"LEGACY_FTP:{host}"):
            cred = windows_read_credential(target)
            if cred:
                return cred
        for cred in windows_enumerate():
            if host.lower() in cred.service.lower():
                if not username or cred.account.lower() == username.lower():
                    return cred
    return None


def find_wifi_password(ssid: str) -> str | None:
    """找本机保存的 WiFi 密码。"""
    if is_macos():
        return macos_wifi_password(ssid)
    if is_windows():
        return windows_wifi_password(ssid)
    return None


def platform_support() -> dict[str, bool]:
    return {
        "macos_keychain": is_macos(),
        "windows_credential_manager": is_windows(),
        "windows_wlan": is_windows(),
    }
