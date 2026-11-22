"""从操作系统里读取已保存的凭据。

这是最实用的恢复路径：自己的 FTP 客户端、WiFi、邮件客户端都会把密码
存进系统凭据库，拿到它比在线暴力尝试快得多，也温和得多。

实现一律走系统正式 API（macOS Security.framework、Windows Credential
Manager 与 wlanapi），不解析命令输出，避免本地化差异带来的误判。

macOS 这边用的是现代的 SecItemCopyMatching，不是旧的
SecKeychainFindInternetPassword：后者在无登录会话的环境里会直接崩掉进程。
"""

from __future__ import annotations

import ctypes
import sys
from dataclasses import dataclass

CFSTR = ctypes.c_void_p
CFIndex = ctypes.c_long
K_CF_STRING_ENCODING_UTF8 = 0x08000100

ERR_SEC_ITEM_NOT_FOUND = -25300
ERR_SEC_SUCCESS = 0

K_SEC_CLASS = "class"
K_SEC_CLASS_GENERIC_PASSWORD = "genp"
K_SEC_CLASS_INTERNET_PASSWORD = "inet"
K_SEC_ATTR_SERVICE = "attr_service"
K_SEC_ATTR_ACCOUNT = "attr_account"
K_SEC_ATTR_SERVER = "attr_server"
K_SEC_RETURN_DATA = "return_data"
K_SEC_MATCH_LIMIT = "match_limit"
K_SEC_MATCH_LIMIT_ONE = "one"


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
_cf = None
_sec = None


def _load_cf():
    global _cf
    if _cf is None:
        lib = ctypes.cdll.LoadLibrary(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        )
        lib.CFStringCreateWithCString.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int32, ctypes.c_void_p
        ]
        lib.CFStringCreateWithCString.restype = CFSTR
        lib.CFDataGetBytePtr.argtypes = [CFSTR]
        lib.CFDataGetBytePtr.restype = ctypes.c_void_p
        lib.CFDataGetLength.argtypes = [CFSTR]
        lib.CFDataGetLength.restype = CFIndex
        lib.CFDictionaryCreate.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(CFSTR),
            ctypes.POINTER(CFSTR),
            CFIndex,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        lib.CFDictionaryCreate.restype = CFSTR
        lib.CFRelease.argtypes = [ctypes.c_void_p]
        _cf = lib
    return _cf


def _load_sec():
    global _sec
    if _sec is None:
        lib = ctypes.cdll.LoadLibrary(
            "/System/Library/Frameworks/Security.framework/Security"
        )
        lib.SecItemCopyMatching.argtypes = [CFSTR, ctypes.POINTER(CFSTR)]
        lib.SecItemCopyMatching.restype = ctypes.c_int32
        _sec = lib
    return _sec


def _cf_string(text: str) -> CFSTR:
    return _load_cf().CFStringCreateWithCString(
        None, text.encode("utf-8"), K_CF_STRING_ENCODING_UTF8, None
    )


def _cf_bool(value: bool) -> CFSTR:
    cf = _load_cf()
    name = "kCFBooleanTrue" if value else "kCFBooleanFalse"
    return ctypes.c_void_p.in_dll(cf, name).value


def _cf_dict(pairs: list[tuple[str, object]]) -> CFSTR:
    """用 CoreFoundation 造一个查询字典。"""
    cf = _load_cf()
    keys = (CFSTR * len(pairs))()
    values = (CFSTR * len(pairs))()
    for i, (key, value) in enumerate(pairs):
        keys[i] = _cf_string(key)
        if isinstance(value, bool):
            values[i] = _cf_bool(value)
        else:
            values[i] = _cf_string(str(value))
    key_cb = ctypes.c_void_p.in_dll(cf, "kCFTypeDictionaryKeyCallBacks")
    value_cb = ctypes.c_void_p.in_dll(cf, "kCFTypeDictionaryValueCallBacks")
    return cf.CFDictionaryCreate(None, keys, values, len(pairs), key_cb, value_cb)


def _sec_item_copy(query_pairs: list[tuple[str, object]]) -> tuple[int, bytes | None]:
    """跑一次 SecItemCopyMatching，返回状态码与数据。"""
    cf = _load_cf()
    sec = _load_sec()
    query = _cf_dict(query_pairs)
    result = CFSTR()
    try:
        status = sec.SecItemCopyMatching(query, ctypes.byref(result))
        if status != ERR_SEC_SUCCESS:
            return status, None
        try:
            ptr = cf.CFDataGetBytePtr(result)
            length = cf.CFDataGetLength(result)
            if not ptr or length <= 0:
                return status, b""
            return status, ctypes.string_at(ptr, length)
        finally:
            cf.CFRelease(result)
    finally:
        cf.CFRelease(query)


def macos_find_generic(service: str, account: str | None = None) -> SavedCredential | None:
    """按服务名与账户名找钥匙串里的通用口令。"""
    pairs: list[tuple[str, object]] = [
        (K_SEC_CLASS, K_SEC_CLASS_GENERIC_PASSWORD),
        (K_SEC_ATTR_SERVICE, service),
        (K_SEC_RETURN_DATA, True),
        (K_SEC_MATCH_LIMIT, K_SEC_MATCH_LIMIT_ONE),
    ]
    if account:
        pairs.append((K_SEC_ATTR_ACCOUNT, account))
    status, data = _sec_item_copy(pairs)
    if status != ERR_SEC_SUCCESS or not data:
        return None
    return SavedCredential(
        service=service, account=account or "", password=data.decode("utf-8", "replace")
    )


def macos_find_internet(server: str, account: str | None = None) -> SavedCredential | None:
    """按服务器名找钥匙串里的互联网口令（FTP、SMTP 之类）。"""
    pairs: list[tuple[str, object]] = [
        (K_SEC_CLASS, K_SEC_CLASS_INTERNET_PASSWORD),
        (K_SEC_ATTR_SERVER, server),
        (K_SEC_RETURN_DATA, True),
        (K_SEC_MATCH_LIMIT, K_SEC_MATCH_LIMIT_ONE),
    ]
    if account:
        pairs.append((K_SEC_ATTR_ACCOUNT, account))
    status, data = _sec_item_copy(pairs)
    if status != ERR_SEC_SUCCESS or not data:
        return None
    return SavedCredential(
        service=server, account=account or "", password=data.decode("utf-8", "replace")
    )


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
        return SavedCredential(
            service=target_name,
            account=c.UserName or "",
            password=blob.decode("utf-16-le", "replace").rstrip("\x00"),
        )
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
            out.append(
                SavedCredential(
                    service=c.TargetName or "",
                    account=c.UserName or "",
                    password=blob.decode("utf-16-le", "replace").rstrip("\x00"),
                )
            )
    finally:
        advapi.CredFree(pcred)
    return out


WLAN_PROFILE_GET_PLAINTEXT_KEY = 0x00000008


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [
        ("InterfaceGuid", ctypes.c_byte * 16),
        ("strInterfaceDescription", ctypes.c_wchar * 256),
        ("isState", ctypes.c_uint32),
    ]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfItems", ctypes.c_uint32),
        ("dwIndex", ctypes.c_uint32),
        ("InterfaceInfo", WLAN_INTERFACE_INFO * 1),
    ]


def windows_wifi_password(ssid: str) -> str | None:
    """读 Windows WLAN 配置里的明文口令（需要管理员权限）。"""
    wlanapi = ctypes.windll.wlanapi

    handle = ctypes.c_void_p()
    if wlanapi.WlanOpenHandle(2, None, ctypes.byref(handle), None) != 0:
        return None
    try:
        iflist = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        if wlanapi.WlanEnumInterfaces(handle, None, ctypes.byref(iflist)) != 0:
            return None
        try:
            count = iflist.contents.dwNumberOfItems
            base = ctypes.addressof(iflist.contents.InterfaceInfo)
            size = ctypes.sizeof(WLAN_INTERFACE_INFO)
            for i in range(count):
                info = ctypes.cast(base + i * size, ctypes.POINTER(WLAN_INTERFACE_INFO)).contents
                pdata = ctypes.c_void_p()
                pstr = ctypes.c_wchar_p()
                dwsize = ctypes.c_uint32(0)
                ptype = ctypes.c_int32()
                rc = wlanapi.WlanGetProfile(
                    handle,
                    ctypes.byref(info.InterfaceGuid),
                    ssid,
                    None,
                    WLAN_PROFILE_GET_PLAINTEXT_KEY,
                    ctypes.byref(pstr),
                    ctypes.byref(pdata),
                    ctypes.byref(dwsize),
                    ctypes.byref(ptype),
                    None,
                )
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
            if host.lower() not in cred.service.lower():
                continue
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
