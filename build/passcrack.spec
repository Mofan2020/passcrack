# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置。

macOS 打成 .app bundle，Windows 打成单文件 exe。
两个平台的 console 都是 False，也就是双击打开不会出现命令行黑框；
Windows 上命令行模式会自己接上父进程的 console（见 passcrack/console.py）。
"""

import re
import sys
from pathlib import Path

ROOT = Path(SPECPATH).parent
SRC = ROOT / "src"

_version_text = (SRC / "passcrack" / "__init__.py").read_text(encoding="utf-8")
VERSION = re.search(r'__version__\s*=\s*"([^"]+)"', _version_text).group(1)

a = Analysis(
    [str(ROOT / "packaging_entry.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=[(str(SRC / "passcrack" / "ui" / "assets"), "passcrack/ui/assets")],
    hiddenimports=[
        "passcrack.core.archives",
        "passcrack.core.candidates",
        "passcrack.core.engine",
        "passcrack.core.ftp",
        "passcrack.core.wifi",
        "passcrack.osint.saved",
        "py7zr",
        "pyzipper",
        "multiprocessing",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "numpy",
        "pytest",
        "IPython",
        "notebook",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="passcrack",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

if sys.platform == "darwin":
    app = BUNDLE(
        exe,
        name="passcrack.app",
        icon=None,
        bundle_identifier="com.skyc8266.passcrack",
        info_plist={
            "CFBundleName": "passcrack",
            "CFBundleDisplayName": "passcrack",
            "CFBundleShortVersionString": VERSION,
            "CFBundleVersion": VERSION,
            "CFBundlePackageType": "APPL",
            "LSMinimumSystemVersion": "11.0",
            "NSHighResolutionCapable": True,
            "NSHumanReadableCopyright": "MIT License. For authorized use only.",
            "LSApplicationCategoryType": "public.app-category.utilities",
        },
    )
