# passcrack 开发笔记

记系统当前的状态与做选择的原因，不记会话过程。

## 入口分流

`passcrack.cli.main` 先看 `sys.argv`：空就走 Pywebview 图形界面，有参数走命令行。
命令行模式在解析完成后打印完整免责声明。

打包后 Windows 用的是 `console=False` 的单文件 exe，命令行模式下 stdout 无处可写，
所以 `passcrack/console.py` 在有参数时 `AttachConsole(ATTACH_PARENT_PROCESS)` 附上父进程
的 console，再把标准流重绑到 `CONOUT$`。

中文 Windows 的默认代码页装不下免责声明里的制表符号，`console.setup()` 先试探当前编码，
装不下才 `SetConsoleOutputCP(65001)` 加 `reconfigure(errors="replace")`，不是无条件强改 UTF-8。

## zip 校验为什么只解 12 字节

ZipCrypto 是流密码，头 12 字节是加密头，最后一个字节是校验字节。
校验字节取 CRC-32 高字节（通用位标志第 3 位没置位时），否则取修改时间高字节。
只做 12 字节解密比对，比 `zipfile` 逐个候选走完整解压快一到两个数量级。

CRC-32 的单字节更新不能用 `zlib.crc32`：zlib 带前后异或，PKWARE 的密钥推进要的是不带异或的
原始表更新，所以 `archives.py` 自己建表。

AES 加密的 zip（压缩方式 99）走 pyzipper，7z 走 py7zr 或外部 7z 命令，找不到工具时明确报错。

## WiFi 校验

WPA2 四次握手是离线的：PBKDF2 推出 PMK，PRF-512 推出 PTK，取前 16 字节当 KCK，
对 EAPOL 帧（MIC 字段置零）算 HMAC-SHA1 跟抓包里的 MIC 比。

EAPOL-Key 帧的 MIC 在偏移 80：类型 1 + 长度 2 + 描述符 1 + 密钥信息 2 + 密钥长度 2 +
重放计数器 8 + SNonce 32 + ANonce 32。

PMKID 用 `HMAC-SHA1(PMK, "PMK Name" || AA || SPA || NA || SPI)`，SPI 依次试 0、1 和
抓到的 PMKID 前 8 字节的小端解释。

hc22000 的 EAPOL 字段里最多四段，每段是 2 字节长度加一帧 EAPOL。
pcap 解析覆盖 Ethernet（0x888E）、802.11 数据帧（含 LLC/SNAP）、radiotap 头三种。

WPA3 的 SAE 要跑完整协议，纯 Python 不现实。检测到 SAE 就提示改用 hashcat 或 hcxtools，
装了 hashcat 时 `--hashcat` 会直接把抓包交出去。

纯 Python 的 PBKDF2 比 hashcat 慢两个数量级，这是语言限制，所以在检测到外部工具时优先交给外部工具。

## 本机已保存的凭据

走系统正式 API，不解析命令输出，避免本地化差异带来的误判。

macOS 用 Security.framework 的 `SecKeychainFindGenericPassword` 与
`SecKeychainFindInternetPassword`。WiFi 口令在钥匙串里的服务名是 `AirPort Network Password`，
账户名是 SSID。

Windows 用 advapi32 的 `CredReadW` / `CredEnumerateW` 读凭据管理器，
用 wlanapi 的 `WlanGetProfile`（`WLAN_PROFILE_GET_PLAINTEXT_KEY`）读 WLAN 配置里的明文口令，
口令在配置 XML 的 `<keyMaterial>` 里。

## 搜索引擎

父进程产生候选并按块分发，子进程只校验一块。CPU 密集的（压缩包、WiFi）走进程池，
I/O 密集的（FTP）走线程池。

进程池用 spawn 上下文，打包后必须先调 `multiprocessing.freeze_support()`，
否则 macOS 上子进程会重新执行整个入口。

候选字典与规则在父进程生成，pickle 开销相对 PBKDF2 可以忽略。

## 不做的事

- 不做目标扫描、批量枚举、多目标并发。每项功能只对使用者显式给出的那一个目标工作。
- 不做 FTP 账户的绕过。服务端锁定就是锁定，工具只提供尝试间隔与次数上限。
- 不在代码、测试、日志、发布说明里写入任何真实凭据。示例一律用占位符。

## 验证

- `scripts/check_version.py` 比对 tag、`pyproject.toml`、`__init__.py`、`release-notes.md` 四处版本号。
- `scripts/check_release_notes.py` 检查发布说明里有免责声明，且只有当前一个版本的段落。
- `tests/test_disclaimer.py` 盯住命令行横幅、图形界面 HTML、界面接口三处的免责声明。
- CI 在 ubuntu、macos、windows 上跑 pytest，lint 用钉死的 ruff 版本。

## 已知边界

- WPA2 的 PMKID 校验里 SPI 的取值是试出来的常见值，不是从抓包里直接读到的。
- Windows 的 WLAN 明文口令读取需要管理员权限。
- 图形界面在 macOS 上用 WKWebView，在 Windows 上用 EdgeChromium（WebView2）。
