# passcrack

FTP、WiFi、压缩包的口令恢复工具。图形界面和命令行两种用法。

## 免责声明

本工具仅供在您拥有或已获得明确授权的系统上进行合法的口令恢复与安全审计。

- 严禁用于任何未经授权的访问
- 本工具不包含扫描、枚举或批量攻击第三方目标的能力
- 每项功能都要求使用者显式提供单一目标
- 使用本工具即表示您已获得授权，并接受可能造成的后果，包括账户锁定、数据丢失、业务中断与法律责任
- 使用者须自行承担全部法律责任

完整的免责声明见 [DISCLAIMER.md](DISCLAIMER.md)，命令行每次启动都会打印一遍。

## 功能

FTP 口令恢复。需要服务器地址与用户名。

WiFi 口令恢复。需要 SSID。支持 WPA2 的四次握手与 PMKID。WPA3 的 SAE 需要跑完整协议，检测到会提示改用 hashcat 或 hcxtools。

压缩包口令恢复。自动识别 zip、7z、rar。zip 的传统加密只解开头 12 字节做校验，比整包尝试快一到两个数量级。

读取本机已保存的凭据。macOS 读钥匙串，Windows 读凭据管理器与 WLAN 配置。这是恢复自己密码最快的路。

## 下载

Releases 页拿安装包。macOS 解压后得到 passcrack.app，Windows 得到 passcrack.exe。

当前只有预发布版本。

## 使用

双击打开是图形界面。命令行里带参数就是命令行模式。

图形界面分成 FTP、WiFi、压缩包、本机已保存四个标签页，用之前要勾掉顶部的授权确认。

```
passcrack ftp --host ftp.example.com --user someone
passcrack wifi --ssid 我的WiFi --capture capture.hc22000
passcrack archive --file backup.zip
passcrack saved --ssid 我的WiFi
```

FTP 与 WiFi 都必须提供对应的服务器地址、用户名或 SSID。

### 字典与规则

内置一份常用口令表。想加大范围就自己准备字典文件，一行一个口令。

```
passcrack archive --file backup.zip --wordlist words.txt --rule digits --rule symbols
```

掩码可以直接展开，不用字典。

```
passcrack archive --file backup.zip --mask "?l?l?l?l?d"
```

掩码符号：`?l` 小写字母，`?u` 大写字母，`?d` 数字，`?s` 符号，`?a` 字母。

`passcrack rules` 能列出全部规则。

### WiFi 抓包

抓包支持 hcxtools 的 hc22000 文件和 pcap 文件。pcapng 要先转成 pcap。

WPA2 的校验是离线的，拿到握手就能在本地跑。装了 hashcat 的话加 `--hashcat` 会优先交给它算，速度比 Python 快两个数量级。

### FTP

FTP 模式会真的去登录你给的那台服务器。默认每次尝试间隔 0.5 秒，可以用 `--delay` 调大，`--max-attempts` 限制次数。服务端把账户锁了就是锁了，调参数救不回来。

## 平台

macOS 优先，Windows 次之。都用 PyInstaller 打包，双击打开没有命令行黑框。

## 许可

MIT。但许可不包括授权。

## 致谢

口令恢复这件事上，hcxtools 与 hashcat 的作者做了大量基础工作，本工具的 WiFi 部分遵循它们公开的格式与算法。
