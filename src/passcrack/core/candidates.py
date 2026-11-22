"""候选口令的生成。

来源有三种，可以叠加使用：
  · 内置常用口令表
  · 外部字典文件（一行一个）
  · 掩码（?l?l?l?l?d 这类模式），直接按位展开

字典条目可以再过一遍「规则」，比如加数字尾巴、转大写、leet 变形等。
所有函数都是惰性的，密码空间再大也不会把内存撑爆。
"""

from __future__ import annotations

import itertools
import string
from collections.abc import Iterable, Iterator, Sequence

# 内置常用口令表。放在代码里而不是单独的数据文件，是为了让打包出来的
# 单文件程序不依赖外部资源。
BUILTIN_PASSWORDS: tuple[str, ...] = tuple(
    """
password Password password1 Password1 123456 1234567 12345678 123456789 1234567890
12345 1234 123 111111 000000 00000 654321 666666 888888 520520 1314520
qwerty Qwerty qwerty123 Qwerty123 qwertyuiop 1q2w3e4r 1q2w3e4r5t zaq1xsw2
admin Admin admin123 Admin123 administrator root Root root123 toor
letmein letmein123 welcome Welcome welcome1 monkey Monkey dragon Dragon
sunshine Sunshine princess Princess football Football baseball Baseball
shadow Shadow master Master michael Michael jennifer Jennifer thomas Thomas
charlie Charlie daniel Daniel jessica Jessica matthew Matthew ashley Ashley
amanda Amanda joseph Joseph william William hannah Hannah alex Alex
nicole Nicole stephanie Stephanie joshua Joshua samantha Samantha
love Love lover Lover iloveyou baby Baby sexy Sexy qwerty1
abc123 Abc123 123abc 1111 2222 3333 4444 5555 6666 7777 8888 9999
abc ABC abcdef Abcdef 123456789abc qwertyui qweasd zxcvbn asdfgh
a1b2c3 1a2b3c 6543210 112233 123321 121212 000111 987654321
sunshine1 princess1 football1 charlie1 letmein1 monkey1 dragon1
trustno1 trustno01 passw0rd p@ssw0rd p@ssword P@ssw0rd P@ssword1 Pa$$w0rd
pass pass123 Pass123 passwd Passwd passwd123 Password123 qwerty123456
iloveyou1 iloveyou2 1234qwer qwe123 1qaz2wsx 1qaz@WSX zaq12wsx
zxc123 zxcvbnm qazwsx qwaszx 12qwaszx 159753 147258 741852 987654
passw0rd! password! Password1! admin! admin1 admin12 admin1234
test Test test123 testtest testing letmein! welcome1! qwerty1!
changeme Changeme changeme1 default Default 11111111 12341234
abcd1234 abc12345 a123456 1q2w3e 1q2w3e4r5t6 q1w2e3r4t5
asd123 asd123456 zxc123456 zxc1234 qwe123456 qwe1234
147258369 159357 753951 9876543210 000000000 111111111
qwer1234 qwer12345 qazwsxedc 1qazxsw2 zaq1xsw zaq12wsx
p4ssw0rd p4ssword passw0rd123 1234abcd abcd1234
god loveyou lovely princess1 rockyou monkey123 dragon123
sunshine123 football123 baseball123 shadow123 master123
cookie cookies orange banana apple
starwars pokemon minecraft fortnite steam
qweasdzxc zaq12wsx 159357zxc asdfghjkl
12345678901 1234567890123456789 00000001 1111111111 2222222222
qqqqqq wwwwww eeeeee rrrrrr tttttt yyyyyy
ninja ninja123 baseball1 dragon1 master1 monkey1 passw0rd
q1w2e3r4t5 q1w2e3r4t5y6 1q2w3e4r5t6y7
qazwsxedcrfvtgbyhnujmikolp zaqwsxedcrfvtgbyhnujmikolp
""".split()
)

# leet 变形表
_LEET = {
    "a": "@4",
    "e": "3",
    "i": "1!",
    "o": "0",
    "s": "$5",
    "t": "7",
    "l": "1",
    "b": "8",
    "g": "9",
}

_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/|~"
_DIGITS = string.digits
_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase

# 规则名 -> 说明，供 CLI --list-rules 使用
RULES: dict[str, str] = {
    "identity": "原样",
    "lower": "全部转小写",
    "upper": "全部转大写",
    "capitalize": "首字母大写",
    "title": "每个单词首字母大写",
    "reverse": "倒序",
    "leet": "a→@4 e→3 i→1 o→0 s→$5 等替换",
    "digits": "追加 0-9999",
    "digits4": "追加 0000-9999",
    "year": "追加 2015-2030",
    "prepend_digits": "前面加 0-9999",
    "symbols": "追加常见符号后缀",
    "duplicate": "重复两遍",
}


def builtin_words() -> list[str]:
    return list(BUILTIN_PASSWORDS)


def load_wordlist(paths: Iterable[str]) -> list[str]:
    """读取字典文件，一行一个口令，忽略空行与 # 注释。"""
    words: list[str] = []
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                w = line.strip()
                if w and not w.startswith("#"):
                    words.append(w)
    return words


def _leet(word: str) -> Iterator[str]:
    """leet 变形的所有组合（每个可替换字符都试两种写法）。"""
    slots: list[list[str]] = []
    for ch in word:
        alts = _LEET.get(ch.lower())
        if alts:
            slots.append([ch] + list(alts))
        else:
            slots.append([ch])
    for combo in itertools.product(*slots):
        yield "".join(combo)


def apply_rule(word: str, rule: str) -> Iterator[str]:
    """对单个词套用一条规则，产出 0 个或多个候选。"""
    if rule == "identity":
        yield word
    elif rule == "lower":
        yield word.lower()
    elif rule == "upper":
        yield word.upper()
    elif rule == "capitalize":
        yield word.capitalize()
    elif rule == "title":
        yield word.title()
    elif rule == "reverse":
        yield word[::-1]
    elif rule == "leet":
        yield from _leet(word)
    elif rule == "digits":
        for n in range(10000):
            yield f"{word}{n}"
    elif rule == "digits4":
        for n in range(10000):
            yield f"{word}{n:04d}"
    elif rule == "year":
        for y in range(2015, 2031):
            yield f"{word}{y}"
    elif rule == "prepend_digits":
        for n in range(10000):
            yield f"{n}{word}"
    elif rule == "symbols":
        for s in ("!", "@", "#", "$", "1!", "123", "1234", "12345", "2024", "2025", "2026"):
            yield f"{word}{s}"
    elif rule == "duplicate":
        yield word + word
    else:
        raise ValueError(f"未知规则: {rule}")


def apply_rules(words: Sequence[str], rules: Sequence[str]) -> Iterator[str]:
    """字典 × 规则 的笛卡尔积。"""
    for rule in rules:
        for w in words:
            yield from apply_rule(w, rule)


def expand_mask(mask: str) -> Iterator[str]:
    """掩码展开。

    ?l 小写字母  ?u 大写字母  ?d 数字  ?s 符号  ?S 常用符号集合
    其余字符按字面处理，\\x 转义下一个字符。
    """
    slots: list[list[str]] = []
    i = 0
    while i < len(mask):
        ch = mask[i]
        if ch == "\\" and i + 1 < len(mask):
            slots.append([mask[i + 1]])
            i += 2
            continue
        if ch == "?" and i + 1 < len(mask):
            kind = mask[i + 1]
            if kind == "l":
                slots.append(list(_LOWER))
            elif kind == "u":
                slots.append(list(_UPPER))
            elif kind == "d":
                slots.append(list(_DIGITS))
            elif kind == "s":
                slots.append(list(_SYMBOLS))
            elif kind == "S":
                slots.append(["!", "@", "#", "$", "%", "&", "*"])
            elif kind == "a":
                slots.append(list(_LOWER) + list(_UPPER))
            else:
                raise ValueError(f"未知掩码符号: ?{kind}")
            i += 2
            continue
        slots.append([ch])
        i += 1
    for combo in itertools.product(*slots):
        yield "".join(combo)


def build_candidates(
    builtin: bool = True,
    wordlists: Sequence[str] = (),
    rules: Sequence[str] = (),
    masks: Sequence[str] = (),
) -> Iterator[str]:
    """按配置产出候选口令流。

    规则为空时字典原样使用；给了规则就只走规则，不再单独输出原样
    （避免同一批口令被重复试一遍）。
    """
    words: list[str] = []
    if builtin:
        words.extend(BUILTIN_PASSWORDS)
    if wordlists:
        words.extend(load_wordlist(wordlists))
    if words:
        if rules:
            yield from apply_rules(words, rules)
        else:
            yield from words
    for mask in masks:
        yield from expand_mask(mask)
