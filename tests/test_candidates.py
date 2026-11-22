"""候选口令生成的测试。"""

from __future__ import annotations

from passcrack.core import candidates


def test_builtin_not_empty():
    assert len(candidates.BUILTIN_PASSWORDS) > 100
    assert "password" in candidates.BUILTIN_PASSWORDS


def test_apply_rule_basic():
    assert list(candidates.apply_rule("abc", "identity")) == ["abc"]
    assert list(candidates.apply_rule("abc", "upper")) == ["ABC"]
    assert list(candidates.apply_rule("abc", "capitalize")) == ["Abc"]
    assert list(candidates.apply_rule("abc", "reverse")) == ["cba"]
    assert list(candidates.apply_rule("a", "duplicate")) == ["aa"]


def test_apply_rule_leet_has_multiple_forms():
    out = set(candidates.apply_rule("a", "leet"))
    assert "a" in out
    assert "@" in out or "4" in out
    assert len(out) > 1


def test_apply_rule_unknown_raises():
    try:
        list(candidates.apply_rule("x", "nope"))
    except ValueError:
        return
    raise AssertionError("未知规则应该抛 ValueError")


def test_expand_mask():
    out = list(candidates.expand_mask("?d?d"))
    assert len(out) == 100
    assert "00" in out
    assert "99" in out
    assert all(len(x) == 2 and x.isdigit() for x in out)


def test_expand_mask_escape():
    out = list(candidates.expand_mask("a\\?b"))
    assert out == ["a?b"]


def test_expand_mask_unknown_raises():
    try:
        list(candidates.expand_mask("?x"))
    except ValueError:
        return
    raise AssertionError("未知掩码符号应该抛 ValueError")


def test_build_candidates_uses_rules():
    out = list(candidates.build_candidates(builtin=True, wordlists=(), rules=["upper"], masks=()))
    assert "PASSWORD" in out
    assert "password" not in out


def test_build_candidates_without_rules_keeps_original():
    out = list(candidates.build_candidates(builtin=True, wordlists=(), rules=[], masks=()))
    assert "password" in out


def test_build_candidates_with_mask():
    out = list(candidates.build_candidates(builtin=False, wordlists=(), rules=[], masks=["?l?d"]))
    assert len(out) == 26 * 10
    assert "a0" in out
    assert "z9" in out


def test_load_wordlist(tmp_path):
    p = tmp_path / "words.txt"
    p.write_text("# 注释\nalpha\n\nbeta\n", encoding="utf-8")
    words = candidates.load_wordlist([str(p)])
    assert words == ["alpha", "beta"]
