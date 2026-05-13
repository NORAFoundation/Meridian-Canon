"""RFC 8785 canonicalization round-trip tests."""

from __future__ import annotations

import json

from meridian.canon.canonicalize import canonicalize, canonicalize_for_seal, roundtrip_check


def test_roundtrip_simple() -> None:
    obj = {"b": 2, "a": 1, "z": [3, 1, 2]}
    assert roundtrip_check(obj)


def test_roundtrip_nested() -> None:
    obj = {
        "z": {"b": 1, "a": 2},
        "a": [{"x": 1, "y": 2}, {"y": 4, "x": 3}],
        "n": None,
        "f": False,
        "t": True,
    }
    assert roundtrip_check(obj)


def test_keys_are_sorted() -> None:
    """RFC 8785 sorts object keys lexicographically by UTF-16 code units."""
    canonical = canonicalize({"b": 1, "a": 2}).decode()
    assert canonical == '{"a":2,"b":1}'


def test_seal_excluded() -> None:
    """canonicalize_for_seal drops the seal field even if present."""
    with_seal = {"a": 1, "seal": {"signature": "x"}}
    without_seal = {"a": 1}
    assert canonicalize_for_seal(with_seal) == canonicalize(without_seal)


def test_unicode_normalization() -> None:
    """RFC 8785 keeps strings as-received (no NFC normalization)."""
    obj = {"k": "café"}
    canonical = canonicalize(obj)
    parsed = json.loads(canonical.decode("utf-8"))
    assert parsed["k"] == "café"
