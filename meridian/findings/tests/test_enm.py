"""Epistemic Neutrality Masking tests."""

from __future__ import annotations

from meridian.findings.enm import EntityMasker


def test_mask_replaces_emails_with_tokens() -> None:
    text = "From: alice@example.com\nTo: bob@example.com\nDispute about deposition."
    masker = EntityMasker()
    masked, emap = masker.mask(text)
    assert "alice@example.com" not in masked
    assert "bob@example.com" not in masked
    assert "S_1" in masked or "S_2" in masked
    assert len(emap) >= 2


def test_mask_unmask_roundtrip() -> None:
    text = "Sender alice@example.com sent to bob@example.com on 2026-05-01."
    masker = EntityMasker()
    masked, emap = masker.mask(text)
    unmasked = masker.unmask(masked, emap)
    assert unmasked == text


def test_mask_preserves_unrelated_text() -> None:
    text = "The deposition is on 2026-05-01 at 9am."
    masker = EntityMasker()
    masked, emap = masker.mask(text)
    # Date is structurally a number sequence; the default extractor doesn't mask dates.
    assert "deposition" in masked
    assert "9am" in masked


def test_unmask_handles_double_digit_tokens() -> None:
    text = " ".join(f"alice{i}@example.com" for i in range(15))
    masker = EntityMasker()
    masked, emap = masker.mask(text)
    assert "S_15" in masked or "S_10" in masked
    unmasked = masker.unmask(masked, emap)
    assert unmasked == text


def test_is_entity_dependent() -> None:
    text = "Sender alice@example.com is the relevant party."
    masker = EntityMasker()
    masked, emap = masker.mask(text)
    # If the LM would respond mentioning S_1, it's entity-dependent.
    assert masker.is_entity_dependent("Canonical sender is S_1.", emap)
    assert not masker.is_entity_dependent("Canonical sender is unknown.", emap)


def test_phone_masking() -> None:
    text = "Call +1-612-555-1212 to confirm."
    masker = EntityMasker()
    masked, emap = masker.mask(text)
    assert "+1-612-555-1212" not in masked
    assert any(kind == "phone" for kind in emap.token_to_kind.values())
