"""AUDIT-FIX tests: dates and transcript tails must never be silently dropped.

  - P4b: merge_to_rich must surface a bad LM date as a human-review gap.
  - P4c: voice_memo must emit a truncation gap when the transcript is cut.
"""

from __future__ import annotations

from meridian.findings.lm_extractor import LMOutput, merge_to_rich
from meridian.findings._base import ExtractionContext
from meridian.findings.enm import EntityMasker
from meridian.findings.voice_memo import VoiceMemoExtractor, VoiceMemoFindings


# --------------------------------------------------------------------------- #
# P4b: bad LM date surfaces as a gap, valid dates still pass                  #
# --------------------------------------------------------------------------- #

def _min_lm(**kw) -> LMOutput:
    base = dict(
        document_kind="court_filing",
        summary_one_sentence="x",
        summary_paragraph="y",
    )
    base.update(kw)
    return LMOutput(**base)


def test_invalid_lm_date_surfaced_as_gap_not_dropped():
    lm = _min_lm(additional_dates_iso=["2026-13-99", "not-a-date"])
    rich = merge_to_rich(
        lm=lm, regex_hints={}, document_text="doc",
        extraction_model="test",
    )
    flags = rich.quality.flags_for_human_review
    # both bad values must appear, none silently erased
    joined = " ".join(flags)
    assert "2026-13-99" in joined
    assert "not-a-date" in joined
    assert sum("dropped_unparseable_date" in f for f in flags) == 2
    # bad dates did not pollute the real date list
    assert all(d.iso not in {"2026-13-99", "not-a-date"} for d in rich.dates)


def test_valid_lm_date_still_added():
    lm = _min_lm(additional_dates_iso=["2026-05-01"])
    rich = merge_to_rich(
        lm=lm, regex_hints={}, document_text="doc",
        extraction_model="test",
    )
    assert "2026-05-01" in {d.iso for d in rich.dates}
    assert not any("dropped_unparseable_date" in f
                   for f in rich.quality.flags_for_human_review)


def test_existing_lm_flags_preserved_alongside_dropped_dates():
    lm = _min_lm(
        additional_dates_iso=["bad-date"],
        flags_for_human_review=["pre_existing_flag"],
    )
    rich = merge_to_rich(
        lm=lm, regex_hints={}, document_text="doc",
        extraction_model="test",
    )
    flags = rich.quality.flags_for_human_review
    assert "pre_existing_flag" in flags
    assert any("dropped_unparseable_date" in f for f in flags)


# --------------------------------------------------------------------------- #
# P4c: voice-memo transcript truncation emits a gap                          #
# --------------------------------------------------------------------------- #

class _FakeLM:
    name = "fake-lm"

    def complete_json(self, prompt, schema_model, *, max_tokens=1024, temperature=0.0):
        return VoiceMemoFindings(
            topic="Long memo",
            key_points=[],
            referenced_entities=[],
            action_items=[],
            inferred_audience="self",
            asr_low_confidence_segments=0,
            speaker_intent="reflection",
            intent_confidence=0.9,
        )


def _ctx():
    return ExtractionContext(model=_FakeLM(), masker=EntityMasker(), masking_enabled=False)


def test_voice_memo_truncation_emits_gap():
    long_text = "word " * 7000  # > 30000 chars
    assert len(long_text) > 30000
    extractor = VoiceMemoExtractor(_ctx())
    findings = extractor.extract(long_text, observation_id="obs-LONG")
    gaps = [g for c in findings["claims"] for g in c["gaps"]]
    assert any("transcript truncated" in g and "30000" in g for g in gaps), \
        "long transcript must surface a truncation gap"


def test_voice_memo_short_no_truncation_gap():
    extractor = VoiceMemoExtractor(_ctx())
    findings = extractor.extract("Short memo about Monday.", observation_id="obs-SHORT")
    gaps = [g for c in findings["claims"] for g in c["gaps"]]
    assert not any("transcript truncated" in g for g in gaps)
