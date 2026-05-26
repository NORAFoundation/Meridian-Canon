"""Smoke tests for the remaining extractors: file, sms, voicemail, voice_memo, call."""

from __future__ import annotations

from meridian.findings import (
    CallExtractor,
    CallFindings,
    FileExtractor,
    FileFindings,
    SMSExtractor,
    SMSFindings,
    Runner,
    VoicemailExtractor,
    VoicemailFindings,
    VoiceMemoExtractor,
    VoiceMemoFindings,
)
from meridian.findings._base import ExtractionContext
from meridian.findings.enm import EntityMasker


def _ctx(fake_lm):  # type: ignore[no-untyped-def]
    return ExtractionContext(model=fake_lm, masker=EntityMasker(), masking_enabled=True)


def test_file_extractor(fake_lm) -> None:  # type: ignore[no-untyped-def]
    fake_lm.responses[FileFindings] = lambda p: FileFindings(
        document_kind="motion",
        document_kind_other=None,
        parties=["S_1", "S_2"],
        effective_dates=["2026-05-01"],
        monetary_amounts=["$5,000.00 USD"],
        case_numbers=["EXAMPLE-MATTER-001"],
        jurisdictions=["Example County Circuit Court"],
        one_paragraph_summary="Motion to compel discovery in S_1 v. S_2.",
        classification_confidence=0.9,
    )
    extractor = FileExtractor(_ctx(fake_lm))
    findings = extractor.extract(
        "MOTION TO COMPEL DISCOVERY\n\nIn re: White v. Example County DHS, EXAMPLE-MATTER-001.\n"
        "Petitioner moves the court...",
        observation_id="obs-FILE-1",
    )
    assert findings["claims"]
    kinds = [c for c in findings["claims"] if "Document kind classified" in c["statement"]]
    assert kinds
    assert "motion" in kinds[0]["statement"]


def test_sms_extractor(fake_lm) -> None:  # type: ignore[no-untyped-def]
    fake_lm.responses[SMSFindings] = lambda p: SMSFindings(
        topic="Coordination about Friday's hearing.",
        tone_register="urgent",
        entities_mentioned=["Friday hearing"],
        significant_events=["S_1 confirmed appearance for Friday."],
        participants_canonical=["S_1", "S_2"],
        coercive_signals=[],
        classification_confidence=0.8,
    )
    extractor = SMSExtractor(_ctx(fake_lm))
    findings = extractor.extract(
        "[2026-04-20 09:13] alice: Are we still on for Friday?\n"
        "[2026-04-20 09:15] bob: Yes confirmed.",
        observation_id="obs-SMS-1",
    )
    assert findings["claims"]


def test_voicemail_extractor(fake_lm) -> None:  # type: ignore[no-untyped-def]
    fake_lm.responses[VoicemailFindings] = lambda p: VoicemailFindings(
        inferred_speaker_canonical="S_1",
        intent="warn",
        urgency="urgent",
        key_phrases=["court date", "consequences"],
        transcription_low_confidence_segments=2,
        contains_specific_threats=True,
        classification_confidence=0.75,
    )
    extractor = VoicemailExtractor(_ctx(fake_lm))
    findings = extractor.extract(
        "[caller_id: +1-612-555-1212] [duration: 47s]\n"
        "Hey, this is John. About the court date — there will be consequences.",
        observation_id="obs-VM-1",
    )
    assert findings["claims"]
    threat_claims = [c for c in findings["claims"] if "threat or ultimatum" in c["statement"]]
    assert threat_claims, "voicemail with threats should produce a flagged claim"


def test_voice_memo_extractor(fake_lm) -> None:  # type: ignore[no-untyped-def]
    fake_lm.responses[VoiceMemoFindings] = lambda p: VoiceMemoFindings(
        topic="Notes on TPR hearing strategy.",
        key_points=["Open with chronology.", "Lead with custody-of-evidence chain."],
        referenced_entities=["S_1", "Example County DHS"],
        action_items=["Draft chronology by Friday."],
        inferred_audience="self",
        asr_low_confidence_segments=0,
        speaker_intent="reflection",
        intent_confidence=0.85,
    )
    extractor = VoiceMemoExtractor(_ctx(fake_lm))
    findings = extractor.extract("OK so for the TPR hearing on Monday I want to...", observation_id="obs-VM-2")
    assert findings["claims"]


def test_call_extractor(fake_lm) -> None:  # type: ignore[no-untyped-def]
    fake_lm.responses[CallFindings] = lambda p: CallFindings(
        direction="incoming",
        counterparty_canonical="S_1",
        duration_class="brief",
        contextual_themes=["follow-up after email about deposition"],
        classification_confidence=0.7,
    )
    extractor = CallExtractor(_ctx(fake_lm))
    findings = extractor.extract(
        "[direction: incoming] [from: +16125551212] [duration: 47s] [time: 2026-04-20T14:32]",
        observation_id="obs-CALL-1",
    )
    assert findings["claims"]


def test_runner_unknown_type_raises(fake_lm) -> None:  # type: ignore[no-untyped-def]
    runner = Runner(model=fake_lm)  # type: ignore[arg-type]
    import pytest
    with pytest.raises(KeyError):
        runner.enrich("anything", document_type="screenshots", observation_id="obs-X")


def test_runner_aliases() -> None:
    """imessage routes to sms; pdf routes to file."""
    from meridian.findings.tests.conftest import FakeLMAdapter
    fake = FakeLMAdapter()
    fake.responses[SMSFindings] = lambda p: SMSFindings(
        topic="x", tone_register="neutral", entities_mentioned=[], significant_events=[],
        participants_canonical=[], coercive_signals=[], classification_confidence=0.5,
    )
    fake.responses[FileFindings] = lambda p: FileFindings(
        document_kind="other", document_kind_other="test", parties=[], effective_dates=[],
        monetary_amounts=[], case_numbers=[], jurisdictions=[],
        one_paragraph_summary="x", classification_confidence=0.5,
    )
    runner = Runner(model=fake)  # type: ignore[arg-type]
    result_sms = runner.enrich("text", document_type="imessage", observation_id="obs-1")
    assert result_sms["claims"]
    result_file = runner.enrich("text", document_type="pdf", observation_id="obs-2")
    assert result_file["claims"]
