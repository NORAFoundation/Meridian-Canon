"""Email extractor end-to-end test with a fake LM adapter."""

from __future__ import annotations

from meridian.findings import EmailExtractor, EmailFindings, Runner
from meridian.findings._base import ExtractionContext
from meridian.findings.enm import EntityMasker


def test_email_extractor_produces_findings_block(fake_lm) -> None:  # type: ignore[no-untyped-def]
    # Configure the fake LM to return a typed response.
    def factory(prompt: str) -> EmailFindings:
        # The prompt has been masked; the LM should reply using S_n tokens.
        return EmailFindings(
            sender_canonical="S_1",
            recipients_canonical=["S_2"],
            subject_summary="Scheduling a deposition for 2026-05-01.",
            body_summary="S_1 proposes a date for deposition. S_2 must respond by week's end.",
            action_items=["Confirm deposition date by 2026-04-25."],
            entities_mentioned=["S_1", "S_2", "2026-05-01"],
            automated=False,
            thread_id="thread-abc",
            tone_register="formal",
            classification_confidence=0.85,
        )
    fake_lm.responses[EmailFindings] = factory

    ctx = ExtractionContext(model=fake_lm, masker=EntityMasker(), masking_enabled=True)
    extractor = EmailExtractor(ctx)
    document = (
        "From: alice@example.com\n"
        "To: bob@example.com\n"
        "Subject: Deposition scheduling\n\n"
        "Bob, can we schedule the deposition for 2026-05-01? Please confirm by week's end."
    )

    findings = extractor.extract(document, observation_id="obs-EMAIL-1")

    # Method line names the extractor.
    assert "email.py" in findings["method"]
    assert "Epistemic Neutrality Masking" in findings["method"]

    claims = findings["claims"]
    assert len(claims) >= 5

    # Sender claim should re-associate the masked entity.
    sender_claims = [c for c in claims if c["statement"].startswith("Canonical sender")]
    assert sender_claims
    assert "alice@example.com" in sender_claims[0]["statement"], sender_claims[0]["statement"]

    # Every non-observation claim must declare a gap.
    for c in claims:
        if c["inference_type"] != "observation":
            assert c["gaps"], f"non-observation claim missing gap: {c}"


def test_runner_dispatches_email() -> None:
    from meridian.findings.tests.conftest import FakeLMAdapter
    fake = FakeLMAdapter()
    fake.responses[EmailFindings] = lambda p: EmailFindings(
        sender_canonical="someone@example.com",
        recipients_canonical=["other@example.com"],
        subject_summary="Test subject.",
        body_summary="Test body.",
        action_items=[],
        entities_mentioned=[],
        automated=False,
        thread_id=None,
        tone_register="neutral",
        classification_confidence=0.7,
    )
    runner = Runner(model=fake)  # type: ignore[arg-type]
    result = runner.enrich("From: a@b.com\nTo: c@d.com\nSubject: x\n\nbody", document_type="email", observation_id="obs-1")
    assert result["claims"]
