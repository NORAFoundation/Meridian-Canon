"""End-to-end test: spans flow through the email extractor into Claim gaps."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Type

from pydantic import BaseModel

from meridian.findings import EmailExtractor, EmailFindings
from meridian.findings._base import ExtractionContext
from meridian.findings._spans import claim_spans
from meridian.findings.enm import EntityMasker


@dataclass
class _SpansAwareFakeAdapter:
    """A fake adapter satisfying SpansAwareLMJsonAdapter for tests.

    Returns canned EmailFindings + canned spans.  ``is_spans_aware`` should
    detect the presence of ``complete_json_with_spans`` and the email
    extractor should propagate spans into the corresponding Claim gaps.
    """

    name: str = "fake-spans-aware"
    family: str = "fake"
    canned_findings: EmailFindings = None  # type: ignore[assignment]
    canned_spans: dict[str, list[tuple[int, int]]] = field(default_factory=dict)

    def complete_json(
        self,
        prompt: str,
        schema_model: Type[BaseModel],
        *,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> BaseModel:
        return self.canned_findings  # type: ignore[return-value]

    def complete_json_with_spans(
        self,
        prompt: str,
        schema_model: Type[BaseModel],
        source_text: str,
        *,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> tuple[BaseModel, dict[str, list[tuple[int, int]]]]:
        return self.canned_findings, dict(self.canned_spans)  # type: ignore[return-value]


_DOCUMENT = (
    "From: alice@example.com\n"
    "To: bob@example.com\n"
    "Subject: Deposition scheduling\n\n"
    "Bob, can we schedule the deposition for 2026-05-01? Please confirm by week's end."
)


def _canned_findings() -> EmailFindings:
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


def test_sender_claim_carries_source_span_when_adapter_provides_one():
    spans = {
        "sender_canonical": [(6, 24)],   # 'alice@example.com' approx position
        "subject_summary": [(43, 64)],
        "body_summary": [(67, 145)],
    }
    adapter = _SpansAwareFakeAdapter(canned_findings=_canned_findings(), canned_spans=spans)
    ctx = ExtractionContext(model=adapter, masker=EntityMasker(), masking_enabled=True)  # type: ignore[arg-type]
    extractor = EmailExtractor(ctx)
    findings = extractor.extract(_DOCUMENT, observation_id="obs-EMAIL-1")

    sender_claims = [c for c in findings["claims"] if c["statement"].startswith("Canonical sender")]
    assert sender_claims, "expected sender claim"
    spans_recovered = claim_spans(sender_claims[0])
    assert (6, 24) in spans_recovered, f"expected sender span (6,24); got {sender_claims[0]['gaps']}"


def test_subject_summary_claim_carries_source_span():
    spans = {"subject_summary": [(43, 64)]}
    adapter = _SpansAwareFakeAdapter(canned_findings=_canned_findings(), canned_spans=spans)
    ctx = ExtractionContext(model=adapter, masker=EntityMasker(), masking_enabled=True)  # type: ignore[arg-type]
    findings = EmailExtractor(ctx).extract(_DOCUMENT, observation_id="obs-1")
    subject_claims = [c for c in findings["claims"] if c["statement"].startswith("Subject summary")]
    assert subject_claims
    assert (43, 64) in claim_spans(subject_claims[0])


def test_extractor_falls_back_when_adapter_is_legacy():
    """Without the spans-aware method, no spans are added but extraction works."""
    @dataclass
    class _Legacy:
        name: str = "legacy"
        family: str = "fake"

        def complete_json(
            self, prompt: str, schema_model: Type[BaseModel], *, max_tokens: int = 1024, temperature: float = 0.0
        ) -> BaseModel:
            return _canned_findings()  # type: ignore[return-value]

    ctx = ExtractionContext(model=_Legacy(), masker=EntityMasker(), masking_enabled=True)  # type: ignore[arg-type]
    findings = EmailExtractor(ctx).extract(_DOCUMENT, observation_id="obs-1")
    sender_claims = [c for c in findings["claims"] if c["statement"].startswith("Canonical sender")]
    assert sender_claims
    # No spans should appear (no source_span:char[...] gap entries).
    assert claim_spans(sender_claims[0]) == []


def test_no_spans_when_adapter_omits_field():
    """If the adapter is spans-aware but doesn't emit a span for a given
    field, no source_span entry is added to that claim."""
    adapter = _SpansAwareFakeAdapter(
        canned_findings=_canned_findings(),
        canned_spans={"subject_summary": [(43, 64)]},  # only subject; sender omitted
    )
    ctx = ExtractionContext(model=adapter, masker=EntityMasker(), masking_enabled=True)  # type: ignore[arg-type]
    findings = EmailExtractor(ctx).extract(_DOCUMENT, observation_id="obs-1")
    sender_claims = [c for c in findings["claims"] if c["statement"].startswith("Canonical sender")]
    assert sender_claims
    assert claim_spans(sender_claims[0]) == []
