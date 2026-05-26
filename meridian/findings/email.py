"""Email enrichment (paper §6.5.2 email.py).

Extracts:
- Canonical sender and recipients
- One-sentence subject summary
- 2-3 sentence body summary
- Action items (explicit asks)
- Entities mentioned (persons, organizations, case numbers, monetary, dates)
- Automated-vs-human classification
- Thread identifier (if discernible from headers/body)
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from . import _base
from ._base import ExtractionContext, build_findings_block, claim, is_spans_aware


class EmailFindings(BaseModel):
    """LM output schema for the email extractor.

    Pydantic model -> JSON schema -> vLLM guided_json -> validated output.
    Field names are token-cheap; the prompt explains intent.
    """

    sender_canonical: str = Field(..., description="Canonical sender (email address or person name); use S_n if masked")
    recipients_canonical: list[str] = Field(default_factory=list)
    subject_summary: str = Field(..., description="One sentence summarizing the subject line and intent")
    body_summary: str = Field(..., description="Two to three sentences summarizing the body content")
    action_items: list[str] = Field(default_factory=list, description="Explicit requests or tasks asked of the recipient(s)")
    entities_mentioned: list[str] = Field(default_factory=list, description="Persons, orgs, case numbers, monetary amounts, ISO dates")
    automated: bool = Field(False, description="True if message appears machine-generated (newsletter, receipt, notification)")
    thread_id: Optional[str] = Field(None, description="Thread identifier if present in headers or recoverable from body")
    tone_register: str = Field("neutral", description="formal | neutral | casual | hostile | urgent")
    classification_confidence: float = Field(0.7, ge=0.0, le=1.0)


PROMPT_TEMPLATE = """\
You are extracting structured facts from an email for use in legal evidence review.

The email's named entities have been replaced with generic S_1, S_2, ... tokens.
Reason about relationships and intent rather than identity. Use the S_n tokens
verbatim in your output where you would otherwise name a person, organization,
or specific identifier.

Email content (from + to + subject + body):
---
{masked_text}
---

Respond with a single JSON object that conforms exactly to the requested schema.
Do not include prose, markdown, or commentary outside the JSON.
"""


class EmailExtractor:
    """Per-document email enrichment."""

    document_type: str = "email"

    def __init__(self, ctx: ExtractionContext) -> None:
        self.ctx = ctx

    def extract(
        self,
        document_text: str,
        *,
        observation_id: str,
    ) -> dict:
        """Run the extractor over one email's combined header+body text.

        Returns a Canon-conformant FindingsBlock dict.
        """
        if self.ctx.masking_enabled:
            masked_text, emap = self.ctx.masker.mask(document_text)
        else:
            from .enm import EntityMap
            masked_text, emap = document_text, EntityMap()

        prompt = PROMPT_TEMPLATE.format(masked_text=masked_text)
        # Use the spans-aware path when available; fall back to the
        # legacy adapter Protocol otherwise.  Spans, if present, are
        # propagated into the per-claim source_spans argument below.
        spans_by_field: dict[str, list[tuple[int, int]]] = {}
        if is_spans_aware(self.ctx.model):
            result, spans_by_field = self.ctx.model.complete_json_with_spans(  # type: ignore[attr-defined]
                prompt, EmailFindings, masked_text, max_tokens=1024, temperature=0.0
            )
        else:
            result = self.ctx.model.complete_json(prompt, EmailFindings, max_tokens=1024, temperature=0.0)
        # Pydantic guarantees the type, but downstream wants dicts.
        result_obj: EmailFindings = result  # type: ignore[assignment]

        # Re-associate entities.
        unmask = self.ctx.masker.unmask
        sender = unmask(result_obj.sender_canonical, emap)
        recipients = [unmask(r, emap) for r in result_obj.recipients_canonical]
        subject_summary = unmask(result_obj.subject_summary, emap)
        body_summary = unmask(result_obj.body_summary, emap)
        action_items = [unmask(a, emap) for a in result_obj.action_items]
        entities_mentioned = [unmask(e, emap) for e in result_obj.entities_mentioned]

        # Build claims.
        masking_dependent = lambda stmt: (
            "masked_entity_dependency: claim depends on entity recognition that was masked during inference"
            if self.ctx.masker.is_entity_dependent(stmt, emap)
            else None
        )

        claims: list[dict] = []
        # Sender / recipient as deductions over mask roundtrip.
        sender_stmt = f"Canonical sender is {sender}."
        sender_gaps = ["DKIM/SPF authentication not verified by this layer"]
        sender_dep = masking_dependent(result_obj.sender_canonical)
        if sender_dep:
            sender_gaps.append(sender_dep)
        claims.append(claim(
            sender_stmt,
            inference_type="deduction",
            supports=[observation_id],
            gaps=sender_gaps,
            source_spans=spans_by_field.get("sender_canonical"),
        ))

        for r in recipients:
            r_gaps = ["DKIM/SPF authentication not verified by this layer"]
            claims.append(claim(f"Recipient is {r}.", inference_type="deduction", supports=[observation_id], gaps=r_gaps))

        # Summaries are abductions over body content.
        claims.append(claim(
            f"Subject summary: {subject_summary}",
            inference_type="abduction",
            supports=[observation_id],
            gaps=["summary may omit nuance present in original"],
            source_spans=spans_by_field.get("subject_summary"),
        ))
        claims.append(claim(
            f"Body summary: {body_summary}",
            inference_type="abduction",
            supports=[observation_id],
            gaps=["summary may omit nuance present in original"],
            source_spans=spans_by_field.get("body_summary"),
        ))

        # Action items (deductions where explicit).
        for ai in action_items:
            ai_gaps = ["interpreted as action item from conversational context"]
            d = masking_dependent(ai)
            if d:
                ai_gaps.append(d)
            claims.append(claim(f"Action item: {ai}", inference_type="deduction", supports=[observation_id], gaps=ai_gaps))

        # Entities mentioned (observations against the source).
        for e in entities_mentioned:
            claims.append(claim(
                f"Entity mentioned in email: {e}",
                inference_type="observation",
                supports=[observation_id],
                gaps=[],
            ))

        # Automated vs human (induction).
        auto_stmt = "Message appears machine-generated." if result_obj.automated else "Message appears human-authored."
        claims.append(claim(
            auto_stmt,
            inference_type="induction",
            supports=[observation_id],
            gaps=[
                f"classification confidence {result_obj.classification_confidence:.2f}",
                "based on stylistic features, not metadata",
            ],
        ))

        # Tone (induction).
        claims.append(claim(
            f"Tone is {result_obj.tone_register}.",
            inference_type="induction",
            supports=[observation_id],
            gaps=["subjective tone assessment; potential cultural nuance"],
        ))

        # Thread (observation if present).
        if result_obj.thread_id:
            claims.append(claim(
                f"Thread identifier: {result_obj.thread_id}.",
                inference_type="observation",
                supports=[observation_id],
                gaps=[],
            ))

        return build_findings_block(
            extractor_name="email.py",
            model_name=self.ctx.model.name,
            claims=claims,
            masking_used=self.ctx.masking_enabled,
            masked_entity_count=len(emap),
        )
