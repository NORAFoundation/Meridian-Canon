"""Call-log enrichment (paper §6.5.2 call.py).

Calls have metadata (number, duration, direction, time) but no content
unless the call was recorded. This extractor enriches metadata-only calls;
recorded calls go through voicemail.py / voice_memo.py for transcript.

Context enrichment: correlate the call against SMS / email exchanges in
the surrounding time window, surfacing themes that may have driven the call.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from ._base import ExtractionContext, build_findings_block, claim


class CallFindings(BaseModel):
    direction: str = Field(..., description="incoming | outgoing | missed")
    counterparty_canonical: str = Field(..., description="Other party (use S_n if masked); 'unknown' if not in contacts")
    duration_class: str = Field("brief", description="missed | brief (<1m) | normal (1-10m) | extended (>10m)")
    contextual_themes: list[str] = Field(default_factory=list, description="Themes from surrounding SMS/email window, if provided")
    classification_confidence: float = Field(0.7, ge=0.0, le=1.0)


PROMPT_TEMPLATE = """\
You are analyzing call-log metadata for legal evidence review. Calls have
no content unless recorded; this extractor enriches metadata.

Named entities are masked as S_n. Use those tokens verbatim.

Call metadata + surrounding-window context (if any):
---
{masked_text}
---

Respond with a single JSON object conforming to the schema.
"""


class CallExtractor:
    document_type: str = "call"

    def __init__(self, ctx: ExtractionContext) -> None:
        self.ctx = ctx

    def extract(self, document_text: str, *, observation_id: str) -> dict:
        if self.ctx.masking_enabled:
            masked_text, emap = self.ctx.masker.mask(document_text)
        else:
            from .enm import EntityMap
            masked_text, emap = document_text, EntityMap()

        prompt = PROMPT_TEMPLATE.format(masked_text=masked_text)
        result_obj: CallFindings = self.ctx.model.complete_json(  # type: ignore[assignment]
            prompt, CallFindings, max_tokens=512, temperature=0.0
        )

        unmask = self.ctx.masker.unmask
        counterparty = unmask(result_obj.counterparty_canonical, emap)
        themes = [unmask(t, emap) for t in result_obj.contextual_themes]

        claims: list[dict] = []
        claims.append(claim(
            f"Call direction: {result_obj.direction}.",
            inference_type="observation",
            supports=[observation_id],
            gaps=[],
        ))
        claims.append(claim(
            f"Counterparty: {counterparty}.",
            inference_type="deduction",
            supports=[observation_id],
            gaps=["counterparty resolution depends on contact-app canonical mapping"],
        ))
        claims.append(claim(
            f"Duration class: {result_obj.duration_class}.",
            inference_type="observation",
            supports=[observation_id],
            gaps=[],
        ))
        for t in themes:
            claims.append(claim(
                f"Contextual theme from surrounding window: {t}",
                inference_type="abduction",
                supports=[observation_id],
                gaps=[
                    "theme inferred from surrounding SMS/email; call has no content of its own",
                    f"classification confidence {result_obj.classification_confidence:.2f}",
                ],
            ))

        return build_findings_block(
            extractor_name="call.py",
            model_name=self.ctx.model.name,
            claims=claims,
            masking_used=self.ctx.masking_enabled,
            masked_entity_count=len(emap),
        )
