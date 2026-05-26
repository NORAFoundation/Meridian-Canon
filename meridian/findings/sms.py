"""SMS / iMessage enrichment (paper §6.5.2 sms.py).

Operates on conversation windows rather than individual messages —
individual texts are too short to enrich meaningfully. The runner is
responsible for assembling a window (chronological run of messages between
the same parties); this extractor analyzes the window.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from ._base import ExtractionContext, build_findings_block, claim


class SMSFindings(BaseModel):
    topic: str = Field(..., description="One-sentence topic of the conversation window")
    tone_register: str = Field("neutral", description="formal | neutral | casual | hostile | urgent | mixed")
    entities_mentioned: list[str] = Field(default_factory=list, description="Persons, places, dates, monetary amounts referenced")
    significant_events: list[str] = Field(default_factory=list, description="Decisions, agreements, threats, scheduling, escalations")
    participants_canonical: list[str] = Field(default_factory=list, description="Canonical participants in the window (use S_n)")
    coercive_signals: list[str] = Field(default_factory=list, description="Direct or implied coercion, threats, manipulation")
    classification_confidence: float = Field(0.7, ge=0.0, le=1.0)


PROMPT_TEMPLATE = """\
You are analyzing a window of SMS / iMessage conversations for legal evidence review.

Named entities are masked as S_1, S_2, ... — use those tokens verbatim.

Conversation window (chronological; participants and timestamps included):
---
{masked_text}
---

Identify the topic, tone, key participants, significant events (decisions,
agreements, threats, scheduling, escalations), and any coercive signals
(direct or implied threats, manipulation, ultimatum patterns).

Respond with a single JSON object conforming to the schema.
"""


class SMSExtractor:
    document_type: str = "sms"

    def __init__(self, ctx: ExtractionContext) -> None:
        self.ctx = ctx

    def extract(self, document_text: str, *, observation_id: str) -> dict:
        if self.ctx.masking_enabled:
            masked_text, emap = self.ctx.masker.mask(document_text)
        else:
            from .enm import EntityMap
            masked_text, emap = document_text, EntityMap()

        prompt = PROMPT_TEMPLATE.format(masked_text=masked_text)
        result_obj: SMSFindings = self.ctx.model.complete_json(  # type: ignore[assignment]
            prompt, SMSFindings, max_tokens=1024, temperature=0.0
        )

        unmask = self.ctx.masker.unmask
        topic = unmask(result_obj.topic, emap)
        participants = [unmask(p, emap) for p in result_obj.participants_canonical]
        events = [unmask(e, emap) for e in result_obj.significant_events]
        entities = [unmask(e, emap) for e in result_obj.entities_mentioned]
        coercive = [unmask(c, emap) for c in result_obj.coercive_signals]

        claims: list[dict] = []
        claims.append(claim(
            f"Conversation topic: {topic}",
            inference_type="abduction",
            supports=[observation_id],
            gaps=["topic is a summary; window may contain sub-threads not summarized here"],
        ))
        for p in participants:
            claims.append(claim(
                f"Participant in conversation: {p}.",
                inference_type="deduction",
                supports=[observation_id],
                gaps=["participant identification depends on contact-app canonical mapping"],
            ))
        claims.append(claim(
            f"Tone register: {result_obj.tone_register}.",
            inference_type="induction",
            supports=[observation_id],
            gaps=["subjective tone assessment; potential cultural nuance"],
        ))
        for ev in events:
            claims.append(claim(
                f"Significant event: {ev}",
                inference_type="abduction",
                supports=[observation_id],
                gaps=["interpreted as significant by language model"],
            ))
        for e in entities:
            claims.append(claim(
                f"Entity mentioned in conversation: {e}",
                inference_type="observation",
                supports=[observation_id],
                gaps=[],
            ))
        for cs in coercive:
            claims.append(claim(
                f"Coercive signal detected: {cs}",
                inference_type="abduction",
                supports=[observation_id],
                gaps=[
                    "coercion is a doctrinal determination; this is a flag for human review, not a legal conclusion",
                    f"classification confidence {result_obj.classification_confidence:.2f}",
                ],
            ))

        return build_findings_block(
            extractor_name="sms.py",
            model_name=self.ctx.model.name,
            claims=claims,
            masking_used=self.ctx.masking_enabled,
            masked_entity_count=len(emap),
        )
