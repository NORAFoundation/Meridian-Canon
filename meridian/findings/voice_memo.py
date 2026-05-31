"""Voice-memo enrichment (paper §6.5.2 voice_memo.py).

Long-form audio (multi-minute Whisper transcripts) authored by the
custodian. Differs from voicemail in length, intent (note-to-self vs.
incoming message), and the absence of caller-ID metadata.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from ._base import ExtractionContext, build_findings_block, claim


class VoiceMemoFindings(BaseModel):
    topic: str = Field(..., description="One-sentence central theme")
    key_points: list[str] = Field(default_factory=list, description="Critical bullet points")
    referenced_entities: list[str] = Field(default_factory=list, description="Persons, orgs, dates, amounts mentioned")
    action_items: list[str] = Field(default_factory=list, description="Explicit or implicit tasks")
    inferred_audience: str = Field("self", description="self | recipient_named | mixed | unclear")
    asr_low_confidence_segments: int = Field(0, ge=0)
    speaker_intent: str = Field("inform", description="request | inform | question | commitment | reflection")
    intent_confidence: float = Field(0.7, ge=0.0, le=1.0)


PROMPT_TEMPLATE = """\
You are analyzing a voice-memo transcript (long-form audio note) for legal
evidence review.

Named entities are masked as S_n. Use those tokens verbatim.

Voice memo transcript:
---
{masked_text}
---

Respond with a single JSON object conforming to the schema.
"""


class VoiceMemoExtractor:
    document_type: str = "voice_memo"

    def __init__(self, ctx: ExtractionContext) -> None:
        self.ctx = ctx

    def extract(self, document_text: str, *, observation_id: str) -> dict:
        if self.ctx.masking_enabled:
            masked_text, emap = self.ctx.masker.mask(document_text)
        else:
            from .enm import EntityMap
            masked_text, emap = document_text, EntityMap()

        # AUDIT-FIX (P4c): long-form voice-memo transcripts (300+ .m4a notes)
        # routinely exceed 30000 chars. Truncating without a gap means a late
        # exculpatory statement in the tail would vanish from the record.
        truncated = len(masked_text) > 30000
        prompt = PROMPT_TEMPLATE.format(masked_text=masked_text[:30000])
        result_obj: VoiceMemoFindings = self.ctx.model.complete_json(  # type: ignore[assignment]
            prompt, VoiceMemoFindings, max_tokens=1024, temperature=0.0
        )

        unmask = self.ctx.masker.unmask
        topic = unmask(result_obj.topic, emap)
        key_points = [unmask(kp, emap) for kp in result_obj.key_points]
        entities = [unmask(e, emap) for e in result_obj.referenced_entities]
        action_items = [unmask(ai, emap) for ai in result_obj.action_items]

        claims: list[dict] = []
        claims.append(claim(
            f"Voice-memo topic: {topic}",
            inference_type="abduction",
            supports=[observation_id],
            gaps=["topic is a summary; long memos may have sub-themes not summarized"],
        ))
        for kp in key_points:
            claims.append(claim(
                f"Key point: {kp}",
                inference_type="abduction",
                supports=[observation_id],
                gaps=["interpreted as key by language model"],
            ))
        for e in entities:
            claims.append(claim(
                f"Entity referenced: {e}",
                inference_type="observation",
                supports=[observation_id],
                gaps=[],
            ))
        for ai in action_items:
            claims.append(claim(
                f"Action item: {ai}",
                inference_type="deduction",
                supports=[observation_id],
                gaps=["interpreted as action item from monologue context"],
            ))
        claims.append(claim(
            f"Inferred audience: {result_obj.inferred_audience}.",
            inference_type="abduction",
            supports=[observation_id],
            gaps=["audience inferred from speech patterns; voice memos are often note-to-self"],
        ))
        intent_gaps = [
            f"intent confidence {result_obj.intent_confidence:.2f}",
        ]
        if result_obj.intent_confidence < 0.7:
            intent_gaps.append(f"unverified_{result_obj.speaker_intent}_intent")
        claims.append(claim(
            f"Speaker intent: {result_obj.speaker_intent}.",
            inference_type="abduction",
            supports=[observation_id],
            gaps=intent_gaps,
        ))
        if truncated:
            # AUDIT-FIX (P4c): record exactly what the LM did not see.
            claims.append(claim(
                f"Transcript truncated before analysis: {len(masked_text)} chars total.",
                inference_type="observation",
                supports=[observation_id],
                gaps=[
                    "transcript truncated: LM saw first 30000 chars only; "
                    "remainder not analyzed",
                ],
            ))
        if result_obj.asr_low_confidence_segments > 0:
            claims.append(claim(
                f"Transcript contains {result_obj.asr_low_confidence_segments} low-confidence ASR segment(s).",
                inference_type="observation",
                supports=[observation_id],
                gaps=[
                    "low_asr_confidence segments may be misheard",
                    "potential_misinterpretation; verify against audio",
                ],
            ))

        return build_findings_block(
            extractor_name="voice_memo.py",
            model_name=self.ctx.model.name,
            claims=claims,
            masking_used=self.ctx.masking_enabled,
            masked_entity_count=len(emap),
        )
