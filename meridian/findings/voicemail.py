"""Voicemail enrichment (paper §6.5.2 voicemail.py).

Voicemail is short-form audio. Input is the Whisper transcript (with
word-level timestamps and per-segment confidence) plus caller-ID metadata.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from ._base import ExtractionContext, build_findings_block, claim


class VoicemailFindings(BaseModel):
    inferred_speaker_canonical: str = Field(..., description="Speaker identity (use S_n if masked); may be 'unknown'")
    intent: str = Field(..., description="One-sentence intent: request | inform | warn | apologize | other")
    urgency: str = Field("normal", description="low | normal | high | urgent")
    key_phrases: list[str] = Field(default_factory=list)
    transcription_low_confidence_segments: int = Field(0, ge=0)
    contains_specific_threats: bool = Field(False, description="True if message contains direct threats or ultimatums")
    classification_confidence: float = Field(0.7, ge=0.0, le=1.0)


PROMPT_TEMPLATE = """\
You are analyzing a voicemail transcript for legal evidence review.

Named entities are masked as S_n. Use those tokens verbatim.

Voicemail transcript (with metadata):
---
{masked_text}
---

Respond with a single JSON object conforming to the schema. No prose outside JSON.
"""


class VoicemailExtractor:
    document_type: str = "voicemail"

    def __init__(self, ctx: ExtractionContext) -> None:
        self.ctx = ctx

    def extract(self, document_text: str, *, observation_id: str) -> dict:
        if self.ctx.masking_enabled:
            masked_text, emap = self.ctx.masker.mask(document_text)
        else:
            from .enm import EntityMap
            masked_text, emap = document_text, EntityMap()

        prompt = PROMPT_TEMPLATE.format(masked_text=masked_text)
        result_obj: VoicemailFindings = self.ctx.model.complete_json(  # type: ignore[assignment]
            prompt, VoicemailFindings, max_tokens=512, temperature=0.0
        )

        unmask = self.ctx.masker.unmask
        speaker = unmask(result_obj.inferred_speaker_canonical, emap)
        intent = unmask(result_obj.intent, emap)
        phrases = [unmask(p, emap) for p in result_obj.key_phrases]

        claims: list[dict] = []
        claims.append(claim(
            f"Inferred speaker: {speaker}.",
            inference_type="abduction",
            supports=[observation_id],
            gaps=[
                "speaker identification is inferred from caller-ID, opening self-identification, or voice match",
                f"classification confidence {result_obj.classification_confidence:.2f}",
            ],
        ))
        claims.append(claim(
            f"Intent: {intent}",
            inference_type="abduction",
            supports=[observation_id],
            gaps=["intent classification is statistical"],
        ))
        claims.append(claim(
            f"Urgency: {result_obj.urgency}.",
            inference_type="induction",
            supports=[observation_id],
            gaps=["subjective urgency assessment based on tone and content"],
        ))
        for p in phrases:
            claims.append(claim(
                f"Key phrase: {p}",
                inference_type="observation",
                supports=[observation_id],
                gaps=[],
            ))
        if result_obj.transcription_low_confidence_segments > 0:
            claims.append(claim(
                f"Transcription contains {result_obj.transcription_low_confidence_segments} low-confidence segment(s).",
                inference_type="observation",
                supports=[observation_id],
                gaps=[
                    "low-confidence segments may be misheard; verify against audio",
                    "ASR confidence threshold p < 0.85 per pipeline configuration",
                ],
            ))
        if result_obj.contains_specific_threats:
            claims.append(claim(
                "Voicemail contains language interpreted as a direct threat or ultimatum.",
                inference_type="abduction",
                supports=[observation_id],
                gaps=[
                    "threat classification is doctrinal; this is a flag for human review, not a legal conclusion",
                    f"classification confidence {result_obj.classification_confidence:.2f}",
                ],
            ))

        return build_findings_block(
            extractor_name="voicemail.py",
            model_name=self.ctx.model.name,
            claims=claims,
            masking_used=self.ctx.masking_enabled,
            masked_entity_count=len(emap),
        )
