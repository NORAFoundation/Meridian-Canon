"""Generic file / PDF enrichment (paper §6.5.2 file.py).

For PDFs, court filings, financial statements, contracts, and other
text-bearing documents. Extracts:
- Document-kind classification from a controlled vocabulary
- Parties named in the document
- Effective dates
- Monetary amounts (with currency, structured)
- Case numbers
- Jurisdictions referenced
- One-paragraph summary
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from . import _base
from ._base import ExtractionContext, build_findings_block, claim


# Controlled vocabulary of document kinds. Approximately thirty-two categories
# per paper §6.5.2; this is a starter set covering the most common litigation
# documents. Extractors are free to return "other" with a free-text refinement.
DOCUMENT_KINDS = [
    "complaint", "answer", "motion", "brief", "order", "judgment",
    "subpoena", "discovery_request", "discovery_response",
    "deposition_transcript", "court_transcript",
    "affidavit", "declaration", "exhibit_list", "verification",
    "contract", "addendum", "lease", "promissory_note",
    "bank_statement", "credit_card_statement", "tax_return",
    "invoice", "receipt", "purchase_order",
    "medical_record", "police_report", "incident_report",
    "correspondence", "memo", "report",
    "regulatory_filing", "license", "insurance_policy",
    "other",
]


class FileFindings(BaseModel):
    """LM output schema for the file extractor."""

    document_kind: str = Field(..., description=f"One of: {', '.join(DOCUMENT_KINDS)}")
    document_kind_other: Optional[str] = Field(None, description="Free-text refinement when document_kind == 'other'")
    parties: list[str] = Field(default_factory=list, description="Persons or entities named as parties; use S_n if masked")
    effective_dates: list[str] = Field(default_factory=list, description="ISO dates relevant to the document's force/event")
    monetary_amounts: list[str] = Field(default_factory=list, description="Amounts with currency, e.g. '$5,000.00 USD'")
    case_numbers: list[str] = Field(default_factory=list, description="Court case numbers in source format")
    jurisdictions: list[str] = Field(default_factory=list, description="Courts, agencies, or geographic jurisdictions")
    one_paragraph_summary: str = Field(..., description="3-5 sentences summarizing the document's substance")
    classification_confidence: float = Field(0.7, ge=0.0, le=1.0)


PROMPT_TEMPLATE = """\
You are extracting structured facts from a document for use in legal evidence review.

The document's named entities have been replaced with generic S_1, S_2, ... tokens.
Reason about the document's substance rather than party identity. Use S_n tokens
verbatim in your output where you would otherwise name a party.

Document text (may be truncated to fit context window):
---
{masked_text}
---

Allowed values for document_kind:
{kinds_list}

Respond with a single JSON object conforming exactly to the schema. No prose
or markdown outside the JSON.
"""


class FileExtractor:
    document_type: str = "file"

    def __init__(self, ctx: ExtractionContext) -> None:
        self.ctx = ctx

    def extract(self, document_text: str, *, observation_id: str) -> dict:
        if self.ctx.masking_enabled:
            masked_text, emap = self.ctx.masker.mask(document_text)
        else:
            from .enm import EntityMap
            masked_text, emap = document_text, EntityMap()

        kinds_list = "\n".join(f"- {k}" for k in DOCUMENT_KINDS)
        prompt = PROMPT_TEMPLATE.format(masked_text=masked_text[:30000], kinds_list=kinds_list)
        result_obj: FileFindings = self.ctx.model.complete_json(  # type: ignore[assignment]
            prompt, FileFindings, max_tokens=1500, temperature=0.0
        )

        unmask = self.ctx.masker.unmask
        parties = [unmask(p, emap) for p in result_obj.parties]
        summary = unmask(result_obj.one_paragraph_summary, emap)

        claims: list[dict] = []

        # Document kind (induction; depends on classifier).
        kind_text = result_obj.document_kind
        if kind_text == "other" and result_obj.document_kind_other:
            kind_text = f"other ({result_obj.document_kind_other})"
        claims.append(claim(
            f"Document kind classified as: {kind_text}.",
            inference_type="induction",
            supports=[observation_id],
            gaps=[
                f"classification confidence {result_obj.classification_confidence:.2f}",
                f"controlled vocabulary of {len(DOCUMENT_KINDS)} kinds; finer-grained refinement requires manual review",
            ],
        ))

        # Parties (deductions; subject to masking).
        for p in parties:
            p_gaps = ["entity extracted by language model; not verified against entity registry"]
            if self.ctx.masker.is_entity_dependent(p, emap):
                p_gaps.append("masked_entity_dependency")
            claims.append(claim(
                f"Party named in document: {p}.",
                inference_type="deduction",
                supports=[observation_id],
                gaps=p_gaps,
            ))

        for d in result_obj.effective_dates:
            claims.append(claim(
                f"Effective date referenced: {d}.",
                inference_type="observation",
                supports=[observation_id],
                gaps=[],
            ))
        for amt in result_obj.monetary_amounts:
            claims.append(claim(
                f"Monetary amount referenced: {amt}.",
                inference_type="observation",
                supports=[observation_id],
                gaps=[],
            ))
        for cn in result_obj.case_numbers:
            claims.append(claim(
                f"Case number referenced: {cn}.",
                inference_type="observation",
                supports=[observation_id],
                gaps=[],
            ))
        for j in result_obj.jurisdictions:
            claims.append(claim(
                f"Jurisdiction referenced: {j}.",
                inference_type="observation",
                supports=[observation_id],
                gaps=[],
            ))

        # Summary (abduction).
        claims.append(claim(
            f"Document summary: {summary}",
            inference_type="abduction",
            supports=[observation_id],
            gaps=[
                "summary may omit nuance present in original",
                "long documents may be truncated to fit LM context window",
            ],
        ))

        return build_findings_block(
            extractor_name="file.py",
            model_name=self.ctx.model.name,
            claims=claims,
            masking_used=self.ctx.masking_enabled,
            masked_entity_count=len(emap),
        )
