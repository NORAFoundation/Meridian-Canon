"""LM-driven enrichment: OpenAI structured outputs (Mistral fallback).

Builds an LM-output schema deliberately flatter than RichFindings so the
provider's JSON-schema mode accepts it. The flat output is then merged
with regex pre-extraction to assemble the final RichFindings object.

Why flat? OpenAI / Mistral structured outputs reject deeply nested
optional-with-discriminator types and very long enum unions. The flat
schema below is what the LM sees; the rich schema is what we store.
"""

from __future__ import annotations

import os
import json
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

from pydantic import BaseModel, Field

from .rich_schema import (
    RichFindings, DocumentKind, ProceduralPosture, ToneRegister,
    Intent, LegalSentiment, PrivilegeMarker,
    CaseNumber, StatuteCitation, DateReference, MonetaryAmount,
    PartyMention, KeyQuote, HearingEvent, RiskFlags, CustodyMarkers,
    QualityMetadata, SourceSpan,
)


# --------------------------------------------------------------------------- #
# Flat LM-output schema (what we send to the provider)                        #
# --------------------------------------------------------------------------- #

class _LMParty(BaseModel):
    name: str
    role: Optional[str] = None
    address: Optional[str] = None
    bar_number: Optional[str] = None


class _LMQuote(BaseModel):
    text: str
    significance: Optional[str] = None
    page: Optional[int] = None


class _LMHearing(BaseModel):
    type: str
    date_iso: Optional[str] = None
    location: Optional[str] = None
    judge: Optional[str] = None


class LMOutput(BaseModel):
    """Flat schema sent to the LM. Reconstituted into RichFindings client-side."""

    # classification
    document_kind: str = Field(..., description="One of the controlled-vocab kinds")
    document_kind_other: Optional[str] = None
    document_kind_confidence: float = 0.7

    title: Optional[str] = None
    language: str = "en"

    # temporal
    primary_date_iso: Optional[str] = Field(None, description="YYYY-MM-DD; the single most relevant date")
    primary_date_kind: Optional[str] = Field(None, description="filed|signed|effective|received|created")
    additional_dates_iso: list[str] = Field(default_factory=list)
    time_period_start_iso: Optional[str] = None
    time_period_end_iso: Optional[str] = None

    # parties (LM extracts; rich PartyMention assembled client-side)
    parties: list[_LMParty] = Field(default_factory=list)
    primary_petitioner: Optional[str] = None
    primary_respondent: Optional[str] = None
    judge: Optional[str] = None
    presiding_court: Optional[str] = None
    attorneys: list[_LMParty] = Field(default_factory=list)
    agencies: list[_LMParty] = Field(default_factory=list)

    # legal substance
    causes_of_action: list[str] = Field(default_factory=list)
    legal_issues: list[str] = Field(default_factory=list)
    relief_sought: list[str] = Field(default_factory=list)
    procedural_posture: str = "unknown"
    jurisdiction: Optional[str] = None
    venue: Optional[str] = None
    next_event: Optional[_LMHearing] = None

    # semantic
    summary_one_sentence: str
    summary_paragraph: str
    executive_findings: list[str] = Field(default_factory=list)
    key_quotes: list[_LMQuote] = Field(default_factory=list)
    topics: list[str] = Field(default_factory=list)
    subject_matter: Optional[str] = None

    # tone & intent
    tone_register: str = "neutral"
    intent: str = "document"
    legal_sentiment: str = "indeterminate"
    urgency_level: int = 0

    # custody
    is_signed: bool = False
    signatory_names: list[str] = Field(default_factory=list)
    is_certified_copy: bool = False
    is_notarized: bool = False
    is_court_filed: bool = False
    filed_date_iso: Optional[str] = None
    is_redacted: bool = False
    has_bates_numbers: bool = False
    bates_range: Optional[str] = None
    service_method: Optional[str] = None
    custodian_named: Optional[str] = None

    # risk
    mentions_minors: bool = False
    minor_names: list[str] = Field(default_factory=list)
    mentions_phi: bool = False
    mentions_drug_use: bool = False
    mentions_mental_health: bool = False
    mentions_violence: bool = False
    mentions_sexual_content: bool = False
    privilege_marker: str = "none"
    redaction_recommended: bool = False
    redaction_reason: Optional[str] = None

    # confidence
    overall_confidence: float = 0.7
    flags_for_human_review: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Prompt                                                                      #
# --------------------------------------------------------------------------- #

_DOC_KINDS_LIST = ", ".join(k.value for k in DocumentKind)
_POSTURES_LIST = ", ".join(p.value for p in ProceduralPosture)
_TONES_LIST = ", ".join(t.value for t in ToneRegister)
_INTENTS_LIST = ", ".join(i.value for i in Intent)
_SENTIMENTS_LIST = ", ".join(s.value for s in LegalSentiment)
_PRIVILEGE_LIST = ", ".join(p.value for p in PrivilegeMarker)


SYSTEM_PROMPT = f"""You are a legal evidence enrichment system. Extract structured \
metadata from a document for use in retrieval and case analysis. Be conservative: \
prefer null over guessing; cite verbatim when uncertain. Use ISO 8601 for all dates.

Controlled vocabularies (use exact strings):
  document_kind: {_DOC_KINDS_LIST}
  procedural_posture: {_POSTURES_LIST}
  tone_register: {_TONES_LIST}
  intent: {_INTENTS_LIST}
  legal_sentiment: {_SENTIMENTS_LIST}
  privilege_marker: {_PRIVILEGE_LIST}

Rules:
- All dates must be valid ISO 8601 (YYYY-MM-DD or full datetime).
- Party names: prefer the form used in the document; do not normalize away from source.
- For court filings, extract the procedural posture from caption + heading.
- legal_issues should be short tags (3-30 chars), e.g. "tpr", "icpc", "discovery".
- key_quotes: at most 3, each ≤500 chars, only legally significant verbatim quotes.
- mentions_minors: True ONLY if individuals under 18 are explicitly named or implied.
- urgency_level 0=none, 1=routine, 2=time-sensitive, 3=imminent deadline (≤7 days).
- If you cannot determine a field with high confidence, leave it null/default and add \
  the field name to flags_for_human_review."""


USER_PROMPT_TEMPLATE = """\
Document text below. Extract all structured fields per the schema.

Some deterministic facts already extracted (use as ground truth, do not contradict):
{regex_hints}

---DOCUMENT---
{document_text}
---END DOCUMENT---

Return ONLY the JSON object."""


# --------------------------------------------------------------------------- #
# Adapter                                                                     #
# --------------------------------------------------------------------------- #

class LMExtractor:
    """OpenAI-first; Mistral fallback. Same flat output schema."""

    def __init__(
        self,
        provider: str = "openai",
        model: Optional[str] = None,
    ):
        self.provider = provider.lower()
        if self.provider == "openai":
            from openai import OpenAI
            self.client = OpenAI()  # reads OPENAI_API_KEY
            self.model = model or "gpt-4o-mini"
        elif self.provider == "mistral":
            from mistralai.client.sdk import Mistral
            self.client = Mistral(api_key=os.environ["MISTRAL_API_KEY"])
            self.model = model or "mistral-small-latest"
        else:
            raise ValueError(f"unknown provider {provider!r}")

    def extract(self, document_text: str, regex_hints: dict) -> LMOutput:
        """Single LM call returning a validated LMOutput."""
        truncated = len(document_text) > 30000
        text = document_text[:30000] if truncated else document_text

        hints_str = self._format_hints(regex_hints)
        user_prompt = USER_PROMPT_TEMPLATE.format(
            regex_hints=hints_str or "(none)",
            document_text=text,
        )

        if self.provider == "openai":
            resp = self.client.chat.completions.parse(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                response_format=LMOutput,
                temperature=0.0,
            )
            return resp.choices[0].message.parsed
        else:  # mistral
            resp = self.client.chat.parse(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                response_format=LMOutput,
                temperature=0.0,
            )
            return resp.choices[0].message.parsed

    @staticmethod
    def _format_hints(hints: dict) -> str:
        lines: list[str] = []
        if hints.get("case_numbers"):
            lines.append(f"case_numbers: {[c.canonical for c in hints['case_numbers']]}")
        if hints.get("statutes"):
            lines.append(f"statutes: {[s.canonical for s in hints['statutes']][:10]}")
        if hints.get("dates"):
            lines.append(f"dates_seen: {[d.iso for d in hints['dates']][:10]}")
        if hints.get("monetary_amounts"):
            lines.append(f"amounts: {[(str(m.value)+m.currency) for m in hints['monetary_amounts']][:10]}")
        if hints.get("emails"):
            lines.append(f"emails: {hints['emails'][:5]}")
        if hints.get("phones"):
            lines.append(f"phones: {hints['phones'][:5]}")
        if hints.get("bar_numbers"):
            lines.append(f"bar_numbers: {hints['bar_numbers']}")
        if hints.get("has_ssn"):
            lines.append("WARNING: SSN-like pattern detected; treat as PHI.")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Merge: regex + LM → RichFindings                                            #
# --------------------------------------------------------------------------- #

def merge_to_rich(
    *,
    lm: LMOutput,
    regex_hints: dict,
    document_text: str,
    extraction_model: str,
    extraction_version: str = "1.0",
    truncated: bool = False,
) -> RichFindings:
    """Combine deterministic regex output with LM output into RichFindings."""

    # --- agreement scoring on cross-validated fields
    agreement = _agreement_score(lm, regex_hints)

    # ---- identifiers: prefer regex (high precision) but include LM-only matches
    case_numbers = list(regex_hints.get("case_numbers", []))
    statutes = list(regex_hints.get("statutes", []))

    # ---- dates: union, prefer regex spans
    dates = list(regex_hints.get("dates", []))
    seen_iso = {d.iso for d in dates}
    for iso in lm.additional_dates_iso:
        if iso and iso not in seen_iso:
            try:
                dates.append(DateReference(iso=iso, raw=iso, certainty="inferred"))
                seen_iso.add(iso)
            except Exception:
                pass

    # ---- money: regex exact; LM-extracted amounts skipped to avoid duplication
    monetary = list(regex_hints.get("monetary_amounts", []))

    # ---- parties (LM-only; regex doesn't NER full names well)
    parties = [
        PartyMention(
            name=p.name, role=p.role, address=p.address, bar_number=p.bar_number,
            confidence=0.75,
        )
        for p in lm.parties
    ]
    attorneys = [
        PartyMention(name=p.name, role=p.role or "attorney", bar_number=p.bar_number, confidence=0.8)
        for p in lm.attorneys
    ]
    agencies = [
        PartyMention(name=p.name, role=p.role or "agency", confidence=0.8)
        for p in lm.agencies
    ]

    # ---- key quotes
    key_quotes = [
        KeyQuote(text=q.text, significance=q.significance, page=q.page)
        for q in lm.key_quotes
    ]

    # ---- enums (defensive: LM might emit something off-vocab)
    def _enum(value: str, enum_cls, default):
        try:
            return enum_cls(value)
        except ValueError:
            return default

    document_kind = _enum(lm.document_kind, DocumentKind, DocumentKind.other)
    posture = _enum(lm.procedural_posture, ProceduralPosture, ProceduralPosture.unknown)
    tone = _enum(lm.tone_register, ToneRegister, ToneRegister.neutral)
    intent = _enum(lm.intent, Intent, Intent.document)
    sentiment = _enum(lm.legal_sentiment, LegalSentiment, LegalSentiment.indeterminate)
    privilege = _enum(lm.privilege_marker, PrivilegeMarker, PrivilegeMarker.none)

    # ---- next event
    next_event = None
    if lm.next_event:
        next_event = HearingEvent(
            type=lm.next_event.type,
            date_iso=lm.next_event.date_iso,
            location=lm.next_event.location,
            judge=lm.next_event.judge,
        )

    # ---- custody
    custody = CustodyMarkers(
        is_signed=lm.is_signed, signatory_names=lm.signatory_names,
        is_certified_copy=lm.is_certified_copy, is_notarized=lm.is_notarized,
        is_court_filed=lm.is_court_filed, filed_date_iso=lm.filed_date_iso,
        is_redacted=lm.is_redacted,
        has_bates_numbers=bool(regex_hints.get("bates")) or lm.has_bates_numbers,
        bates_range=lm.bates_range,
        service_method=lm.service_method,
        custodian_named=lm.custodian_named,
    )

    # ---- risk
    risk = RiskFlags(
        mentions_minors=lm.mentions_minors,
        minor_names=lm.minor_names,
        mentions_phi=lm.mentions_phi,
        mentions_financial_account_numbers=False,
        mentions_ssn=regex_hints.get("has_ssn", False),
        mentions_drug_use=lm.mentions_drug_use,
        mentions_mental_health=lm.mentions_mental_health,
        mentions_violence=lm.mentions_violence,
        mentions_sexual_content=lm.mentions_sexual_content,
        privilege_marker=privilege,
        redaction_recommended=lm.redaction_recommended,
        redaction_reason=lm.redaction_reason,
    )

    # ---- quality
    quality = QualityMetadata(
        extraction_model=extraction_model,
        extraction_version=extraction_version,
        extracted_at_iso=datetime.now(timezone.utc).isoformat(),
        overall_confidence=lm.overall_confidence,
        field_confidences={},
        flags_for_human_review=lm.flags_for_human_review,
        regex_lm_agreement_score=agreement,
        truncated=truncated,
    )

    return RichFindings(
        document_kind=document_kind,
        document_kind_other=lm.document_kind_other,
        document_kind_confidence=lm.document_kind_confidence,
        title=lm.title,
        language=lm.language,
        word_count=len(document_text.split()),
        primary_date_iso=lm.primary_date_iso,
        primary_date_kind=lm.primary_date_kind,
        dates=dates,
        time_period_start_iso=lm.time_period_start_iso,
        time_period_end_iso=lm.time_period_end_iso,
        case_numbers=case_numbers,
        statutes=statutes,
        case_law=regex_hints.get("case_law", []),
        docket_numbers=[],
        exhibit_labels=[],
        parties=parties,
        primary_petitioner=lm.primary_petitioner,
        primary_respondent=lm.primary_respondent,
        judge=lm.judge,
        presiding_court=lm.presiding_court,
        attorneys=attorneys,
        agencies=agencies,
        monetary_amounts=monetary,
        causes_of_action=lm.causes_of_action,
        legal_issues=lm.legal_issues,
        relief_sought=lm.relief_sought,
        procedural_posture=posture,
        jurisdiction=lm.jurisdiction,
        venue=lm.venue,
        next_event=next_event,
        summary_one_sentence=lm.summary_one_sentence,
        summary_paragraph=lm.summary_paragraph,
        executive_findings=lm.executive_findings,
        key_quotes=key_quotes,
        topics=lm.topics,
        subject_matter=lm.subject_matter,
        tone_register=tone,
        intent=intent,
        legal_sentiment=sentiment,
        urgency_level=lm.urgency_level,
        custody=custody,
        risk=risk,
        quality=quality,
    )


def _agreement_score(lm: LMOutput, regex_hints: dict) -> float:
    """Score 0..1 on how much LM agreed with regex on cross-validated fields."""
    checks: list[bool] = []

    regex_cases = {c.canonical for c in regex_hints.get("case_numbers", []) if c.canonical}
    if regex_cases and lm.title:
        checks.append(any(c in (lm.title or "") or c in (lm.subject_matter or "")
                          for c in regex_cases))

    regex_dates = {d.iso for d in regex_hints.get("dates", [])}
    if regex_dates and lm.primary_date_iso:
        checks.append(lm.primary_date_iso in regex_dates)

    if not checks:
        return 0.5  # nothing to validate; neutral
    return sum(checks) / len(checks)


__all__ = ["LMExtractor", "LMOutput", "merge_to_rich"]
