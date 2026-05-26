"""Rich, typed, normalized findings schema for litigation evidence.

Goals:
  - Diversified fields covering temporal, identifiers, parties, financial,
    legal substance, semantic, custodial, and risk dimensions.
  - Normalized values: dates as ISO 8601, money as Decimal + ISO 4217,
    case numbers in source format with parsed components.
  - Field-level confidence so retrieval can weight by trust.
  - Source spans for every extracted value (which char range / page).
  - Designed for split extraction: regex layer fills deterministic
    fields; LM fills semantic fields; both agree → high confidence.

The Pydantic model is the source of truth. The same JSON shape is stored
in documents.findings (jsonb) and embedded into chunks for retrieval.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Optional, Annotated

from pydantic import BaseModel, Field, field_validator, ConfigDict


# --------------------------------------------------------------------------- #
# Controlled vocabularies                                                     #
# --------------------------------------------------------------------------- #

class DocumentKind(str, Enum):
    # Court filings
    complaint = "complaint"
    answer = "answer"
    counterclaim = "counterclaim"
    petition = "petition"
    motion = "motion"
    brief = "brief"
    memorandum = "memorandum"
    order = "order"
    judgment = "judgment"
    notice = "notice"
    summons = "summons"
    subpoena = "subpoena"
    citation = "citation"
    warrant = "warrant"
    # Discovery
    discovery_request = "discovery_request"
    discovery_response = "discovery_response"
    interrogatory = "interrogatory"
    rfp = "request_for_production"
    rfa = "request_for_admission"
    deposition_transcript = "deposition_transcript"
    court_transcript = "court_transcript"
    # Sworn statements
    affidavit = "affidavit"
    declaration = "declaration"
    verification = "verification"
    # Service/proof
    proof_of_service = "proof_of_service"
    return_of_service = "return_of_service"
    certificate_of_service = "certificate_of_service"
    # Evidence
    exhibit = "exhibit"
    exhibit_list = "exhibit_list"
    # Contracts/transactional
    contract = "contract"
    addendum = "addendum"
    lease = "lease"
    promissory_note = "promissory_note"
    deed = "deed"
    # Financial
    bank_statement = "bank_statement"
    credit_card_statement = "credit_card_statement"
    tax_return = "tax_return"
    invoice = "invoice"
    receipt = "receipt"
    # Records
    medical_record = "medical_record"
    psych_evaluation = "psych_evaluation"
    police_report = "police_report"
    incident_report = "incident_report"
    cps_report = "cps_report"
    foster_care_record = "foster_care_record"
    # Correspondence
    letter = "letter"
    email_print = "email_print"
    memo = "memo"
    # Misc
    regulatory_filing = "regulatory_filing"
    license = "license"
    insurance_policy = "insurance_policy"
    application = "application"
    report = "report"
    docket_sheet = "docket_sheet"
    other = "other"


class ProceduralPosture(str, Enum):
    pre_filing = "pre_filing"
    pleading = "pleading"
    discovery = "discovery"
    motion_pending = "motion_pending"
    pre_trial = "pre_trial"
    trial = "trial"
    post_trial_motion = "post_trial_motion"
    appeal = "appeal"
    post_judgment = "post_judgment"
    closed = "closed"
    unknown = "unknown"


class ToneRegister(str, Enum):
    formal = "formal"
    neutral = "neutral"
    casual = "casual"
    hostile = "hostile"
    urgent = "urgent"
    threatening = "threatening"
    deferential = "deferential"


class Intent(str, Enum):
    persuade = "persuade"        # advocacy / argument
    inform = "inform"            # report / notify
    request = "request"          # ask for action
    require = "require"          # order / command
    comply = "comply"            # response to demand
    document = "document"        # record a fact
    contest = "contest"          # dispute / challenge
    settle = "settle"            # negotiate / resolve
    other = "other"


class LegalSentiment(str, Enum):
    favorable_to_self = "favorable_to_self"
    favorable_to_opposing = "favorable_to_opposing"
    neutral = "neutral"
    mixed = "mixed"
    indeterminate = "indeterminate"


class PrivilegeMarker(str, Enum):
    none = "none"
    attorney_client = "attorney_client"
    work_product = "work_product"
    settlement_communication = "settlement_communication"
    physician_patient = "physician_patient"
    psychotherapist_patient = "psychotherapist_patient"
    spousal = "spousal"
    self_incrimination = "self_incrimination"
    unclear = "unclear"


# --------------------------------------------------------------------------- #
# Sub-models                                                                  #
# --------------------------------------------------------------------------- #

class SourceSpan(BaseModel):
    """Where in the source document this value came from."""
    char_start: Optional[int] = None
    char_end: Optional[int] = None
    page: Optional[int] = None
    line: Optional[int] = None
    quoted_text: Optional[str] = Field(None, description="Verbatim quote, max 200 chars")

    @field_validator("quoted_text")
    @classmethod
    def _truncate_quote(cls, v):
        if v and len(v) > 200:
            return v[:197] + "..."
        return v


class CaseNumber(BaseModel):
    """A court case number, parsed into components."""
    raw: str = Field(..., description="As it appears in source")
    canonical: Optional[str] = Field(None, description="Normalized form, e.g. 'EXAMPLE-MATTER-001'")
    year: Optional[int] = None
    case_type_code: Optional[str] = Field(None, description="JC|CF|FA|TP|CV|CR|JD etc")
    sequence: Optional[int] = None
    jurisdiction: Optional[str] = Field(None, description="e.g. 'Example State Example County'")
    court: Optional[str] = None
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    source: SourceSpan = Field(default_factory=SourceSpan)


class StatuteCitation(BaseModel):
    """A statutory or regulatory citation."""
    raw: str
    canonical: Optional[str] = Field(None, description="e.g. 'wis.stat.48.42.1'")
    jurisdiction: Optional[str] = Field(None, description="federal | wisconsin | minnesota | ...")
    code: Optional[str] = Field(None, description="USC | CFR | WisStat | WisAdmCode | ...")
    title: Optional[str] = None
    section: Optional[str] = None
    subsection: Optional[str] = None
    source: SourceSpan = Field(default_factory=SourceSpan)


class CaseLawCitation(BaseModel):
    """A reference to case law."""
    raw: str
    case_name: Optional[str] = None
    reporter: Optional[str] = None
    volume: Optional[int] = None
    page: Optional[int] = None
    year: Optional[int] = None
    court: Optional[str] = None
    source: SourceSpan = Field(default_factory=SourceSpan)


class DateReference(BaseModel):
    """A date mentioned in the document, normalized."""
    iso: str = Field(..., description="ISO 8601 date or datetime")
    raw: str = Field(..., description="As written in source")
    context: Optional[str] = Field(None, description="What this date refers to")
    certainty: str = Field("explicit", description="explicit | inferred | approximate")
    source: SourceSpan = Field(default_factory=SourceSpan)

    @field_validator("iso")
    @classmethod
    def _validate_iso(cls, v):
        # Accept date or datetime. Will raise if neither.
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m"):
            try:
                datetime.strptime(v, fmt)
                return v
            except ValueError:
                continue
        # Try fromisoformat (handles +tz)
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
            return v
        except ValueError:
            raise ValueError(f"date {v!r} is not ISO 8601")


class MonetaryAmount(BaseModel):
    """A money value, normalized."""
    value: Decimal = Field(..., description="Decimal amount, never a string")
    currency: str = Field("USD", description="ISO 4217 code")
    raw: str = Field(..., description="As written in source")
    context: Optional[str] = Field(None, description="filing_fee | damages | child_support | etc")
    is_estimate: bool = False
    source: SourceSpan = Field(default_factory=SourceSpan)

    model_config = ConfigDict(json_encoders={Decimal: str})

    @field_validator("currency")
    @classmethod
    def _validate_currency(cls, v):
        if not re.fullmatch(r"[A-Z]{3}", v):
            raise ValueError(f"currency {v!r} must be ISO 4217 (3 uppercase letters)")
        return v


class PartyMention(BaseModel):
    """A person/org mentioned in the document, with role."""
    name: str
    role: Optional[str] = Field(None, description="petitioner|respondent|plaintiff|defendant|witness|attorney|judge|gal|caseworker|etc")
    aliases: list[str] = Field(default_factory=list)
    address: Optional[str] = None
    dob: Optional[str] = Field(None, description="ISO date if known")
    bar_number: Optional[str] = Field(None, description="If attorney")
    badge_number: Optional[str] = Field(None, description="If law enforcement")
    canonical_party_id: Optional[str] = Field(None, description="UUID of resolved parties row, if matched")
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    source: SourceSpan = Field(default_factory=SourceSpan)


class KeyQuote(BaseModel):
    """A verbatim quote of legal significance."""
    text: str = Field(..., description="≤500 chars")
    significance: Optional[str] = Field(None, description="Why this quote matters")
    speaker: Optional[str] = None
    page: Optional[int] = None

    @field_validator("text")
    @classmethod
    def _cap(cls, v):
        if len(v) > 500:
            raise ValueError("key quote > 500 chars; chunk first")
        return v


class HearingEvent(BaseModel):
    """A scheduled or completed court event mentioned in the doc."""
    type: str = Field(..., description="status_conference|trial|motion_hearing|etc")
    date_iso: Optional[str] = None
    time: Optional[str] = None
    location: Optional[str] = None
    judge: Optional[str] = None
    is_future: Optional[bool] = None


class RiskFlags(BaseModel):
    """Boolean flags for downstream gating."""
    mentions_minors: bool = False
    minor_names: list[str] = Field(default_factory=list)
    mentions_phi: bool = False
    mentions_financial_account_numbers: bool = False
    mentions_ssn: bool = False
    mentions_drug_use: bool = False
    mentions_mental_health: bool = False
    mentions_violence: bool = False
    mentions_sexual_content: bool = False
    privilege_marker: PrivilegeMarker = PrivilegeMarker.none
    redaction_recommended: bool = False
    redaction_reason: Optional[str] = None


class CustodyMarkers(BaseModel):
    """Who handled this and how."""
    is_signed: bool = False
    signatory_names: list[str] = Field(default_factory=list)
    is_certified_copy: bool = False
    is_notarized: bool = False
    is_court_filed: bool = False
    filed_date_iso: Optional[str] = None
    is_redacted: bool = False
    has_bates_numbers: bool = False
    bates_range: Optional[str] = Field(None, description="e.g. 'PROD000001-PROD000050'")
    service_method: Optional[str] = Field(None, description="mail|electronic|personal|publication")
    custodian_named: Optional[str] = None


class QualityMetadata(BaseModel):
    """How and how confidently this was extracted."""
    extraction_model: str
    extraction_version: str = "1.0"
    extracted_at_iso: str
    overall_confidence: float = Field(0.5, ge=0.0, le=1.0)
    field_confidences: dict[str, float] = Field(default_factory=dict)
    flags_for_human_review: list[str] = Field(default_factory=list)
    regex_lm_agreement_score: Optional[float] = Field(
        None, ge=0.0, le=1.0,
        description="0=disagree, 1=full agreement on cross-validated fields"
    )
    truncated: bool = Field(False, description="Was source text truncated to fit context window?")
    cross_validated_with: Optional[str] = Field(
        None, description="Second model name if a re-pass was performed"
    )


# --------------------------------------------------------------------------- #
# Top-level findings                                                          #
# --------------------------------------------------------------------------- #

class RichFindings(BaseModel):
    """The complete enrichment record for a single document.

    Stored in documents.findings (jsonb). Used by embed_chunks to build
    the structured prefix that augments raw chunk text before embedding.
    """

    # ---- identity & classification ----
    document_kind: DocumentKind
    document_kind_other: Optional[str] = None
    document_kind_confidence: float = Field(0.5, ge=0.0, le=1.0)

    title: Optional[str] = Field(None, description="Document title or caption if present")
    language: str = Field("en", description="ISO 639-1")
    word_count: Optional[int] = None

    # ---- temporal ----
    primary_date_iso: Optional[str] = Field(
        None, description="The single most-relevant date for this doc"
    )
    primary_date_kind: Optional[str] = Field(
        None, description="filed|signed|effective|received|created"
    )
    dates: list[DateReference] = Field(default_factory=list)
    time_period_start_iso: Optional[str] = None
    time_period_end_iso: Optional[str] = None

    # ---- identifiers ----
    case_numbers: list[CaseNumber] = Field(default_factory=list)
    statutes: list[StatuteCitation] = Field(default_factory=list)
    case_law: list[CaseLawCitation] = Field(default_factory=list)
    docket_numbers: list[str] = Field(default_factory=list)
    exhibit_labels: list[str] = Field(default_factory=list)

    # ---- parties ----
    parties: list[PartyMention] = Field(default_factory=list)
    primary_petitioner: Optional[str] = None
    primary_respondent: Optional[str] = None
    judge: Optional[str] = None
    presiding_court: Optional[str] = None
    attorneys: list[PartyMention] = Field(default_factory=list)
    agencies: list[PartyMention] = Field(default_factory=list)

    # ---- financial ----
    monetary_amounts: list[MonetaryAmount] = Field(default_factory=list)
    total_amount_in_dispute: Optional[MonetaryAmount] = None

    # ---- legal substance ----
    causes_of_action: list[str] = Field(
        default_factory=list,
        description="e.g. 'breach of contract', 'TPR under Wis. Stat. § 48.415(2)'"
    )
    legal_issues: list[str] = Field(
        default_factory=list,
        description="Issue tags from a legal taxonomy"
    )
    relief_sought: list[str] = Field(default_factory=list)
    procedural_posture: ProceduralPosture = ProceduralPosture.unknown
    jurisdiction: Optional[str] = None
    venue: Optional[str] = None
    next_event: Optional[HearingEvent] = None

    # ---- semantic ----
    summary_one_sentence: str = Field(..., max_length=300)
    summary_paragraph: str = Field(..., max_length=2000)
    executive_findings: list[str] = Field(
        default_factory=list,
        description="Top 1-3 most legally significant facts"
    )
    key_quotes: list[KeyQuote] = Field(default_factory=list)
    topics: list[str] = Field(
        default_factory=list,
        description="Topic tags, e.g. 'tpr', 'icpc', 'foster_placement', 'methamphetamine'"
    )
    subject_matter: Optional[str] = Field(
        None, description="One-line subject, e.g. 'TPR petition — Example County DHS'"
    )

    # ---- tone & intent ----
    tone_register: ToneRegister = ToneRegister.neutral
    intent: Intent = Intent.document
    legal_sentiment: LegalSentiment = LegalSentiment.indeterminate
    urgency_level: int = Field(0, ge=0, le=3, description="0=none, 3=imminent deadline")

    # ---- custody / evidentiary ----
    custody: CustodyMarkers = Field(default_factory=CustodyMarkers)

    # ---- risk ----
    risk: RiskFlags = Field(default_factory=RiskFlags)

    # ---- quality ----
    quality: QualityMetadata


__all__ = [
    "RichFindings",
    "DocumentKind", "ProceduralPosture", "ToneRegister", "Intent",
    "LegalSentiment", "PrivilegeMarker",
    "CaseNumber", "StatuteCitation", "CaseLawCitation", "DateReference",
    "MonetaryAmount", "PartyMention", "KeyQuote", "HearingEvent",
    "RiskFlags", "CustodyMarkers", "QualityMetadata", "SourceSpan",
]
