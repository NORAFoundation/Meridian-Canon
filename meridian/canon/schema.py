"""Pydantic models matching canon.schema.json v0.1.0.

Spec reference: Meridian-Canon-Revised.tex §4.1.2 (four-stage chain),
§5 (conformance requirements R1-R9), §6.10 (attestation kinds).

These models enforce structural validity (R1) at construction time. Other
requirements (R2 content integrity, R3 supports closure, R5 gap disclosure,
R6 refutation completeness) are enforced at emission time in emit.py.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


CANON_VERSION = "0.1.1"
CANON_VERSION_DSSE = "0.2.0"
_SUPPORTED_VERSIONS = {CANON_VERSION, CANON_VERSION_DSSE}


# --- Enums ----------------------------------------------------------------


class InferenceType(str, Enum):
    """Closed vocabulary per R4 (paper §6.5.3)."""

    OBSERVATION = "observation"
    DEDUCTION = "deduction"
    INDUCTION = "induction"
    ABDUCTION = "abduction"
    COMPOUND = "compound"


class ChallengeType(str, Enum):
    """Five challenge types per paper §6.6.1."""

    REPLAY = "replay"
    ADVERSARIAL_PROMPT = "adversarial_prompt"
    CONSISTENCY_CHECK = "consistency_check"
    COVERAGE_AUDIT = "coverage_audit"
    COUNTER_EVIDENCE = "counter_evidence"


class ChallengeOutcome(str, Enum):
    """Per paper §6.6.2."""

    SURVIVED = "survived"
    FAILED = "failed"
    REVISED = "revised"
    CONTESTED = "contested"  # Tri-Model Consensus all-disagree case


class AttestationKind(str, Enum):
    """Four attestation kinds per paper §6.10 plus audit."""

    OBSERVATION = "observation"
    ENRICHMENT = "enrichment"
    SEARCH = "search"
    BRIEF = "brief"
    AUDIT = "audit"


# --- Witness block --------------------------------------------------------


class CustodyEvent(BaseModel):
    """A custody-chain entry per paper §6.2."""

    custodian: str = Field(..., description="Identifier of the data custodian at this transition")
    received_at: str = Field(..., description="RFC 3339 microsecond UTC timestamp")
    signature: Optional[str] = Field(None, description="Optional signature over this transition")


class WitnessEntry(BaseModel):
    """One observation: hashed bytes plus custody chain (R2)."""

    observation_id: str = Field(..., pattern=r"^obs-[A-Za-z0-9_-]+$")
    source: str = Field(..., description="URI identifying the upstream source of these bytes")
    received_at: str
    custody_chain: list[CustodyEvent] = Field(default_factory=list)
    content_hash: str = Field(..., pattern=r"^sha256:[0-9a-f]{64}$")
    content_ref: Optional[str] = Field(None, description="Retrievable URI for the bytes")
    content_inline: Optional[str] = Field(None, description="Base64 inline content (if no content_ref)")

    @model_validator(mode="after")
    def _content_retrievable(self) -> "WitnessEntry":
        if self.content_ref is None and self.content_inline is None:
            raise ValueError("WitnessEntry MUST have either content_ref or content_inline (R2)")
        return self


# --- Findings block -------------------------------------------------------


class Claim(BaseModel):
    """A typed claim with explicit supports and gaps (R3, R4, R5)."""

    claim_id: str = Field(..., pattern=r"^claim-[A-Za-z0-9_-]+$")
    statement: str
    supports: list[str] = Field(..., min_length=1)
    inference_type: InferenceType
    gaps: list[str] = Field(default_factory=list)
    revisions: Optional[list[dict[str, Any]]] = None

    @model_validator(mode="after")
    def _gap_disclosure(self) -> "Claim":
        # R5: non-observational claims MUST enumerate at least one gap.
        if self.inference_type != InferenceType.OBSERVATION and not self.gaps:
            raise ValueError(
                f"Claim {self.claim_id} of inference_type {self.inference_type} "
                "must declare at least one gap (R5)"
            )
        return self


class Findings(BaseModel):
    """Findings block: typed claims plus method metadata."""

    method: str = Field(..., description="Free text describing how the claims were produced")
    claims: list[Claim] = Field(default_factory=list)


# --- Refutation block -----------------------------------------------------


class Challenge(BaseModel):
    """One applied challenge per paper §6.6."""

    challenge_id: str = Field(..., pattern=r"^chal-[A-Za-z0-9_-]+$")
    type: ChallengeType
    targets: list[str] = Field(..., min_length=1)
    input: str
    outcome: ChallengeOutcome
    revisions: Optional[Any] = None
    model_config = ConfigDict(protected_namespaces=())
    model_outcomes: Optional[dict[str, ChallengeOutcome]] = Field(
        None, description="Per-model outcomes for Tri-Model Consensus (paper §6.6.1)"
    )
    consensus_outcome: Optional[ChallengeOutcome] = None


class DeclinedChallenge(BaseModel):
    """A challenge type intentionally not applied, with machine-readable reason (R6)."""

    type: ChallengeType
    reason: str = Field(..., min_length=1)


class Coverage(BaseModel):
    """Inventory of applied vs declined challenge types (R6)."""

    applied: list[ChallengeType] = Field(default_factory=list)
    declined: list[DeclinedChallenge] = Field(default_factory=list)


class Refutation(BaseModel):
    """Refutation block: challenges plus coverage."""

    challenges: list[Challenge] = Field(..., min_length=1)
    coverage: Coverage

    @model_validator(mode="after")
    def _refutation_complete(self) -> "Refutation":
        # R6: must have at least one challenge AND coverage with both lists.
        if not self.challenges:
            raise ValueError("Refutation must contain at least one Challenge (R6)")
        return self


# --- Seal block -----------------------------------------------------------


class Seal(BaseModel):
    """Cryptographic binding (R7, R8)."""

    chain_hash: str = Field(..., pattern=r"^sha256:[0-9a-f]{64}$")
    canonicalization: str = Field("rfc8785", description="MUST be 'rfc8785' for v0.1.1")
    signature_algorithm: str = Field("ed25519", description="MUST be 'ed25519' for v0.1.1")
    signature: str = Field(..., description="Base64-encoded Ed25519 signature over chain_hash bytes")
    public_key_fingerprint: str = Field(..., pattern=r"^sha256:[0-9a-f]{64}$")
    public_key_url: str = Field(..., description="Stable URL hosting the issuer's PEM public key")


# --- DSSE envelope --------------------------------------------------------


class DSSESignature(BaseModel):
    """One signer's contribution to a DSSE envelope."""

    keyid: str = Field(..., description="sha256: fingerprint of the public key")
    sig: str = Field(..., description="base64url DSSE signature over PAE(payloadType, payload)")
    public_key_url: str = Field(..., description="Stable URL hosting the issuer's PEM public key (R8)")


class DSSEEnvelope(BaseModel):
    """DSSE outer envelope wrapping a Canon Attestation payload (v0.2.0)."""

    payload_type: str = Field(
        default="application/vnd.nora.canon.attestation+json; version=0.2.0"
    )
    payload: str = Field(..., description="base64-encoded canonical Attestation JSON bytes (seal field excluded)")
    signatures: list[DSSESignature] = Field(..., min_length=1)
    chain_hash: str = Field(
        ...,
        pattern=r"^sha256:[0-9a-f]{64}$",
        description="sha256 of canonical payload bytes; convenience field for verifiers",
    )


# --- Attestation envelope -------------------------------------------------


class Attestation(BaseModel):
    """Full Canon-conformant Attestation (R1)."""

    canon_version: str = Field(CANON_VERSION)
    attestation_id: str = Field(..., pattern=r"^[A-Z0-9]+$", description="ULID")
    kind: AttestationKind
    issued_at: str
    issuer: str
    matter_id: Optional[UUID] = Field(None, description="Per paper §6.2 procedural substrate")
    subject: str
    witness: list[WitnessEntry] = Field(..., min_length=1)
    findings: Findings
    refutation: Refutation
    seal: Optional[Seal] = Field(None, description="Populated only after emit.py runs")

    @field_validator("canon_version")
    @classmethod
    def _version(cls, v: str) -> str:
        if v not in _SUPPORTED_VERSIONS:
            raise ValueError(
                f"Unsupported canon_version {v!r}; this verifier supports {sorted(_SUPPORTED_VERSIONS)}"
            )
        return v

    @model_validator(mode="after")
    def _supports_closure(self) -> "Attestation":
        """R3: every claim's supports must resolve to an observation_id in this Witness
        or to a claim_id earlier in this Findings. Forward references prohibited.
        """
        observation_ids = {w.observation_id for w in self.witness}
        seen_claim_ids: set[str] = set()
        for claim in self.findings.claims:
            for support in claim.supports:
                if support in observation_ids:
                    continue
                if support in seen_claim_ids:
                    continue
                raise ValueError(
                    f"Claim {claim.claim_id} references unresolved support {support} (R3)"
                )
            seen_claim_ids.add(claim.claim_id)

        # Refutation targets must resolve to claim_ids defined in Findings.
        for challenge in self.refutation.challenges:
            for target in challenge.targets:
                if target not in seen_claim_ids:
                    raise ValueError(
                        f"Challenge {challenge.challenge_id} targets unresolved {target}"
                    )
        return self
