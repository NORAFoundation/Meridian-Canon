"""NORA Canon v0.1.0 conformance layer.

Public surface:
    schema.py        — Pydantic models for Attestation / Witness / Findings / Refutation / Seal
    canonicalize.py  — RFC 8785 JCS serialization
    hashing.py       — SHA-256 chain hash over canonical JSON
    signing.py       — Ed25519 sign/verify (PyNaCl)
    keys.py          — Keypair generation; macOS Keychain integration; PEM export
    emit.py          — Build, canonicalize, hash, sign, persist
    walk.py          — Reference verifier (seven-step falsification protocol)
    cli.py           — Command-line entry point
"""

from .schema import (
    Attestation,
    AttestationKind,
    Challenge,
    ChallengeOutcome,
    ChallengeType,
    Claim,
    Coverage,
    DeclinedChallenge,
    Findings,
    InferenceType,
    Refutation,
    Seal,
    WitnessEntry,
)

__all__ = [
    "Attestation",
    "AttestationKind",
    "Challenge",
    "ChallengeOutcome",
    "ChallengeType",
    "Claim",
    "Coverage",
    "DeclinedChallenge",
    "Findings",
    "InferenceType",
    "Refutation",
    "Seal",
    "WitnessEntry",
]
