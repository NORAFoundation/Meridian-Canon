"""meridian.forensics — Forensic science audit tools for Canon-conformant attestations.

Provides three audit modules:
  - SAMHSA chain-of-custody audit (coc-audit CLI command)
  - Toxicology one-compartment PK plausibility audit (kinetics CLI command)
  - Literature-RAG challenge for contested-assay questions (lit-challenge CLI command)

Each module exposes a query/specimen model, an audit function, and an attestation builder.
"""

from meridian.forensics.coc import Specimen, build_coc_audit_attestation
from meridian.forensics.kinetics import (
    KineticsQuery,
    audit_kinetics,
    build_kinetics_attestation,
    load_constants,
)
from meridian.forensics.lit import (
    LitQuery,
    build_lit_challenge_attestation,
    run_lit_challenge,
)

__all__ = [
    # CoC
    "Specimen",
    "build_coc_audit_attestation",
    # Kinetics
    "KineticsQuery",
    "audit_kinetics",
    "build_kinetics_attestation",
    "load_constants",
    # Lit challenge
    "LitQuery",
    "build_lit_challenge_attestation",
    "run_lit_challenge",
]
