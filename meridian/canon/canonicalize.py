"""RFC 8785 JSON Canonicalization Scheme (JCS) wrapper.

Spec reference: paper §8.1, R7. The Seal's chain_hash MUST be computed
over the canonical serialization of the Attestation with the seal field excluded.

This module wraps the rfc8785 PyPI package and adds a round-trip test
helper. Implementations across languages vary in maturity (paper §13);
production attestations should cross-validate against the JS reference
implementation per the spec's R7 implementer note.
"""

from __future__ import annotations

import json
from typing import Any

import rfc8785


def canonicalize(obj: Any) -> bytes:
    """Serialize a JSON-compatible object to RFC 8785 canonical bytes.

    Returns UTF-8 encoded canonical JSON.
    """
    return rfc8785.dumps(obj)


def canonicalize_for_seal(attestation: dict[str, Any]) -> bytes:
    """Canonicalize an Attestation dict with the seal field excluded.

    The seal block is never included in the input to chain_hash, even when
    present in the dict (R7).
    """
    if "seal" not in attestation:
        return canonicalize(attestation)
    seal_excluded = {k: v for k, v in attestation.items() if k != "seal"}
    return canonicalize(seal_excluded)


def roundtrip_check(obj: Any) -> bool:
    """Verify canonicalize(parse(canonicalize(obj))) == canonicalize(obj).

    Used in tests and as a self-check before relying on the implementation
    for production attestations (paper §5.2 R7 implementer note).
    """
    first = canonicalize(obj)
    parsed = json.loads(first.decode("utf-8"))
    second = canonicalize(parsed)
    return first == second
