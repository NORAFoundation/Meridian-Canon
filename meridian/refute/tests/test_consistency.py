"""Consistency check tests."""

from __future__ import annotations

from meridian.refute.consistency import consistency_check


def test_no_entities_survives() -> None:
    result = consistency_check("This is a claim with no entities.")
    assert result["outcome"] == "survived"


def test_no_registry_is_error_not_survived() -> None:
    """AUDIT-FIX (R2): when entities were extracted but no registry is
    available, the check could not run. It must report ERROR (inconclusive)
    with a decline_reason — NOT survived. The old behavior asserted
    'survived', which laundered the absence of a consistency check into a
    successful one. Updated to assert the corrected, honest outcome.
    """
    result = consistency_check("Sender is sender@example.com.")
    assert result["outcome"] == "error"
    assert result.get("decline_reason") == "no_entity_registry_available"


def test_consistent_with_registry() -> None:
    def lookup(entity: str) -> list[dict]:
        return [{"claim_id": "claim-OLD-1", "statement": "Sender is sender@example.com.", "attestation_id": "att-1"}]

    result = consistency_check(
        "Sender is sender@example.com on 2026-04-01.",
        registry_lookup=lookup,
    )
    assert result["outcome"] == "survived"


def test_negation_contradiction() -> None:
    def lookup(entity: str) -> list[dict]:
        return [{"claim_id": "claim-OLD-1", "statement": "Sender is sender@example.com.", "attestation_id": "att-1"}]

    result = consistency_check(
        "Sender is not sender@example.com.",
        registry_lookup=lookup,
    )
    assert result["outcome"] == "revised"
    assert result["revisions"][0]["contradicting_claim_id"] == "claim-OLD-1"


def test_amount_mismatch_contradiction() -> None:
    def lookup(entity: str) -> list[dict]:
        return [{"claim_id": "claim-OLD-1", "statement": "Amount due is $5,000.00.", "attestation_id": "att-1"}]

    result = consistency_check(
        "Amount due is $7,500.00.",
        registry_lookup=lookup,
    )
    assert result["outcome"] == "revised"


def test_date_mismatch_contradiction() -> None:
    def lookup(entity: str) -> list[dict]:
        return [{"claim_id": "claim-OLD-1", "statement": "Hearing is 2026-05-01.", "attestation_id": "att-1"}]
    result = consistency_check("Hearing is 2026-06-15.", registry_lookup=lookup)
    assert result["outcome"] == "revised"
