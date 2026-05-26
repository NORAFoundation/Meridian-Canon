"""Test fixtures: ephemeral key directory and a builder for valid Attestations."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture(autouse=True)
def isolated_keystore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Force key files into a per-test directory; do not touch real Keychain."""
    monkeypatch.setenv("MERIDIAN_KEY_DIR", str(tmp_path / "keys"))

    # Replace keyring backend with an in-memory fake so tests never touch Keychain.
    import keyring
    from keyring.backend import KeyringBackend

    class _MemoryKeyring(KeyringBackend):
        priority = 1  # type: ignore[assignment]

        def __init__(self) -> None:
            self._store: dict[tuple[str, str], str] = {}

        def set_password(self, service: str, username: str, password: str) -> None:
            self._store[(service, username)] = password

        def get_password(self, service: str, username: str) -> str | None:
            return self._store.get((service, username))

        def delete_password(self, service: str, username: str) -> None:
            self._store.pop((service, username), None)

    keyring.set_keyring(_MemoryKeyring())

    # Reload keys module so it picks up the new MERIDIAN_KEY_DIR.
    import importlib
    from meridian.canon import keys as keys_module
    importlib.reload(keys_module)
    return tmp_path


@pytest.fixture
def sample_attestation_dict() -> dict[str, Any]:
    """A minimal valid Attestation (pre-seal) for round-trip tests."""
    return {
        "canon_version": "0.1.1",
        "attestation_id": "01H4P2JYZ5C9G8K3F7M1N6B0Q2R4S0V",
        "kind": "observation",
        "issued_at": "2026-04-18T14:22:33.451Z",
        "issuer": "meridian-canon.local/test",
        "subject": "Test observation",
        "witness": [
            {
                "observation_id": "obs-01ABCDEFGHJKMNPQRSTVWXYZ01",
                "source": "test://example",
                "received_at": "2026-04-18T14:22:30.100Z",
                "custody_chain": [],
                "content_hash": "sha256:" + "a" * 64,
                "content_ref": "test://example/raw",
                "content_inline": None,
            }
        ],
        "findings": {
            "method": "Test observation method.",
            "claims": [
                {
                    "claim_id": "claim-01ABCDEF-001",
                    "statement": "The bytes were observed.",
                    "supports": ["obs-01ABCDEFGHJKMNPQRSTVWXYZ01"],
                    "inference_type": "observation",
                    "gaps": [],
                }
            ],
        },
        "refutation": {
            "challenges": [
                {
                    "challenge_id": "chal-01ABCDEF-replay",
                    "type": "replay",
                    "targets": ["claim-01ABCDEF-001"],
                    "input": "recompute SHA-256 over content_ref bytes",
                    "outcome": "survived",
                    "revisions": None,
                }
            ],
            "coverage": {
                "applied": ["replay"],
                "declined": [
                    {"type": "adversarial_prompt", "reason": "no_findings_to_contest"},
                    {"type": "consistency_check", "reason": "no_entity_claims"},
                    {"type": "coverage_audit", "reason": "applies_at_batch_level_not_per_observation"},
                    {"type": "counter_evidence", "reason": "no_inferential_claims"},
                ],
            },
        },
    }
