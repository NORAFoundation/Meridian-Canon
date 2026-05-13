"""BriefAttestation builder + PDF render tests."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path

import pytest

from meridian.canon import emit, keys, signing
from meridian.export import build_brief_attestation, BriefSynthesizer, render_brief_pdf


CUSTODIAN = "brief-test"


@dataclass
class EchoSynth:
    """Stub adapter that returns a fixed synthesis. For tests."""
    name: str = "echo-synth"
    response: str = "This is the synthesized brief.\n\nIt covers the supplied sources."

    def complete(self, prompt: str, *, max_tokens: int = 2000, temperature: float = 0.0) -> str:
        return self.response


@pytest.fixture
def published_keypair(tmp_path: Path) -> tuple[str, str]:
    private, public, fingerprint = keys.keygen(CUSTODIAN)
    pem = signing.public_key_to_pem(public)
    pem_path = tmp_path / "brief.pem"
    pem_path.write_bytes(pem)
    return fingerprint, f"file://{pem_path}"


def _fake_source(att_id: str, kind: str = "enrichment") -> dict:
    return {
        "attestation_id": att_id,
        "kind": kind,
        "issued_at": "2026-04-18T14:22:33.451Z",
        "subject": f"Test source {att_id}",
        "findings": {"claims": [
            {"claim_id": f"claim-{att_id}-1", "statement": f"Source {att_id} asserts something.",
             "inference_type": "deduction", "supports": ["obs-x"], "gaps": ["test gap"]},
        ]},
        "seal": {"chain_hash": "sha256:" + "a" * 64},
    }


def test_synthesizer_produces_expected_text() -> None:
    synth = BriefSynthesizer(EchoSynth(response="Synthesized output."))
    out = synth.synthesize(
        subject="TPR chronology",
        sources=[_fake_source("01ABC"), _fake_source("01DEF")],
    )
    assert out == "Synthesized output."


def test_brief_attestation_seals_and_walks(published_keypair: tuple[str, str]) -> None:
    fingerprint, url = published_keypair
    sources = [_fake_source("01ABC"), _fake_source("01DEF", kind="search")]
    body = "First paragraph of the brief.\n\nSecond paragraph cites (att:01ABC) and (att:01DEF)."
    att = build_brief_attestation(
        subject="TPR chronology",
        body_text=body,
        sources=sources,
        issuer="brief-issuer",
        matter_id="22222222-2222-2222-2222-222222222222",
        custodian=CUSTODIAN,
        synthesis_model="echo-synth",
    )
    sealed = emit.emit(att, custodian=CUSTODIAN, public_key_url=url, fingerprint=fingerprint)
    assert sealed["kind"] == "brief"
    from meridian.canon import walk
    result = walk.walk(sealed)
    assert result["verdict"] == "valid", result


def test_brief_witness_inlines_body_and_binds_sources(published_keypair: tuple[str, str]) -> None:
    fingerprint, url = published_keypair
    sources = [_fake_source("01ABC")]
    body = "Test body."
    att = build_brief_attestation(
        subject="x", body_text=body, sources=sources, issuer="t",
        matter_id=None, custodian=CUSTODIAN, synthesis_model="echo",
    )
    # Body inline.
    body_w = next(w for w in att["witness"] if w["source"].startswith("synthesis://"))
    decoded = base64.b64decode(body_w["content_inline"])
    assert decoded == body.encode("utf-8")
    expected_hash = "sha256:" + hashlib.sha256(decoded).hexdigest()
    assert body_w["content_hash"] == expected_hash
    # Source binding: the brief recomputes the source's canonical hash.
    src_w = next(w for w in att["witness"] if w["source"] == "attestation://01ABC")
    src_canonical = base64.b64decode(src_w["content_inline"])
    expected_src_hash = "sha256:" + hashlib.sha256(src_canonical).hexdigest()
    assert src_w["content_hash"] == expected_src_hash


def test_brief_pdf_renders(published_keypair: tuple[str, str], tmp_path: Path) -> None:
    fingerprint, url = published_keypair
    sources = [_fake_source("01ABC"), _fake_source("01DEF")]
    body = "Para one.\n\nPara two referring to att:01ABC and att:01DEF."
    att = build_brief_attestation(
        subject="Test brief", body_text=body, sources=sources, issuer="t",
        matter_id=None, custodian=CUSTODIAN, synthesis_model="echo",
    )
    sealed = emit.emit(att, custodian=CUSTODIAN, public_key_url=url, fingerprint=fingerprint)
    out_path = tmp_path / "brief.pdf"
    render_brief_pdf(sealed, out_path=out_path)
    assert out_path.exists()
    # Sanity-check that the PDF is non-trivially sized.
    assert out_path.stat().st_size > 1000
    # Header bytes.
    assert out_path.read_bytes().startswith(b"%PDF")


def test_supports_closure_in_brief() -> None:
    """R3: every claim's supports must resolve to a witness observation_id."""
    sources = [_fake_source("01ABC"), _fake_source("01DEF")]
    att = build_brief_attestation(
        subject="x", body_text="b", sources=sources, issuer="t",
        matter_id=None, custodian=CUSTODIAN, synthesis_model="echo",
    )
    obs_ids = {w["observation_id"] for w in att["witness"]}
    for c in att["findings"]["claims"]:
        for s in c["supports"]:
            assert s in obs_ids, f"unresolved support {s}"
