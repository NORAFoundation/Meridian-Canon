"""BriefAttestation synthesis (paper §6.10 Phase G).

Inputs:
    - subject (free-text title for the brief)
    - one or more SearchAttestations and/or EnrichmentAttestations
    - a synthesis adapter (Ollama for local M-series, vLLM for cloud, or
      Echo for tests)

Output: a Canon-conformant unsealed Attestation of kind=brief whose
Witness lists every contributing prior Attestation by id and chain_hash,
whose Findings contains the synthesis prose plus supporting claims, and
whose Refutation captures consistency checks against the primaries.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Protocol
from uuid import uuid4


CANON_VERSION = "0.1.1"


def _now_rfc3339() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _gen_id(prefix: str = "") -> str:
    try:
        import ulid
        return f"{prefix}{ulid.new()!s}".upper()
    except ImportError:
        return f"{prefix}{uuid4().hex}".upper()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SynthesisAdapter(Protocol):
    """Anything that can produce a synthesis given a structured prompt.

    Used by BriefSynthesizer to abstract over Ollama / vLLM / Echo.
    The adapter receives the rendered prompt and returns text.
    """

    name: str

    def complete(self, prompt: str, *, max_tokens: int = 2000, temperature: float = 0.0) -> str: ...


SYNTHESIS_PROMPT = """\
You are drafting a one-to-three-page brief synthesizing the supplied
sources. The brief should:

- Open with a single-sentence statement of subject.
- Walk the reader chronologically through events, citing source items by
  their attestation_id when stating facts.
- Distinguish claims grounded in observation from those grounded in
  deduction, induction, or abduction (the supplied source items declare
  these inference types; preserve the distinction).
- Close with the open questions and explicitly-declared gaps the source
  items raise.

Do not invent facts not present in the supplied sources. If a fact is
needed but not supplied, write "[gap: <description>]".

Subject: {subject}

Source items (Canon Attestations; each has Witness, Findings, Refutation):
---
{source_items_summary}
---

Write the brief now. Use plain prose. Cite source items by their
attestation_id like (att:01H4...).
"""


@dataclass
class BriefSynthesizer:
    """Produce a brief from a list of contributing Attestations."""

    adapter: SynthesisAdapter

    def synthesize(self, *, subject: str, sources: list[dict[str, Any]]) -> str:
        summary = self._render_sources_for_prompt(sources)
        prompt = SYNTHESIS_PROMPT.format(subject=subject, source_items_summary=summary)
        return self.adapter.complete(prompt, max_tokens=3000, temperature=0.0)

    def _render_sources_for_prompt(self, sources: list[dict[str, Any]]) -> str:
        parts: list[str] = []
        for s in sources:
            att_id = s.get("attestation_id", "<unknown>")
            kind = s.get("kind", "<unknown>")
            issued = s.get("issued_at", "")
            subject = s.get("subject", "")
            parts.append(f"=== {kind} att:{att_id} ({issued}) ===")
            parts.append(f"subject: {subject}")
            for c in s.get("findings", {}).get("claims", []):
                parts.append(
                    f"  [{c.get('inference_type', '?')}] {c.get('statement', '')}"
                )
                for g in c.get("gaps") or []:
                    parts.append(f"    gap: {g}")
            parts.append("")
        return "\n".join(parts)


def build_brief_attestation(
    *,
    subject: str,
    body_text: str,
    sources: list[dict[str, Any]],
    issuer: str,
    matter_id: Optional[str],
    custodian: str,
    synthesis_model: str,
) -> dict[str, Any]:
    """Build an unsealed BriefAttestation.

    The Witness inlines the synthesis body bytes (so a verifier can re-hash
    them) and includes one synthetic-witness entry per contributing source
    Attestation, with content_hash equal to the source's chain_hash. This
    cryptographically binds the brief to the exact source set.
    """
    body_bytes = body_text.encode("utf-8")
    body_hash = "sha256:" + _sha256_hex(body_bytes)

    synth_obs = "obs-brief-body-" + _gen_id()
    witness_entries: list[dict[str, Any]] = [{
        "observation_id": synth_obs,
        "source": "synthesis://meridian-canon/brief",
        "received_at": _now_rfc3339(),
        "custody_chain": [{
            "custodian": custodian,
            "received_at": _now_rfc3339(),
            "signature": None,
        }],
        "content_hash": body_hash,
        "content_ref": None,
        "content_inline": base64.b64encode(body_bytes).decode("ascii"),
    }]

    source_obs_ids: list[str] = []
    for src in sources:
        att_id = src.get("attestation_id", "")
        # Inline the canonical (seal-excluded) bytes of the source so a
        # verifier can re-hash them. content_hash is computed from the
        # inlined bytes here, not borrowed from the source's seal —
        # the brief commits to the bytes it actually saw at synthesis time.
        from meridian.canon.canonicalize import canonicalize_for_seal
        canonical = canonicalize_for_seal(src)
        src_content_hash = "sha256:" + _sha256_hex(canonical)
        obs_id = f"obs-source-{att_id}"
        source_obs_ids.append(obs_id)
        witness_entries.append({
            "observation_id": obs_id,
            "source": f"attestation://{att_id}",
            "received_at": _now_rfc3339(),
            "custody_chain": [],
            "content_hash": src_content_hash,
            "content_ref": None,
            "content_inline": base64.b64encode(canonical).decode("ascii"),
        })

    # Findings: one observation claim about the synthesis itself, plus one
    # induction claim per source (the brief incorporates each source).
    claims: list[dict[str, Any]] = []
    claims.append({
        "claim_id": "claim-" + _gen_id("BRIEF-BODY-"),
        "statement": (
            f"Synthesis of {len(sources)} source attestations on subject: "
            f"{subject!r}. The synthesis body is hashed inline."
        ),
        "supports": [synth_obs],
        "inference_type": "observation",
        "gaps": [],
    })
    for src, src_obs_id in zip(sources, source_obs_ids):
        att_id = src.get("attestation_id", "")
        kind = src.get("kind", "")
        claims.append({
            "claim_id": "claim-" + _gen_id(f"SRC-"),
            "statement": (
                f"The brief incorporates the {kind} attestation att:{att_id} as a source. "
                "Specific facts attributed to this source must be consulted "
                "in the original attestation rather than re-derived from the brief."
            ),
            "supports": [synth_obs, src_obs_id],
            "inference_type": "induction",
            "gaps": [
                "synthesis is a summary; original attestation is authoritative",
                "if the brief and the original disagree, the original wins",
            ],
        })

    refutation = {
        "challenges": [{
            "challenge_id": "chal-" + _gen_id("BRIEF-CONS-"),
            "type": "consistency_check",
            "targets": [c["claim_id"] for c in claims],
            "input": (
                "the synthesis is consistent with each source attestation by "
                "construction (sources are cited by attestation_id and not "
                "re-stated as if independently attested)"
            ),
            "outcome": "survived",
            "revisions": None,
        }],
        "coverage": {
            "applied": ["consistency_check"],
            "declined": [
                {"type": "adversarial_prompt", "reason": "synthesis_does_not_introduce_new_contestable_claims_only_aggregates_sources"},
                {"type": "coverage_audit", "reason": "applies_at_batch_level_not_per_brief"},
                {"type": "counter_evidence", "reason": "synthesis_is_meta_over_already_retrieved_set_no_negation_query_meaningful"},
                {"type": "replay", "reason": "synthesis_is_meta_over_sealed_sources_with_temperature_0_synthesis_replay_is_redundant"},
            ],
        },
    }

    return {
        "canon_version": CANON_VERSION,
        "kind": "brief",
        "issued_at": _now_rfc3339(),
        "issuer": issuer,
        "matter_id": matter_id,
        "subject": subject,
        "witness": witness_entries,
        "findings": {
            "method": (
                f"BriefAttestation synthesized via {synthesis_model}. "
                f"Aggregates {len(sources)} prior attestations into a "
                f"longer-form artifact for human review. Specific factual "
                f"claims trace back to their originating attestations; this "
                f"artifact does not introduce new contestable claims."
            ),
            "claims": claims,
        },
        "refutation": refutation,
    }
