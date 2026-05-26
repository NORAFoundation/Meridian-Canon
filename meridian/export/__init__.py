"""Export layer (Phase G): BriefAttestation synthesis + PDF rendering.

A BriefAttestation is a composite Canon Attestation that synthesizes
prior SearchAttestations and EnrichmentAttestations into a longer-form
artifact (memo, brief, chronology). Witness lists every contributing
prior Attestation by id; Findings contains the synthesis prose and its
supporting claims; Refutation cross-checks the synthesis against the
underlying primaries via consistency checks.

PDF rendering is via reportlab — pure Python, runs anywhere, no system
deps. The PDF embeds the BriefAttestation's chain_hash in the footer
so the printed artifact is bound to its sealed JSON form.
"""

from .brief import BriefSynthesizer, build_brief_attestation
from .pdf import render_brief_pdf

__all__ = ["BriefSynthesizer", "build_brief_attestation", "render_brief_pdf"]
