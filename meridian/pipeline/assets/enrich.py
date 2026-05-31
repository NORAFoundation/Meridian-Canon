"""Dagster asset: ObservationAttestation → EnrichmentAttestation via LM extraction."""
from __future__ import annotations
import base64
from urllib.parse import urlparse

try:
    from dagster import asset
    _DAGSTER_AVAILABLE = True
except ImportError:
    _DAGSTER_AVAILABLE = False

    def asset(*args, **kwargs):  # type: ignore[misc]
        def decorator(fn):
            return fn
        return decorator if (args and callable(args[0])) else decorator


# AUDIT-FIX (P3): map a witness source URI to a runner document_type.
# meridian.findings.runner.EXTRACTORS_BY_TYPE is the authoritative registry;
# anything not matched here falls back to "file" (FileExtractor), which is the
# correct general-document path.
_EXT_TO_TYPE = {
    "eml": "email", "emlx": "email", "msg": "email",
    "txt": "file", "pdf": "pdf", "doc": "file", "docx": "file",
    "vcf": "voicemail",
}
_SCHEME_TO_TYPE = {
    "mailto": "email", "sms": "sms", "imessage": "imessage",
    "tel": "call", "voicemail": "voicemail", "voice_memo": "voice_memo",
}


def _document_type_for(source_uri: str) -> str:
    """Best-effort dispatch key for the enrichment runner."""
    parsed = urlparse(source_uri or "")
    scheme = (parsed.scheme or "").lower()
    if scheme in _SCHEME_TO_TYPE:
        return _SCHEME_TO_TYPE[scheme]
    path = (parsed.path or source_uri or "").split("#", 1)[0]
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return _EXT_TO_TYPE.get(ext, "file")


def _decode_witness_text(entry: dict) -> str:
    """Decode a witness entry's content_inline (base64) to text.

    Returns "" when the bytes live behind a content_ref instead of inline.
    """
    inline = entry.get("content_inline")
    if not inline:
        return ""
    try:
        return base64.b64decode(inline).decode("utf-8", errors="replace")
    except Exception:
        return ""


@asset(
    name="enrichment_attestation",
    group_name="canon_pipeline",
    description="Run LM extraction on observations to produce typed EnrichmentAttestation.",
)
def enrichment_attestation(context, observation_attestation: dict, llm=None) -> dict:
    """L3: LM-based enrichment via meridian.findings.runner.Runner.

    AUDIT-FIX (P3 enrich is a stub): this asset previously passed the
    observation through unchanged and merely relabelled the method
    ``lm_extraction_pending`` — no extraction ran in the orchestrated pipeline,
    so EnrichmentAttestations carried zero real findings. We now decode each
    witness ``content_inline``, dispatch by source kind, run the registered
    per-type extractor, and attach the produced Findings claims.

    Requires an LM adapter (the ``llm`` resource, exposing ``get_adapters()``).
    If the extractor stack or an adapter is unavailable we raise a clear
    RuntimeError rather than silently degrading to a pass-through — an
    EnrichmentAttestation with no findings is a forensic-integrity defect, not
    a benign no-op.
    """
    from meridian.findings.runner import Runner

    adapters = (
        llm.get_adapters() if (llm is not None and hasattr(llm, "get_adapters")) else []
    )
    if not adapters:
        raise RuntimeError(
            "enrichment_attestation requires an LM adapter: configure the 'llm' "
            "resource (LLMResource.get_adapters() must return at least one "
            "adapter). Refusing to emit an EnrichmentAttestation with no findings."
        )

    runner = Runner(model=adapters[0])

    enriched = dict(observation_attestation)
    enriched["kind"] = "enrichment"

    subject = enriched.get("subject", "")
    claims: list[dict] = []
    method = None
    for entry in enriched.get("witness", []):
        text = _decode_witness_text(entry)
        if not text.strip():
            continue
        doc_type = _document_type_for(entry.get("source") or subject)
        observation_id = entry.get("observation_id", "")
        block = runner.enrich(text, document_type=doc_type, observation_id=observation_id)
        if method is None:
            method = block.get("method")
        claims.extend(block.get("claims", []))

    enriched["findings"] = {
        "method": method or "lm_extraction via meridian.findings.runner.Runner",
        "claims": claims,
    }
    return enriched
