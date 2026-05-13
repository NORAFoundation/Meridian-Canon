"""meridian-canon command-line entry point.

Subcommands:
    keygen --custodian=<name>       Generate keypair, write public PEM, store private in Keychain
    rotate-key --custodian=<name>   Generate new keypair; old PEM remains valid for prior Attestations
    walk <attestation.json>         Run the seven-step falsification protocol
    verify <attestation.json>       Like walk, but exits 0 only on verdict=valid
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import admissibility_auditor, emit as emit_module, keys, walk as walk_module


def _cmd_keygen(args: argparse.Namespace) -> int:
    private, public, fingerprint = keys.keygen(args.custodian)
    pem_path = keys.DEFAULT_KEY_DIR / f"{fingerprint.replace(':', '_')}.pem"
    print(f"Custodian:    {args.custodian}")
    print(f"Fingerprint:  {fingerprint}")
    print(f"Public PEM:   {pem_path}")
    print(f"Private key:  Keychain (service={keys.KEYRING_SERVICE}, account={args.custodian})")
    return 0


def _cmd_rotate(args: argparse.Namespace) -> int:
    keys.revoke(args.custodian)
    return _cmd_keygen(args)


def _cmd_walk(args: argparse.Namespace) -> int:
    attestation = json.loads(Path(args.path).read_text())
    result = walk_module.walk(attestation)
    print(json.dumps(result, indent=2))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    attestation = json.loads(Path(args.path).read_text())
    result = walk_module.walk(attestation)
    print(json.dumps(result, indent=2))
    return 0 if result["verdict"] == "valid" else 1


def _cmd_enrich(args: argparse.Namespace) -> int:
    """Enrich a single document file via vLLM and emit a sealed EnrichmentAttestation."""
    from meridian.findings import Runner, VLLMAdapter

    text = Path(args.input).read_text()
    adapter = VLLMAdapter(model=args.model, base_url=args.vllm_url)
    runner = Runner(model=adapter, masking_enabled=not args.disable_masking)
    findings = runner.enrich(
        text,
        document_type=args.type,
        observation_id=args.observation_id,
    )

    # Build a minimal EnrichmentAttestation referencing the input.
    import hashlib, base64
    content = text.encode("utf-8")
    content_hash = "sha256:" + hashlib.sha256(content).hexdigest()
    att = {
        "kind": "enrichment",
        "issuer": args.issuer or args.custodian,
        "subject": f"Enrichment of {args.input}",
        "witness": [{
            "observation_id": args.observation_id,
            "source": f"file://{Path(args.input).resolve()}",
            "received_at": _now_rfc3339(),
            "custody_chain": [{"custodian": args.custodian, "received_at": _now_rfc3339(), "signature": None}],
            "content_hash": content_hash,
            "content_ref": None,
            "content_inline": base64.b64encode(content).decode("ascii"),
        }],
        "findings": findings,
        "refutation": _stub_refutation([c["claim_id"] for c in findings["claims"]]),
    }
    sealed = emit_module.emit(att, custodian=args.custodian, public_key_url=args.pubkey_url, fingerprint=args.fingerprint)
    out = json.dumps(sealed, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(out)
        print(f"Wrote {args.out}")
    else:
        print(out)
    return 0


def _now_rfc3339() -> str:
    from datetime import datetime, timezone
    return datetime.now(tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _stub_refutation(claim_ids: list[str]) -> dict:
    """Minimum-viable Refutation block when the harness isn't being run.

    Use `meridian-canon refute` to apply the full Tri-Model Consensus harness.
    """
    return {
        "challenges": [{
            "challenge_id": "chal-ENR-replay",
            "type": "replay",
            "targets": claim_ids,
            "input": "metadata-only replay; full harness deferred",
            "outcome": "survived",
            "revisions": None,
        }],
        "coverage": {
            "applied": ["replay"],
            "declined": [
                {"type": "adversarial_prompt", "reason": "not_invoked_in_enrich_pass; use refute subcommand"},
                {"type": "consistency_check", "reason": "not_invoked_in_enrich_pass; use refute subcommand"},
                {"type": "coverage_audit", "reason": "applies_at_batch_level_not_per_observation"},
                {"type": "counter_evidence", "reason": "not_invoked_in_enrich_pass; use refute subcommand"},
            ],
        },
    }


def _cmd_refute(args: argparse.Namespace) -> int:
    """Apply the refutation harness to an unsealed Attestation; emit sealed."""
    from meridian.refute import OllamaAdapter, run_harness

    target = json.loads(Path(args.path).read_text())
    if "seal" in target:
        target = {k: v for k, v in target.items() if k != "seal"}

    models = []
    if args.ollama_models:
        for spec in args.ollama_models:
            models.append(OllamaAdapter(model=spec))

    refutation = run_harness(target, models=models if len(models) >= 2 else None)
    target["refutation"] = refutation

    sealed = emit_module.emit(
        target,
        custodian=args.custodian,
        public_key_url=args.pubkey_url,
        fingerprint=args.fingerprint,
    )
    out = json.dumps(sealed, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(out)
        print(f"Wrote {args.out}")
    else:
        print(out)
    return 0


def _cmd_search(args: argparse.Namespace) -> int:
    """Run hybrid retrieval and emit a sealed SearchAttestation."""
    import os
    import psycopg
    from psycopg.rows import dict_row
    from meridian.query import HybridSearch, build_search_attestation

    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("DATABASE_URL is not set", file=sys.stderr)
        return 2
    actor = os.environ.get("SYSTEM_ACTOR_ID", "00000000-0000-0000-0000-000000000001")

    with psycopg.connect(db_url, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.current_actor_id', %s, true)", (actor,))
        searcher = HybridSearch(conn=conn, rerank=args.rerank)
        results = searcher.search(args.query, top_k=args.top_k, matter_id=args.matter_id)

    att = build_search_attestation(
        query=args.query,
        results=results,
        issuer=args.issuer or args.custodian,
        matter_id=args.matter_id,
        custodian=args.custodian,
        reranker_used=args.rerank,
    )
    sealed = emit_module.emit(att, custodian=args.custodian, public_key_url=args.pubkey_url, fingerprint=args.fingerprint)
    out = json.dumps(sealed, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(out)
        print(f"Wrote {args.out}")
    else:
        print(out)
    return 0


def _cmd_brief(args: argparse.Namespace) -> int:
    """Synthesize a BriefAttestation from one or more source Attestation files."""
    from meridian.export import BriefSynthesizer, build_brief_attestation, render_brief_pdf
    from meridian.refute import OllamaAdapter

    sources = [json.loads(Path(p).read_text()) for p in args.sources]
    adapter = OllamaAdapter(model=args.synthesis_model)
    synth = BriefSynthesizer(adapter=adapter)  # type: ignore[arg-type]
    body_text = synth.synthesize(subject=args.subject, sources=sources)

    att = build_brief_attestation(
        subject=args.subject,
        body_text=body_text,
        sources=sources,
        issuer=args.issuer or args.custodian,
        matter_id=args.matter_id,
        custodian=args.custodian,
        synthesis_model=args.synthesis_model,
    )
    sealed = emit_module.emit(att, custodian=args.custodian, public_key_url=args.pubkey_url, fingerprint=args.fingerprint)
    Path(args.out_json).write_text(json.dumps(sealed, indent=2, default=str))
    print(f"Wrote {args.out_json}")
    if args.out_pdf:
        render_brief_pdf(sealed, out_path=Path(args.out_pdf))
        print(f"Wrote {args.out_pdf}")
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    target = json.loads(Path(args.path).read_text())
    audit_att = admissibility_auditor.audit(
        target,
        custodian=args.custodian,
        public_key_url=args.pubkey_url,
        fingerprint=args.fingerprint,
        auditor_issuer=args.auditor_issuer,
    )
    out = json.dumps(audit_att, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(out)
        print(f"Wrote {args.out}")
    else:
        print(out)
    return 0


def _cmd_lit_challenge(args: argparse.Namespace) -> int:
    """Literature-RAG challenge for a contested-assay question; emit sealed."""
    from meridian.forensics import (
        LitQuery,
        build_lit_challenge_attestation,
        run_lit_challenge,
    )

    query = LitQuery(
        question=args.question,
        analyte=args.analyte,
        max_papers=args.max_papers,
        pubmed_query=args.pubmed_query,
        matter_id=args.matter_id,
    )
    report = run_lit_challenge(query)
    issuer = args.issuer or f"{args.custodian}+lit-challenge-auditor"
    att = build_lit_challenge_attestation(report, issuer=issuer, matter_id=args.matter_id)
    sealed = emit_module.emit(
        att, custodian=args.custodian, public_key_url=args.pubkey_url, fingerprint=args.fingerprint,
    )
    out = json.dumps(sealed, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(out)
        print(f"Wrote {args.out}")
    else:
        print(out)
    return 0


def _cmd_kinetics(args: argparse.Namespace) -> int:
    """Toxicology kinetics audit of one KineticsQuery JSON; emit sealed."""
    from meridian.forensics import (
        KineticsQuery,
        audit_kinetics,
        build_kinetics_attestation,
        load_constants,
    )

    qdoc = json.loads(Path(args.query).read_text())
    query = KineticsQuery.model_validate(qdoc)
    constants = load_constants()
    assessment = audit_kinetics(query, constants)
    issuer = args.issuer or f"{args.custodian}+tox-kinetics-auditor"

    att = build_kinetics_attestation(
        query, assessment,
        issuer=issuer, matter_id=args.matter_id, constants=constants,
    )
    sealed = emit_module.emit(
        att,
        custodian=args.custodian,
        public_key_url=args.pubkey_url,
        fingerprint=args.fingerprint,
    )
    out = json.dumps(sealed, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(out)
        print(f"Wrote {args.out}")
    else:
        print(out)
    return 0


def _cmd_coc_audit(args: argparse.Namespace) -> int:
    """SAMHSA chain-of-custody audit of one Specimen JSON; emit sealed."""
    from meridian.forensics import Specimen, build_coc_audit_attestation

    spec_doc = json.loads(Path(args.specimen).read_text())
    specimen = Specimen.model_validate(spec_doc)
    issuer = args.issuer or f"{args.custodian}+samhsa-coc-auditor"

    att = build_coc_audit_attestation(
        specimen,
        issuer=issuer,
        matter_id=args.matter_id,
    )
    sealed = emit_module.emit(
        att,
        custodian=args.custodian,
        public_key_url=args.pubkey_url,
        fingerprint=args.fingerprint,
    )
    out = json.dumps(sealed, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(out)
        print(f"Wrote {args.out}")
    else:
        print(out)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="meridian-canon")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen", help="Generate keypair")
    p.add_argument("--custodian", required=True)
    p.set_defaults(func=_cmd_keygen)

    p = sub.add_parser("rotate-key", help="Rotate keypair")
    p.add_argument("--custodian", required=True)
    p.set_defaults(func=_cmd_rotate)

    p = sub.add_parser("walk", help="Run seven-step falsification protocol")
    p.add_argument("path", type=Path)
    p.set_defaults(func=_cmd_walk)

    p = sub.add_parser("verify", help="Verify Attestation; exit 0 only on valid")
    p.add_argument("path", type=Path)
    p.set_defaults(func=_cmd_verify)

    p = sub.add_parser("enrich", help="Run a per-type extractor against a document; emit sealed EnrichmentAttestation")
    p.add_argument("input", type=Path, help="Path to the document text")
    p.add_argument("--type", required=True, help="Document type: email, file, sms, voicemail, voice_memo, call, pdf, imessage")
    p.add_argument("--observation-id", required=True, help="The originating ObservationAttestation's observation_id (obs-...)")
    p.add_argument("--model", default="Qwen/Qwen2.5-7B-Instruct", help="vLLM model name (server-side)")
    p.add_argument("--vllm-url", default="http://localhost:8000/v1", help="vLLM OpenAI-compatible base URL")
    p.add_argument("--custodian", required=True)
    p.add_argument("--pubkey-url", required=True)
    p.add_argument("--fingerprint")
    p.add_argument("--issuer")
    p.add_argument("--disable-masking", action="store_true", help="Skip Epistemic Neutrality Masking")
    p.add_argument("--out")
    p.set_defaults(func=_cmd_enrich)

    p = sub.add_parser("refute", help="Apply refutation harness to an unsealed Attestation; emit sealed")
    p.add_argument("path", type=Path, help="Unsealed Attestation JSON (Witness/Findings; no seal)")
    p.add_argument("--custodian", required=True)
    p.add_argument("--pubkey-url", required=True)
    p.add_argument("--fingerprint")
    p.add_argument(
        "--ollama-models",
        nargs="+",
        help="Ollama model identifiers for Tri-Model Consensus (need ≥ 2). Example: "
             "--ollama-models llama3.1:8b-instruct mistral-nemo:latest gemma2:9b",
    )
    p.add_argument("--out", help="Write sealed Attestation to file (default: stdout)")
    p.set_defaults(func=_cmd_refute)

    p = sub.add_parser("search", help="Hybrid retrieval; emit sealed SearchAttestation")
    p.add_argument("query", help="Query string")
    p.add_argument("--top-k", type=int, default=20)
    p.add_argument("--rerank", action="store_true", help="Apply cross-encoder re-rank")
    p.add_argument("--matter-id", help="Restrict to one matter")
    p.add_argument("--custodian", required=True)
    p.add_argument("--pubkey-url", required=True)
    p.add_argument("--fingerprint")
    p.add_argument("--issuer")
    p.add_argument("--out", help="Write to file (default: stdout)")
    p.set_defaults(func=_cmd_search)

    p = sub.add_parser("brief", help="Synthesize a BriefAttestation from source Attestations")
    p.add_argument("--subject", required=True)
    p.add_argument("sources", nargs="+", help="Paths to source Attestation JSON files")
    p.add_argument("--synthesis-model", default="llama3.1:8b-instruct", help="Ollama model identifier")
    p.add_argument("--matter-id")
    p.add_argument("--custodian", required=True)
    p.add_argument("--pubkey-url", required=True)
    p.add_argument("--fingerprint")
    p.add_argument("--issuer")
    p.add_argument("--out-json", required=True, help="Path for the sealed BriefAttestation JSON")
    p.add_argument("--out-pdf", help="Optional path for rendered PDF")
    p.set_defaults(func=_cmd_brief)

    p = sub.add_parser("audit", help="Produce admissibility-audit Attestation for a target")
    p.add_argument("path", type=Path, help="Target Attestation JSON")
    p.add_argument("--custodian", required=True, help="Auditor's Keychain account name")
    p.add_argument("--pubkey-url", required=True)
    p.add_argument("--fingerprint")
    p.add_argument("--auditor-issuer")
    p.add_argument("--out", help="Write audit to file (default: stdout)")
    p.set_defaults(func=_cmd_audit)

    p = sub.add_parser(
        "coc-audit",
        help="Run SAMHSA chain-of-custody audit on a Specimen JSON; emit sealed audit Attestation",
    )
    p.add_argument("specimen", type=Path, help="Path to a Specimen JSON file")
    p.add_argument("--custodian", required=True, help="Auditor's Keychain account name")
    p.add_argument("--pubkey-url", required=True)
    p.add_argument("--fingerprint")
    p.add_argument("--issuer", help="Issuer string; defaults to <custodian>+samhsa-coc-auditor")
    p.add_argument("--matter-id")
    p.add_argument("--out", help="Write sealed Attestation to file (default: stdout)")
    p.set_defaults(func=_cmd_coc_audit)

    p = sub.add_parser(
        "lit-challenge",
        help="Run a literature-RAG challenge for a contested-assay question; emit sealed audit Attestation",
    )
    p.add_argument("question", help="The contested-assay question to answer")
    p.add_argument("--analyte", help="Analyte / drug being challenged (free text)")
    p.add_argument("--max-papers", type=int, default=15)
    p.add_argument("--pubmed-query", help="Override the raw PubMed query string")
    p.add_argument("--custodian", required=True, help="Auditor's Keychain account name")
    p.add_argument("--pubkey-url", required=True)
    p.add_argument("--fingerprint")
    p.add_argument("--issuer", help="Issuer string; defaults to <custodian>+lit-challenge-auditor")
    p.add_argument("--matter-id")
    p.add_argument("--out", help="Write sealed Attestation to file (default: stdout)")
    p.set_defaults(func=_cmd_lit_challenge)

    p = sub.add_parser(
        "kinetics",
        help="Run toxicology one-compartment-PK plausibility audit on a KineticsQuery JSON; emit sealed audit Attestation",
    )
    p.add_argument("query", type=Path, help="Path to a KineticsQuery JSON file")
    p.add_argument("--custodian", required=True, help="Auditor's Keychain account name")
    p.add_argument("--pubkey-url", required=True)
    p.add_argument("--fingerprint")
    p.add_argument("--issuer", help="Issuer string; defaults to <custodian>+tox-kinetics-auditor")
    p.add_argument("--matter-id")
    p.add_argument("--out", help="Write sealed Attestation to file (default: stdout)")
    p.set_defaults(func=_cmd_kinetics)

    ns = parser.parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    sys.exit(main())
