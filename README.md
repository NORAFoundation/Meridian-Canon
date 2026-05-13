# Meridian-Canon

**A Postgres + pgvector substrate for Canon-conformant evidence attestations.**

Meridian is the open-source reference implementation of the [Canon attestation protocol](https://norafoundation.io) — a cryptographic format for personal digital evidence that any recipient can falsify, independently, without trusting the system that produced it.

This repository provides:

- A **Postgres 16 + pgvector + PostGIS** schema for ingesting, normalizing, and hashing digital evidence (email, audio, PDFs, court records, communications, financial records, telemetry).
- A **Python package (`meridian`)** implementing the seven-layer pipeline: Witness → Findings → Refute → Query → Export, plus the Canon foundation (canonicalization, hashing, Ed25519 signing, and seven-step verification).
- A **Docker dev environment** for local development.

> 📖 **Read the textbook:** *Designing Falsifiable Evidence Systems: A Canon for Digital Attestations* — published at [norafoundation.github.io/Designing-Falsifiable-Evidence-Systems](https://norafoundation.github.io/Designing-Falsifiable-Evidence-Systems/).

---

## What's here

```
schema/                Postgres DDL, applied in filename order
  00_setup.sql         extensions (pgvector, PostGIS, pg_trgm, btree_gin)
  10_core.sql          matters, parties, actors, audit_log (hash-chained)
  20_provenance.sql    sources, acquisitions, productions, records_requests
  30_documents.sql     documents, chunks, embeddings, entities
  40–87_*.sql          communications, recordings, court, financial, telemetry, legal
  90_workers_correlations.sql, 95_views_indexes.sql
  97_supabase.sql, 99_rls.sql
  A0_attestations.sql  Canon attestations table
  B0_chunks_fts.sql    FTS index for hybrid retrieval
  C0_entities_resolution.sql, D0_citations.sql, D1_enrichments.sql

meridian/              Python package (pip install -e .)
  canon/               Canon foundation — schemas, canonicalize, hashing, signing, emit, walk
  witness/             Phase B: ObservationAttestation + local-first chunking
  findings/            Phase C: per-type LM extractors + ENM masking
  refute/              Phase D: Tri-Model Consensus harness (five challenge types)
  query/               Phase E+F: hybrid retrieval (dense + FTS + RRF) + SearchAttestation
  export/              Phase G: BriefAttestation + PDF rendering

dev/                   Docker Compose for Postgres 16 + PostGIS 3.4 + pgvector
```

## Quick start

```bash
# 1. Bring up Postgres (port 5433; avoids clashing with a local instance)
cd dev && docker-compose up -d

# 2. Apply schema migrations
./apply.sh

# 3. Install the Python package
pip install -e ".[test]"

# 4. Run the test suite
pytest meridian/canon/tests/
```

## CLI

`meridian-canon` is the single entry point:

| Subcommand | Purpose |
|---|---|
| `keygen --custodian=<name>` | Generate Ed25519 keypair; store private key in OS keychain |
| `rotate-key --custodian=<name>` | Revoke old key, generate new |
| `walk <file.json>` | Run the seven-step falsification protocol; print verdict |
| `verify <file.json>` | Like walk; exits 0 only on `verdict=valid` |
| `enrich <doc> --type=<t>` | Phase C: extract findings via vLLM; emit sealed EnrichmentAttestation |
| `refute <unsealed.json>` | Phase D: Tri-Model Consensus harness; emit sealed Attestation |
| `search "<query>" --top-k=N` | Phase E+F: hybrid retrieval; emit sealed SearchAttestation |
| `brief --subject="..." <sources...>` | Phase G: synthesize BriefAttestation |
| `audit <attestation.json>` | Phase H: admissibility audit; emit sealed AuditAttestation |

## Conventions

- **Python 3.10+**, type hints throughout, pydantic v2 for schemas.
- **Idempotent ingest:** every record is keyed on `source_hash` (SHA-256 of original bytes).
- **Audit log is hash-chained:** every Canon emission writes one audit row that links to the previous.
- **Migrations are sequential and reversible:** every `X0_*.sql` has a matching `X0_*.down.sql`.
- **Embedding model:** `bge-large-en-v1.5` (1024-d), cosine `<=>` operator.
- **Conventional Commits:** `feat:`, `fix:`, `test:`, `docs:`.

## Architecture

The system is built around a single invariant: every artifact emitted to a recipient is a sealed Canon Attestation, independently verifiable. The seven-layer pipeline (Layers L0 through L6) carries a document from receipt to seal, with the audit log writing a hash-chained row at every boundary.

For the architectural rationale, see the textbook chapters 13–20.

## License

MIT for code. Canon spec is dedicated to the public domain (CC0).

## Contributing

This is an open-source reference implementation. Issues and pull requests welcome at <https://github.com/NORAFoundation/Meridian-Canon>.

When reporting bugs or contributing changes, do **not** include personal data, real case identifiers, or identifying file paths in examples — use synthetic identifiers (`EXAMPLE-MATTER-001`, `user@example.com`, etc.).

## Citation

> NORA Foundation. *Meridian-Canon: A Postgres + pgvector Substrate for Canon-Conformant Evidence Attestations.* 2026. <https://github.com/NORAFoundation/Meridian-Canon>
