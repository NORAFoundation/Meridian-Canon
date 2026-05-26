"""Query layer (Phases E + F): hybrid retrieval + SearchAttestation emission.

Phase E: hybrid retrieval combining
    - Lexical (Postgres tsvector + GIN, BM25-equivalent ts_rank)
    - Dense vector (pgvector cosine over embeddings)
    - Optional cross-encoder re-ranking (FastEmbed BAAI/bge-reranker-base)
fused via Reciprocal Rank Fusion (k=60 per Cormack et al. 2009).

Phase F: every retrieval emits a sealed SearchAttestation. Witness records
the query string and top-K observation_ids; Findings records the ranking
rationale; Refutation captures the consistency and coverage challenges.

Apple Silicon path: FastEmbed runs ONNX on CPU/MPS without CUDA. Both the
embedder and the re-ranker work on M-series Macs.
"""

from .rrf import reciprocal_rank_fusion
from .search import HybridSearch, SearchResult
from .embeddings import embed_query
from .attestation import build_search_attestation

__all__ = [
    "HybridSearch",
    "SearchResult",
    "embed_query",
    "reciprocal_rank_fusion",
    "build_search_attestation",
]
