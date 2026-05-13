"""Witness layer (Phase B): wraps existing ingest workers with ObservationAttestation emission.

Every successful acquisition produces a sealed ObservationAttestation referencing
the acquisition row. The attestation_id is written back to acquisitions.obs_attestation_id
so verifiers and queries can walk in either direction.

Local-First Chunking lives in local_chunker.py.
"""

from .wrapper import attest_acquisition, backfill_observations
from .local_chunker import chunk_local, ChunkRecord

__all__ = ["attest_acquisition", "backfill_observations", "chunk_local", "ChunkRecord"]
