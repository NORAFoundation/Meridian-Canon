"""Enrichment runner: dispatches documents to per-type extractors.

The runner is the orchestration layer between the documents table and
the extractors. It:

    1. Loads un-enriched documents from Postgres (one batch at a time).
    2. Dispatches each document to the appropriate per-type extractor.
    3. Builds an unsealed EnrichmentAttestation (Witness from the prior
       ObservationAttestation; Findings from the extractor).
    4. (Optionally) runs the L5 refutation harness.
    5. Seals via meridian.canon.emit.

This module exposes the dispatch table; the database-touching loop lives
in scripts/enrich_run.py so unit tests can drive the runner without DB.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from ._base import ExtractionContext, LMJsonAdapter
from .enm import EntityMasker
from .email import EmailExtractor
from .file import FileExtractor
from .sms import SMSExtractor
from .voicemail import VoicemailExtractor
from .voice_memo import VoiceMemoExtractor
from .call import CallExtractor


# Registry mapping document type -> extractor class.
EXTRACTORS_BY_TYPE = {
    "email": EmailExtractor,
    "file": FileExtractor,
    "pdf": FileExtractor,           # PDFs route to file extractor
    "sms": SMSExtractor,
    "imessage": SMSExtractor,        # iMessage routes to sms extractor
    "voicemail": VoicemailExtractor,
    "voice_memo": VoiceMemoExtractor,
    "call": CallExtractor,
}


@dataclass
class Runner:
    """Per-process enrichment dispatcher.

    Holds the LM adapter and entity masker so extractors share them
    (one model handle, one masker; no per-document allocation).
    """

    model: LMJsonAdapter
    masker: EntityMasker = None  # type: ignore[assignment]
    masking_enabled: bool = True

    def __post_init__(self) -> None:
        if self.masker is None:
            self.masker = EntityMasker()
        self._ctx = ExtractionContext(
            model=self.model, masker=self.masker, masking_enabled=self.masking_enabled
        )
        self._cache: dict[type, object] = {}

    def get_extractor(self, document_type: str):
        cls = EXTRACTORS_BY_TYPE.get(document_type)
        if cls is None:
            raise KeyError(
                f"No extractor registered for document_type={document_type!r}; "
                f"known types: {sorted(EXTRACTORS_BY_TYPE)}"
            )
        if cls not in self._cache:
            self._cache[cls] = cls(self._ctx)
        return self._cache[cls]

    def enrich(self, document_text: str, *, document_type: str, observation_id: str) -> dict:
        """Run the per-type extractor; return a Findings block dict."""
        extractor = self.get_extractor(document_type)
        return extractor.extract(document_text, observation_id=observation_id)

    def known_types(self) -> Sequence[str]:
        return list(EXTRACTORS_BY_TYPE.keys())
