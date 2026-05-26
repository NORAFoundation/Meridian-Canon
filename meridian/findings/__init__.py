"""Findings layer (Phase C): per-type LM-based claim extraction.

Each document type has a dedicated extractor that:
    1. Pre-processes the source text (Epistemic Neutrality Masking).
    2. Calls a language model with a JSON-schema-constrained prompt.
    3. Validates the output against a Pydantic schema.
    4. Re-associates entities and constructs a Canon-conformant FindingsBlock.

Public surface:
    VLLMAdapter      — vLLM server client (OpenAI-compatible API + guided_json)
    OpenAIAdapter    — also works against vLLM's OpenAI-compatible endpoint
    EntityMasker     — Epistemic Neutrality Masking
    EmailExtractor   — email enrichment
    FileExtractor    — generic file/PDF enrichment
    SMSExtractor     — sms conversation-window enrichment
    VoicemailExtractor — voicemail intent + urgency
    VoiceMemoExtractor — long-form audio (Whisper transcript) enrichment
    CallExtractor    — call metadata + correlation context
    Runner           — orchestrates batches across extractors
"""

from .lm_vllm import VLLMAdapter
from .enm import EntityMap, EntityMasker
from .email import EmailExtractor, EmailFindings
from .file import FileExtractor, FileFindings
from .sms import SMSExtractor, SMSFindings
from .voicemail import VoicemailExtractor, VoicemailFindings
from .voice_memo import VoiceMemoExtractor, VoiceMemoFindings
from .call import CallExtractor, CallFindings
from .runner import Runner, EXTRACTORS_BY_TYPE

__all__ = [
    "VLLMAdapter",
    "EntityMap",
    "EntityMasker",
    "EmailExtractor",
    "EmailFindings",
    "FileExtractor",
    "FileFindings",
    "SMSExtractor",
    "SMSFindings",
    "VoicemailExtractor",
    "VoicemailFindings",
    "VoiceMemoExtractor",
    "VoiceMemoFindings",
    "CallExtractor",
    "CallFindings",
    "Runner",
    "EXTRACTORS_BY_TYPE",
]
