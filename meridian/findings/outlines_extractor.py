"""Outlines-constrained LM extraction — guarantees schema-valid LMOutput.

Outlines uses logits masking to make it mathematically impossible to emit
JSON that violates the LMOutput schema. Use this for vLLM-backed local models.

Install: pip install outlines>=0.1 vllm>=0.4
"""
from __future__ import annotations

import logging
from typing import Optional

from pydantic import ValidationError

try:
    import outlines
    import outlines.models as om
    _OUTLINES_AVAILABLE = True
except ImportError:
    _OUTLINES_AVAILABLE = False

from .lm_extractor import LMOutput

logger = logging.getLogger(__name__)

# AUDIT-FIX (P4a): Sentinel string written into summary_one_sentence so that
# downstream consumers can detect a failed extraction without inspecting flags.
# A real extraction never emits this prefix.
EXTRACTION_FAILED_SENTINEL = "EXTRACTION_FAILED"

# AUDIT-FIX (P4d): outlines truncates input at 8000 chars (3.75x stricter than
# the 30000-char limit used elsewhere). Surface that as a hard cap + flag.
_OUTLINES_INPUT_CAP = 8000

# AUDIT-FIX (P4a): only swallow the failure modes a generator can legitimately
# raise (network/runtime issues, malformed JSON). Everything else (e.g.
# KeyboardInterrupt, MemoryError, programming errors) must propagate.
_EXTRACTION_FAILURE_EXCEPTIONS = (ValidationError, ValueError, RuntimeError, OSError)


def is_failed_extraction(result: LMOutput) -> bool:
    """True if ``result`` is the failure sentinel from a swallowed error.

    Downstream code MUST treat a failed extraction as 'no extraction' and never
    persist its (empty) semantic fields as real findings.
    """
    return (
        result.overall_confidence == 0.0
        and "extraction_failed" in result.flags_for_human_review
        and result.summary_one_sentence.startswith(EXTRACTION_FAILED_SENTINEL)
    )


def build_outlines_generator(model_name: str, *, device: str = "auto"):
    """Build an Outlines-constrained JSON generator for LMOutput.

    Args:
        model_name: HuggingFace model ID or path (e.g. "mistralai/Mistral-7B-Instruct-v0.3")
        device: "auto", "cuda", "cpu"

    Returns:
        A callable: generator(prompt: str) -> LMOutput
    """
    if not _OUTLINES_AVAILABLE:
        raise RuntimeError(
            "outlines not installed. Run: pip install outlines>=0.1"
        )
    model = om.transformers(model_name, device=device)
    return outlines.generate.json(model, LMOutput)


def build_vllm_outlines_generator(model_name: str):
    """Build an Outlines generator backed by a running vLLM server.

    Args:
        model_name: model name as served by vLLM (must match what's loaded)

    Returns:
        A callable: generator(prompt: str) -> LMOutput
    """
    if not _OUTLINES_AVAILABLE:
        raise RuntimeError(
            "outlines not installed. Run: pip install outlines>=0.1 vllm>=0.4"
        )
    try:
        model = om.vllm(model_name)
    except Exception as e:
        raise RuntimeError(f"Could not connect to vLLM for model {model_name!r}: {e}") from e
    return outlines.generate.json(model, LMOutput)


class OutlinesExtractor:
    """Drop-in replacement for the cloud-API extractor in lm_extractor.py.

    Wraps an Outlines generator; guarantees LMOutput conformance on every call.
    Falls back gracefully if the generator fails.
    """

    def __init__(self, generator, *, extraction_prompt_template: Optional[str] = None):
        self._generator = generator
        self._prompt_template = extraction_prompt_template or _DEFAULT_PROMPT

    def extract(self, text: str, *, source_uri: str = "", doc_type_hint: str = "") -> LMOutput:
        """Extract structured findings from text.

        On success returns the generator's LMOutput. On a recognized failure
        returns a clearly-marked failure sentinel (``is_failed_extraction()``
        True): overall_confidence=0.0 and flags_for_human_review including
        ``"extraction_failed"`` — never empty semantic fields masquerading as a
        real result. Unrecognized exceptions propagate.
        """
        # AUDIT-FIX (P4d): track truncation at the 8000-char outlines cap so a
        # silently-dropped tail (e.g. a late exculpatory paragraph) becomes a
        # human-review flag and a confidence ceiling rather than vanishing.
        truncated = len(text) > _OUTLINES_INPUT_CAP
        prompt = self._prompt_template.format(
            text=text[:_OUTLINES_INPUT_CAP],  # truncate for context window safety
            source_uri=source_uri,
            doc_type_hint=doc_type_hint or "legal document",
        )
        try:
            result = self._generator(prompt)
            if isinstance(result, LMOutput):
                pass
            # Some outlines versions return dict; coerce
            elif isinstance(result, dict):
                result = LMOutput.model_validate(result)
            else:
                result = LMOutput.model_validate_json(str(result))
        except _EXTRACTION_FAILURE_EXCEPTIONS:
            # AUDIT-FIX (P4a): do NOT silently store an empty stub as a real
            # result. Log at ERROR with full traceback, then return a failure
            # sentinel downstream treats as "no extraction".
            logger.error(
                "Outlines extraction failed for source_uri=%r (doc_type_hint=%r); "
                "returning failure sentinel, not empty findings",
                source_uri, doc_type_hint, exc_info=True,
            )
            return LMOutput(
                document_kind="other",
                summary_one_sentence=f"{EXTRACTION_FAILED_SENTINEL}: see ERROR log for traceback",
                summary_paragraph="",
                overall_confidence=0.0,
                flags_for_human_review=["extraction_failed"],
            )

        if truncated:
            # AUDIT-FIX (P4d): flag truncation and cap confidence so an analyst
            # knows the LM never saw the full document.
            if "input_truncated_at_8000_chars" not in result.flags_for_human_review:
                result.flags_for_human_review = list(result.flags_for_human_review) + [
                    "input_truncated_at_8000_chars"
                ]
            result.overall_confidence = min(result.overall_confidence, 0.5)
        return result


_DEFAULT_PROMPT = """You are a legal document analyst. Extract structured information from the following {doc_type_hint}.

Source: {source_uri}

Document text:
{text}

Return a JSON object with structured findings."""
