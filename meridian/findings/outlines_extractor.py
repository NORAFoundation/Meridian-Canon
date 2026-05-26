"""Outlines-constrained LM extraction — guarantees schema-valid LMOutput.

Outlines uses logits masking to make it mathematically impossible to emit
JSON that violates the LMOutput schema. Use this for vLLM-backed local models.

Install: pip install outlines>=0.1 vllm>=0.4
"""
from __future__ import annotations
from typing import Optional

try:
    import outlines
    import outlines.models as om
    _OUTLINES_AVAILABLE = True
except ImportError:
    _OUTLINES_AVAILABLE = False

from .lm_extractor import LMOutput


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
        """Extract structured findings from text. Always returns a valid LMOutput."""
        prompt = self._prompt_template.format(
            text=text[:8000],  # truncate for context window safety
            source_uri=source_uri,
            doc_type_hint=doc_type_hint or "legal document",
        )
        try:
            result = self._generator(prompt)
            if isinstance(result, LMOutput):
                return result
            # Some outlines versions return dict; coerce
            if isinstance(result, dict):
                return LMOutput.model_validate(result)
            return LMOutput.model_validate_json(str(result))
        except Exception as e:
            # Never raise — return a minimal valid LMOutput with error in summary
            return LMOutput(
                document_kind="other",
                summary_one_sentence=f"extraction failed: {e!s:.200}",
                summary_paragraph="",
            )


_DEFAULT_PROMPT = """You are a legal document analyst. Extract structured information from the following {doc_type_hint}.

Source: {source_uri}

Document text:
{text}

Return a JSON object with structured findings."""
