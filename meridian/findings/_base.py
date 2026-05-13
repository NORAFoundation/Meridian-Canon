"""Shared extractor primitives.

Each per-type extractor:
    1. Defines a Pydantic schema describing the LM-output JSON shape.
    2. Renders a prompt template against the masked input + a brief instruction.
    3. Calls the LM with guided_json constrained to its schema.
    4. Builds a Canon-conformant FindingsBlock dict from the validated output.

This module contains the shared scaffolding so each extractor is small.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, Type
from uuid import uuid4

from pydantic import BaseModel

from ._spans import format_span_gap
from .enm import EntityMap, EntityMasker
from .lm_vllm import VLLMAdapter


def _gen_id(prefix: str = "") -> str:
    try:
        import ulid
        return f"{prefix}{ulid.new()!s}".upper()
    except ImportError:
        return f"{prefix}{uuid4().hex}".upper()


class LMJsonAdapter(Protocol):
    """Anything that can produce schema-validated JSON. VLLMAdapter satisfies this."""

    name: str

    def complete_json(
        self,
        prompt: str,
        schema_model: Type[BaseModel],
        *,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> BaseModel: ...


class SpansAwareLMJsonAdapter(LMJsonAdapter, Protocol):
    """Extension of LMJsonAdapter that additionally returns char-offset
    spans tying each extracted field back to the source text.

    The LangExtract adapter (``meridian.findings.lm_langextract``) is the
    canonical implementation; tests can substitute any object exposing
    ``complete_json_with_spans``.
    """

    def complete_json_with_spans(
        self,
        prompt: str,
        schema_model: Type[BaseModel],
        source_text: str,
        *,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> tuple[BaseModel, dict[str, list[tuple[int, int]]]]:
        """Returns (validated_object, {field_name: [(start, end), ...]}).

        Field names match the Pydantic model's attribute names. Any field
        the adapter cannot localize is omitted from the spans dict (the
        caller treats absence as 'no span available').
        """
        ...


def is_spans_aware(adapter: LMJsonAdapter) -> bool:
    """Runtime check: does the adapter expose the spans-aware method?"""
    return callable(getattr(adapter, "complete_json_with_spans", None))


@dataclass
class ExtractionContext:
    """What an extractor needs at runtime."""

    model: LMJsonAdapter
    masker: EntityMasker = field(default_factory=EntityMasker)
    masking_enabled: bool = True


def build_findings_block(
    *,
    extractor_name: str,
    model_name: str,
    claims: list[dict[str, Any]],
    masking_used: bool,
    masked_entity_count: int,
) -> dict[str, Any]:
    """Construct a Canon-conformant FindingsBlock dict."""
    method_parts = [
        f"Enrichment via {model_name} using {extractor_name}.",
    ]
    if masking_used and masked_entity_count > 0:
        method_parts.append(
            f"Epistemic Neutrality Masking applied to {masked_entity_count} entities; "
            f"original entities re-associated post-inference."
        )
    return {
        "method": " ".join(method_parts),
        "claims": claims,
    }


def claim(
    statement: str,
    *,
    inference_type: str,
    supports: list[str],
    gaps: list[str] | None = None,
    source_spans: list[tuple[int, int]] | None = None,
) -> dict[str, Any]:
    """Build a Canon-conformant claim dict.

    If ``source_spans`` is provided, a ``source_span:char[X-Y,...]`` gap
    entry is appended after the supplied gaps so spans always appear in
    the same canonical position.
    """
    final_gaps = list(gaps) if gaps else (
        [] if inference_type == "observation" else ["extracted by language model; correctness not independently verified"]
    )
    if source_spans:
        formatted = format_span_gap(source_spans)
        if formatted:
            final_gaps.append(formatted)
    return {
        "claim_id": "claim-" + _gen_id(),
        "statement": statement,
        "supports": supports,
        "inference_type": inference_type,
        "gaps": final_gaps,
    }
