"""LangExtract adapter for source-span-aware extraction.

LangExtract (https://github.com/google/langextract) returns char-offset
spans for every extracted field.  This adapter satisfies the
``SpansAwareLMJsonAdapter`` Protocol declared in ``meridian.findings._base``
so per-document extractors can flow spans into Claim gaps.

This module is opt-in.  Install with:

    pip install -e ".[langextract]"

Provider configuration (matches the broader meridian/findings pattern):

    MERIDIAN_LE_PROVIDER=ollama|openai|anthropic|gemini   (default: ollama)
    MERIDIAN_LE_MODEL=<model id>                          (default per provider)
    MERIDIAN_LE_API_KEY                                    (provider-specific)

For tests/development without LangExtract installed, substitute any
object exposing ``complete_json_with_spans``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Type

from pydantic import BaseModel


@dataclass
class LangExtractAdapter:
    """Schema-validated extraction with character-offset spans.

    The ``complete_json`` path satisfies the existing ``LMJsonAdapter`` Protocol
    by discarding span info; ``complete_json_with_spans`` returns both the
    validated Pydantic instance and the spans dict.
    """

    name: str = "langextract"
    family: str = "langextract"
    provider: str = field(default_factory=lambda: os.environ.get("MERIDIAN_LE_PROVIDER", "ollama"))
    model: str = field(default_factory=lambda: os.environ.get("MERIDIAN_LE_MODEL", ""))
    api_key: str | None = field(default_factory=lambda: os.environ.get("MERIDIAN_LE_API_KEY"))

    def __post_init__(self) -> None:
        # Defer the actual import; tests can substitute a fake adapter
        # without LangExtract installed.
        if not self.model:
            defaults = {
                "ollama": "llama3.1:8b-instruct",
                "openai": "gpt-4o-mini",
                "anthropic": "claude-haiku-4-5-20251001",
                "gemini": "gemini-2.0-flash-exp",
            }
            self.model = defaults.get(self.provider, "llama3.1:8b-instruct")

    # --- LMJsonAdapter ----------------------------------------------------

    def complete_json(
        self,
        prompt: str,
        schema_model: Type[BaseModel],
        *,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> BaseModel:
        result, _spans = self.complete_json_with_spans(
            prompt,
            schema_model,
            source_text="",
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return result

    # --- SpansAwareLMJsonAdapter -----------------------------------------

    def complete_json_with_spans(
        self,
        prompt: str,
        schema_model: Type[BaseModel],
        source_text: str,
        *,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> tuple[BaseModel, dict[str, list[tuple[int, int]]]]:
        """Run LangExtract over ``source_text`` against ``schema_model``.

        The prompt is forwarded as the LangExtract task description.  We
        translate the Pydantic schema into a LangExtract Extraction object
        per field using the field descriptions as hints.
        """
        try:
            import langextract as _le  # type: ignore[import-untyped]
        except ImportError as e:
            raise RuntimeError(
                "langextract is not installed. Run `pip install -e \".[langextract]\"`"
            ) from e

        extractions = _build_extractions_from_schema(schema_model, _le)

        config = _build_config(self.provider, self.model, self.api_key, _le)
        result = _le.extract(
            text_or_documents=source_text or prompt,
            prompt_description=prompt,
            examples=[],
            extractions=extractions,
            **config,
        )

        validated, spans = _coerce_le_result_to_pydantic(result, schema_model)
        return validated, spans


# --- helpers --------------------------------------------------------------

def _build_extractions_from_schema(schema_model: Type[BaseModel], le_module: Any) -> list[Any]:
    """Build LangExtract Extraction definitions from a Pydantic schema.

    Each model field becomes one Extraction whose name == field name and
    whose description == the Pydantic Field description (or the field name
    if absent).
    """
    Extraction = le_module.Extraction  # noqa: N806
    out: list[Any] = []
    for fname, info in schema_model.model_fields.items():
        desc = info.description or fname
        out.append(Extraction(name=fname, description=desc))
    return out


def _build_config(provider: str, model: str, api_key: str | None, le_module: Any) -> dict[str, Any]:
    cfg: dict[str, Any] = {"model_id": model}
    if api_key:
        cfg["api_key"] = api_key
    if provider == "ollama":
        cfg["model_url"] = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    return cfg


def _coerce_le_result_to_pydantic(
    le_result: Any, schema_model: Type[BaseModel]
) -> tuple[BaseModel, dict[str, list[tuple[int, int]]]]:
    """Convert a LangExtract result object into (Pydantic instance, spans).

    LangExtract returns a structured object where each Extraction has a
    ``value`` and a ``span`` (or list of spans).  We map names to the
    schema model and collect spans by field name.
    """
    raw: dict[str, Any] = {}
    spans: dict[str, list[tuple[int, int]]] = {}
    for ex in getattr(le_result, "extractions", None) or []:
        name = getattr(ex, "name", None)
        value = getattr(ex, "value", None)
        if name is None:
            continue
        raw[name] = value
        sp = getattr(ex, "span", None)
        if sp is not None:
            spans.setdefault(name, []).append((int(sp.start), int(sp.end)))
        for sp2 in getattr(ex, "spans", None) or []:
            spans.setdefault(name, []).append((int(sp2.start), int(sp2.end)))
    # Fill required fields with sentinels if LangExtract did not produce them;
    # the gap will be visible to a verifier (spans dict will lack the field).
    for fname, info in schema_model.model_fields.items():
        if info.is_required() and fname not in raw:
            raw[fname] = _sentinel_for(info.annotation)
    return schema_model.model_validate(raw), spans


def _sentinel_for(annotation: Any) -> Any:
    """Match the conftest sentinel logic so missing fields don't blow up
    schema validation."""
    if annotation is str:
        return ""
    if annotation is int:
        return 0
    if annotation is float:
        return 0.0
    if annotation is bool:
        return False
    origin = getattr(annotation, "__origin__", None)
    if origin is list:
        return []
    if origin is dict:
        return {}
    return None
