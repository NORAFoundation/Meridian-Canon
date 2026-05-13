"""Test fixtures: a fake schema-validating LM adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Type

import pytest
from pydantic import BaseModel


@dataclass
class FakeLMAdapter:
    """Returns canned outputs by inspecting the requested schema_model.

    Tests register `responses[schema_model] = factory_callable` where the
    callable receives the prompt string and returns a Pydantic instance.
    Callers without a registered factory get a default-constructed instance
    where every required field is filled with a sentinel.
    """

    name: str = "fake-lm"
    family: str = "fake"
    responses: dict[Type[BaseModel], Callable[[str], BaseModel]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.responses is None:
            self.responses = {}

    def complete(self, prompt: str, *, max_tokens: int = 200, temperature: float = 0.0) -> str:
        return ""

    def complete_json(
        self,
        prompt: str,
        schema_model: Type[BaseModel],
        *,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> BaseModel:
        factory = self.responses.get(schema_model)
        if factory is not None:
            return factory(prompt)
        # Auto-fill: build a minimal instance.
        return _auto_fill(schema_model)


def _auto_fill(schema_model: Type[BaseModel]) -> BaseModel:
    fields: dict[str, Any] = {}
    for name, info in schema_model.model_fields.items():
        if info.is_required():
            ann = info.annotation
            fields[name] = _sentinel_for(ann)
    return schema_model.model_validate(fields)


def _sentinel_for(annotation: Any) -> Any:
    import types
    if annotation is str:
        return "AUTO"
    if annotation is int:
        return 0
    if annotation is float:
        return 0.5
    if annotation is bool:
        return False
    if isinstance(annotation, type) and issubclass(annotation, list):
        return []
    origin = getattr(annotation, "__origin__", None)
    if origin is list:
        return []
    if origin is dict:
        return {}
    return "AUTO"


@pytest.fixture
def fake_lm() -> FakeLMAdapter:
    return FakeLMAdapter()
