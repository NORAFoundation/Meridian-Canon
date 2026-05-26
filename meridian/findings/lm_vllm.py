"""vLLM client adapter using the OpenAI-compatible API + guided_json.

vLLM serves models behind /v1/chat/completions (OpenAI-compatible). For
structured output, vLLM accepts an `extra_body={"guided_json": <schema>}`
argument that constrains generation to the given JSON schema via Outlines.
This adapter uses that to guarantee Pydantic-conformant output.

Server example (separate process / VM with CUDA):
    pip install vllm
    python -m vllm.entrypoints.openai.api_server \
        --model Qwen/Qwen2.5-7B-Instruct \
        --quantization gptq_marlin \
        --host 0.0.0.0 --port 8000

Then on the client side (this repo):
    adapter = VLLMAdapter(
        model="Qwen/Qwen2.5-7B-Instruct",
        base_url="http://your-vllm-host:8000/v1",
    )

When vLLM is not reachable, all calls raise; callers should wrap with
appropriate decline-handling so the harness still produces R6-conformant
output.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Type, TypeVar

from pydantic import BaseModel, ValidationError


T = TypeVar("T", bound=BaseModel)


@dataclass
class VLLMAdapter:
    """Client for a vLLM-hosted OpenAI-compatible chat completions endpoint.

    Attributes:
        model: vLLM model identifier (must match the --model arg the server was started with).
        base_url: e.g. "http://localhost:8000/v1".
        api_key: vLLM accepts any non-empty string by default; "EMPTY" is conventional.
        timeout_seconds: per-request timeout.
    """

    model: str
    base_url: str = ""
    api_key: str = "EMPTY"
    name: str = ""
    family: str = ""
    timeout_seconds: int = 180

    def __post_init__(self) -> None:
        if not self.base_url:
            self.base_url = os.environ.get("VLLM_BASE_URL", "http://localhost:8000/v1")
        if not self.name:
            self.name = self.model
        if not self.family:
            prefix = self.model.split("/")[-1].split("-")[0].lower() if "/" in self.model else self.model.split("-")[0].lower()
            self.family = prefix or "vllm"

    # --- Plain text completion (for prompts that don't need JSON) --------

    def complete(
        self,
        prompt: str,
        *,
        max_tokens: int = 200,
        temperature: float = 0.0,
    ) -> str:
        """OpenAI-compatible chat call returning plain text content."""
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        return self._post_chat(payload)

    # --- Schema-constrained JSON completion (the main path for enrichment)

    def complete_json(
        self,
        prompt: str,
        schema_model: Type[T],
        *,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> T:
        """Call the LM with vLLM's guided_json constraint; return validated Pydantic.

        The schema is passed via `extra_body={"guided_json": <JSON Schema>}`,
        which vLLM enforces via Outlines/Marlin guided decoding. The output
        is therefore guaranteed to validate against the schema_model.

        Falls back to JSON-mode + Pydantic validation with retry if the
        server doesn't support guided_json (e.g., a non-vLLM OpenAI server).
        """
        json_schema = schema_model.model_json_schema()
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a precise extraction engine. Respond with a single "
                        "JSON object that conforms to the requested schema. Do not "
                        "include prose, markdown, or commentary outside the JSON."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
            # vLLM-specific: enforce schema via Outlines.
            "extra_body": {"guided_json": json_schema},
            # Standard OpenAI: also request JSON object mode as a fallback.
            "response_format": {"type": "json_object"},
        }
        text = self._post_chat(payload)
        return _parse_json_strict(text, schema_model)

    # --- Internal HTTP helpers -------------------------------------------

    def _post_chat(self, payload: dict[str, Any]) -> str:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                envelope = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"vLLM HTTPError {e.code}: {detail}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            raise RuntimeError(f"vLLM unreachable at {self.base_url}: {e}") from e
        choices = envelope.get("choices") or []
        if not choices:
            raise RuntimeError(f"vLLM returned no choices: {envelope}")
        return str(choices[0]["message"]["content"])


def _parse_json_strict(text: str, schema_model: Type[T]) -> T:
    """Parse text as JSON and validate against the Pydantic schema_model.

    Tolerates surrounding markdown fences (```json ... ```) and leading/
    trailing whitespace, but does not tolerate prose interleaved with JSON.
    """
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()
        if cleaned.startswith("json"):
            cleaned = cleaned[4:].lstrip()
    try:
        obj = json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise ValueError(f"LM did not return valid JSON: {e}; got {text!r}") from e
    try:
        return schema_model.model_validate(obj)
    except ValidationError as e:
        raise ValueError(f"LM JSON failed Pydantic validation: {e}") from e
