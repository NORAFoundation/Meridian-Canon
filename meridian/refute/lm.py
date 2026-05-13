"""Language-model adapters for the refutation harness.

The harness is backend-agnostic: any object satisfying the LMAdapter
protocol can serve as M_1, M_2, or M_3 in Tri-Model Consensus. The paper's
default configuration uses three locally-hosted models from distinct
families (llama, mistral, gemma) to reduce correlated failure modes.

Adapters:
    EchoAdapter   — deterministic; returns a fixed outcome. For tests and
                    for cases where no LM is available (the harness still
                    produces a valid Refutation block, with declines).
    OllamaAdapter — talks to a local Ollama HTTP endpoint.
    OpenAIAdapter — frontier API. Custodian-authorized use only; the
                    refutation block records the substitution.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from meridian.canon.schema import ChallengeOutcome


REFUTATION_PROMPT = """You are an adversarial reviewer. A claim has been derived from
a source document. Your task is to attempt to REFUTE the claim using only
the source content shown. If the claim is supportable from the source,
say "survived". If the source contradicts or fails to support the claim,
say "failed" or "revised" depending on whether the claim could be salvaged.

Reply with a single word: "survived", "failed", or "revised". No prose.

Claim: {claim}

Source excerpt: {source}

Outcome:"""


def _parse_outcome(text: str) -> ChallengeOutcome:
    """Parse a model's free-text response into a ChallengeOutcome.

    The prompt asks for one word, but models add prose; this normalizes.
    Defaults to 'survived' (least-prejudicial) on parse failure.
    """
    norm = text.strip().lower()
    for token in norm.split():
        clean = token.strip(".,;:'\"")
        if clean in {"survived", "passed", "supported"}:
            return ChallengeOutcome.SURVIVED
        if clean in {"failed", "refuted", "disproven"}:
            return ChallengeOutcome.FAILED
        if clean in {"revised", "modified", "weakened"}:
            return ChallengeOutcome.REVISED
    return ChallengeOutcome.SURVIVED


# --- Protocol -------------------------------------------------------------


@runtime_checkable
class LMAdapter(Protocol):
    """Interface every adversary model must satisfy.

    Implementations should set `name` to a stable identifier suitable for
    recording in `model_outcomes` (e.g., 'llama3.1:8b-instruct'), and
    `family` to one of the broad families used in Tri-Model Consensus
    correlation analysis.
    """

    name: str
    family: str

    def complete(self, prompt: str, *, max_tokens: int = 64, temperature: float = 0.0) -> str: ...

    def refute(self, claim_statement: str, source_excerpt: str) -> ChallengeOutcome: ...


# --- Echo adapter ---------------------------------------------------------


@dataclass
class EchoAdapter:
    """Deterministic adapter that always returns the configured outcome.

    Useful for tests, for cases where the user wants to explicitly suppress
    LM-based refutation while preserving the Refutation block's structure,
    and for staging the harness before LM infrastructure is wired up.
    """

    name: str = "echo"
    family: str = "echo"
    outcome: ChallengeOutcome = ChallengeOutcome.SURVIVED

    def complete(self, prompt: str, *, max_tokens: int = 64, temperature: float = 0.0) -> str:
        return self.outcome.value

    def refute(self, claim_statement: str, source_excerpt: str) -> ChallengeOutcome:
        return self.outcome


# --- Ollama adapter -------------------------------------------------------


@dataclass
class OllamaAdapter:
    """Talks to a local Ollama HTTP endpoint.

    Default points at localhost:11434; override OLLAMA_HOST env var or pass
    `host` explicitly. The model name must be one Ollama is hosting (run
    `ollama list` to see available).

    Examples:
        OllamaAdapter(model="llama3.1:8b-instruct")
        OllamaAdapter(model="mistral-nemo:latest")
        OllamaAdapter(model="gemma2:9b-instruct-q6_K")
    """

    model: str
    host: str = ""
    name: str = ""
    family: str = ""
    timeout_seconds: int = 120

    def __post_init__(self) -> None:
        if not self.host:
            self.host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        if not self.name:
            self.name = self.model
        if not self.family:
            # Best-effort: derive family from model name prefix.
            prefix = self.model.split(":")[0].split("-")[0].lower()
            self.family = prefix or "unknown"

    def complete(self, prompt: str, *, max_tokens: int = 64, temperature: float = 0.0) -> str:
        body = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                payload = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError) as e:
            raise RuntimeError(f"Ollama request failed: {e}") from e
        return str(payload.get("response", ""))

    def refute(self, claim_statement: str, source_excerpt: str) -> ChallengeOutcome:
        prompt = REFUTATION_PROMPT.format(claim=claim_statement, source=source_excerpt)
        try:
            text = self.complete(prompt, max_tokens=24, temperature=0.0)
        except RuntimeError:
            return ChallengeOutcome.SURVIVED  # network/down → least-prejudicial; harness records this
        return _parse_outcome(text)


# --- OpenAI adapter -------------------------------------------------------


@dataclass
class OpenAIAdapter:
    """Talks to the OpenAI-compatible Chat Completions API.

    Custodian-authorized use only; the harness records the substitution
    when this adapter participates in Tri-Model Consensus, so verifiers
    can see that a frontier API saw the relevant claim.
    """

    model: str = "gpt-4o-mini"
    base_url: str = ""
    api_key: str = ""
    name: str = ""
    family: str = ""
    timeout_seconds: int = 60

    def __post_init__(self) -> None:
        if not self.base_url:
            self.base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        if not self.api_key:
            self.api_key = os.environ.get("OPENAI_API_KEY", "")
        if not self.name:
            self.name = self.model
        if not self.family:
            self.family = "gpt" if "gpt" in self.model.lower() else self.model.split("-")[0]

    def complete(self, prompt: str, *, max_tokens: int = 64, temperature: float = 0.0) -> str:
        if not self.api_key:
            raise RuntimeError("OPENAI_API_KEY not set")
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
            payload = json.loads(resp.read())
        return str(payload["choices"][0]["message"]["content"])

    def refute(self, claim_statement: str, source_excerpt: str) -> ChallengeOutcome:
        prompt = REFUTATION_PROMPT.format(claim=claim_statement, source=source_excerpt)
        try:
            text = self.complete(prompt, max_tokens=24, temperature=0.0)
        except (urllib.error.URLError, TimeoutError, RuntimeError):
            return ChallengeOutcome.SURVIVED
        return _parse_outcome(text)
