"""Language-model adapters for the refutation harness.

The harness is backend-agnostic: any object satisfying the LMAdapter
protocol can serve as M_1, M_2, or M_3 in Tri-Model Consensus. The paper's
default configuration uses three locally-hosted models from distinct
families (llama, mistral, gemma) to reduce correlated failure modes.

Core adapters (no extra deps — use these):
    EchoAdapter   — deterministic; returns a fixed outcome. For tests and
                    for cases where no LM is available (the harness still
                    produces a valid Refutation block, with declines).
    OllamaAdapter — talks to a local Ollama HTTP endpoint via urllib.
    OpenAIAdapter — any OpenAI-compatible API (OpenAI, vLLM, LM Studio,
                    local llama.cpp server) via urllib.

Optional (infrastructure layer — use in meridian/pipeline/ not here):
    LiteLLMAdapter — unified adapter via LiteLLM (pip install litellm).
                     Belongs in the pipeline orchestration layer, not in
                     per-attestation refutation calls. Kept here for
                     convenience but not the recommended path.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from meridian.canon.schema import ChallengeOutcome

# --- Langfuse observability (optional) -----------------------------------

try:
    from langfuse.decorators import observe as _lf_observe, langfuse_context as _lf_ctx
    _LANGFUSE_AVAILABLE = True
except ImportError:
    # No-op decorator when Langfuse not installed
    def _lf_observe(*args, **kwargs):  # type: ignore[misc]
        def decorator(fn):
            return fn
        return decorator if args and callable(args[0]) else decorator
    _LANGFUSE_AVAILABLE = False
    _lf_ctx = None  # type: ignore[assignment]

# --- LiteLLM (optional) --------------------------------------------------

try:
    import litellm as _litellm
    _LITELLM_AVAILABLE = True
except ImportError:
    _LITELLM_AVAILABLE = False


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


# --- LiteLLM adapter (recommended) ----------------------------------------
# OllamaAdapter and OpenAIAdapter are kept for backward compat.
# Prefer LiteLLMAdapter for new code.


@dataclass
class LiteLLMAdapter:
    """Backend-agnostic adapter via LiteLLM — supports 100+ providers.

    Model name format: "<provider>/<model>" or just "<model>" for OpenAI.
    Examples:
        LiteLLMAdapter("ollama/llama3.1:8b-instruct")    # local Ollama
        LiteLLMAdapter("gpt-4o-mini")                    # OpenAI
        LiteLLMAdapter("claude-haiku-4-5-20251001")      # Anthropic
        LiteLLMAdapter("groq/llama3-8b-8192")            # Groq
        LiteLLMAdapter("ollama/mistral-nemo:latest")     # local Mistral

    For Tri-Model Consensus use three models from different families:
        models = [
            LiteLLMAdapter("ollama/llama3.1:8b-instruct"),
            LiteLLMAdapter("ollama/mistral-nemo:latest"),
            LiteLLMAdapter("claude-haiku-4-5-20251001"),
        ]
    """

    model: str
    name: str = ""
    family: str = ""
    timeout: int = 120

    def __post_init__(self) -> None:
        if not self.name:
            self.name = self.model
        if not self.family:
            # Best-effort family from model string
            provider = self.model.split("/")[0] if "/" in self.model else ""
            base = self.model.split("/")[-1].split(":")[0].split("-")[0].lower()
            self.family = provider or base or "unknown"

    @_lf_observe(name="meridian.refute.lm.complete")  # type: ignore[misc]
    def complete(self, prompt: str, *, max_tokens: int = 64, temperature: float = 0.0) -> str:
        if _LANGFUSE_AVAILABLE and _lf_ctx:
            _lf_ctx.update_current_observation(
                model=self.model,
                input=prompt,
                metadata={"max_tokens": max_tokens, "temperature": temperature, "family": self.family},
            )
        if not _LITELLM_AVAILABLE:
            raise RuntimeError(
                "litellm not installed. Run: pip install litellm>=1.40"
            )
        response = _litellm.completion(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=temperature,
            timeout=self.timeout,
        )
        result = str(response.choices[0].message.content or "")
        if _LANGFUSE_AVAILABLE and _lf_ctx:
            _lf_ctx.update_current_observation(output=result)
        return result

    def refute(self, claim_statement: str, source_excerpt: str) -> ChallengeOutcome:
        prompt = REFUTATION_PROMPT.format(claim=claim_statement, source=source_excerpt)
        try:
            text = self.complete(prompt, max_tokens=24, temperature=0.0)
        except Exception:
            return ChallengeOutcome.SURVIVED  # least-prejudicial on failure
        return _parse_outcome(text)
