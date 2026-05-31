"""Dagster resources for Meridian-Canon pipeline."""
from __future__ import annotations
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from dagster import ConfigurableResource
    _DAGSTER_AVAILABLE = True
except ImportError:
    _DAGSTER_AVAILABLE = False

    class ConfigurableResource:  # type: ignore[no-redef]
        """Stub when Dagster not installed."""
        pass


class DatabaseResource(ConfigurableResource if _DAGSTER_AVAILABLE else object):  # type: ignore[misc]
    """psycopg connection pool resource."""
    # AUDIT-FIX (HIGH wrong DB port): canonical litigation_db listens on 5432,
    # not 5433. Override via MERIDIAN_DB_URL.
    connection_string: str = os.environ.get(
        "MERIDIAN_DB_URL", "postgresql://localhost:5432/meridian"
    )

    def get_connection(self):
        try:
            import psycopg
            return psycopg.connect(self.connection_string)
        except Exception as e:
            raise RuntimeError(f"Cannot connect to Meridian DB: {e}") from e


class LLMResource(ConfigurableResource if _DAGSTER_AVAILABLE else object):  # type: ignore[misc]
    """LM provider configuration for the pipeline refutation harness.

    LiteLLM is the correct tool at this layer — the pipeline orchestrates
    calls to multiple providers as a managed infrastructure resource.
    For per-attestation refutation outside the pipeline, use OllamaAdapter
    or OpenAIAdapter from meridian.refute.lm (no extra deps).

    Install: pip install meridian-canon[pipeline]  (includes litellm)
    """
    model_names: list = ["ollama/llama3.1:8b-instruct", "ollama/mistral-nemo:latest"]

    def get_adapters(self):
        try:
            from meridian.refute.lm import LiteLLMAdapter
            return [LiteLLMAdapter(name) for name in self.model_names]
        except ImportError:
            # AUDIT-FIX (MED LLMResource fallback masks failures): only fall back
            # when litellm itself is missing. Any other error (auth, config,
            # runtime) must propagate so the run fails loudly instead of
            # silently degrading to a different provider/model.
            from meridian.refute.lm import OllamaAdapter
            logger.warning(
                "litellm not installed; falling back to OllamaAdapter for models %s",
                self.model_names,
            )
            return [OllamaAdapter(model=name.split("/", 1)[-1]) for name in self.model_names]


class CanonResource(ConfigurableResource if _DAGSTER_AVAILABLE else object):  # type: ignore[misc]
    """Canon signing configuration."""
    custodian: str = os.environ.get("MERIDIAN_CUSTODIAN", "meridian-pipeline")
    public_key_url: str = os.environ.get(
        "MERIDIAN_PUBLIC_KEY_URL", "https://norafoundation.io/canon/key.pem"
    )
    # AUDIT-FIX (P1 seal swallows failures): when True (default), a signing
    # failure propagates and Dagster marks the run failed instead of emitting
    # an unsigned attestation downstream. Override via MERIDIAN_STRICT_SEALING=0
    # only for explicit dev/test graceful-degradation.
    strict_sealing: bool = os.environ.get("MERIDIAN_STRICT_SEALING", "1") not in ("0", "false", "False")
