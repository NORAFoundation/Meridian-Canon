"""Tests for LiteLLMAdapter — works without litellm installed via graceful error."""
import pytest
from meridian.refute.lm import LiteLLMAdapter, _LITELLM_AVAILABLE, _LANGFUSE_AVAILABLE
from meridian.canon.schema import ChallengeOutcome


def test_litellm_adapter_attributes():
    adapter = LiteLLMAdapter("ollama/llama3.1:8b-instruct")
    assert adapter.name == "ollama/llama3.1:8b-instruct"
    assert adapter.family == "ollama"


def test_litellm_adapter_family_inference():
    gpt_adapter = LiteLLMAdapter("gpt-4o-mini")
    assert gpt_adapter.family in ("gpt", "unknown", "gpt-4o-mini")
    claude_adapter = LiteLLMAdapter("claude-haiku-4-5-20251001")
    assert claude_adapter.family in ("claude", "claude-haiku-4-5-20251001")


def test_litellm_adapter_no_litellm_raises():
    """complete() raises RuntimeError with install instructions when litellm missing."""
    if _LITELLM_AVAILABLE:
        pytest.skip("litellm is installed; this test is for when it's absent")
    adapter = LiteLLMAdapter("gpt-4o-mini")
    with pytest.raises(RuntimeError, match="litellm not installed"):
        adapter.complete("hello")


def test_litellm_adapter_refute_survives_error():
    """refute() returns SURVIVED (least-prejudicial) when complete() raises."""
    adapter = LiteLLMAdapter("nonexistent-model-xyz-123456789")
    # Will fail to connect/call, should not raise
    outcome = adapter.refute("The sky is blue.", "Source: sky is blue on clear days.")
    assert outcome == ChallengeOutcome.SURVIVED


def test_litellm_adapter_protocol_conformance():
    """LiteLLMAdapter satisfies the LMAdapter protocol."""
    from meridian.refute.lm import LMAdapter
    adapter = LiteLLMAdapter("gpt-4o-mini")
    assert isinstance(adapter, LMAdapter)


def test_langfuse_flag():
    """_LANGFUSE_AVAILABLE is a bool."""
    assert isinstance(_LANGFUSE_AVAILABLE, bool)
