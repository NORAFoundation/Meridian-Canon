"""Tests for Langfuse observability — works with or without langfuse installed."""
import base64
from meridian.refute.lm import LiteLLMAdapter, _LANGFUSE_AVAILABLE, _LITELLM_AVAILABLE
from meridian.canon.schema import ChallengeOutcome


def test_langfuse_available_flag():
    """_LANGFUSE_AVAILABLE is a bool — either True (installed) or False (graceful)."""
    assert isinstance(_LANGFUSE_AVAILABLE, bool)


def test_litellm_adapter_complete_no_langfuse():
    """complete() works when Langfuse is not installed (or does graceful error with no litellm)."""
    adapter = LiteLLMAdapter("echo/mock-model")
    if not _LITELLM_AVAILABLE:
        import pytest
        with pytest.raises(RuntimeError, match="litellm not installed"):
            adapter.complete("hello")
    # If litellm is installed, the call would go to the provider — skip that in unit test


def test_run_harness_accepts_langfuse_session_id():
    """run_harness accepts langfuse_session_id without raising."""
    from meridian.refute.harness import run_harness
    from meridian.refute.lm import EchoAdapter

    attestation = {
        "attestation_id": "TESTLF01",
        "witness": [{
            "observation_id": "obs-lf-01",
            "source": "test://",
            "content_hash": "sha256:" + "a" * 64,
            "content_inline": base64.b64encode(b"test").decode(),
            "received_at": "2026-01-01T00:00:00Z",
            "custody_chain": [],
        }],
        "findings": {
            "method": "test",
            "claims": [{
                "claim_id": "claim-lf-01",
                "statement": "test claim",
                "supports": ["obs-lf-01"],
                "inference_type": "observation",
                "gaps": [],
            }],
        },
    }
    result = run_harness(
        attestation,
        models=[EchoAdapter()],
        langfuse_session_id="TESTLF01",
    )
    assert "challenges" in result
    assert "coverage" in result


def test_run_harness_no_langfuse_session_id():
    """run_harness works without langfuse_session_id (backward compat)."""
    from meridian.refute.harness import run_harness
    from meridian.refute.lm import EchoAdapter

    attestation = {
        "attestation_id": "TESTLF02",
        "witness": [{
            "observation_id": "obs-lf-02",
            "source": "test://",
            "content_hash": "sha256:" + "b" * 64,
            "content_inline": base64.b64encode(b"test2").decode(),
            "received_at": "2026-01-01T00:00:00Z",
            "custody_chain": [],
        }],
        "findings": {
            "method": "test",
            "claims": [{
                "claim_id": "claim-lf-02",
                "statement": "test claim",
                "supports": ["obs-lf-02"],
                "inference_type": "observation",
                "gaps": [],
            }],
        },
    }
    # No langfuse_session_id provided — should work fine
    result = run_harness(attestation, models=[EchoAdapter()])
    assert "challenges" in result
