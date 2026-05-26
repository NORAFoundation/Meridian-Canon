"""Tests for Rekor transparency log integration."""
import json
import os
import pytest
from unittest.mock import patch, MagicMock
from meridian.canon.transparency import (
    publish_attestation,
    RekorPublishResult,
    RekorEntry,
    _SIGSTORE_AVAILABLE,
)


def _minimal_sealed():
    return {
        "attestation_id": "TEST01",
        "seal": {
            "chain_hash": "sha256:" + "a" * 64,
            "signature": "dGVzdHNpZ25hdHVyZQ==",  # base64 of "testsignature"
            "canonicalization": "rfc8785",
            "signature_algorithm": "ed25519",
            "public_key_fingerprint": "sha256:" + "b" * 64,
            "public_key_url": "https://example.com/key.pem",
        }
    }


def test_publish_disabled_by_env(monkeypatch):
    monkeypatch.setenv("MERIDIAN_REKOR_ENABLED", "0")
    result = publish_attestation(_minimal_sealed(), public_key_pem=b"fake-pem")
    assert not result.is_published
    assert "disabled" in result.error.lower()


def test_publish_unreachable_server():
    """Returns error gracefully when Rekor server is not running."""
    result = publish_attestation(
        _minimal_sealed(),
        public_key_pem=b"fake-pem",
        rekor_url="http://localhost:19999",  # nothing running here
    )
    assert not result.is_published
    assert result.error is not None


def test_publish_success_mocked():
    """With a mocked successful Rekor response, parses entry correctly."""
    mock_response_body = json.dumps({
        "abc123uuid": {
            "logIndex": 42,
            "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
            "integratedTime": 1700000000,
            "body": "dGVzdA==",
        }
    }).encode()

    mock_resp = MagicMock()
    mock_resp.read.return_value = mock_response_body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp), \
         patch.dict("os.environ", {"MERIDIAN_REKOR_ENABLED": "1"}):
        result = publish_attestation(
            _minimal_sealed(),
            public_key_pem=b"fake-pem",
            rekor_url="http://localhost:3000",
        )

    assert result.is_published
    assert result.entry.log_index == 42
    assert result.entry.entry_uuid == "abc123uuid"
    assert "abc123uuid" in result.entry.verification_url


def test_publish_bad_response_format():
    """Unexpected response format returns is_published=False with error."""
    # Response where the entry value is missing required fields
    mock_response_body = json.dumps({"abc123uuid": {"noLogIndex": True}}).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = mock_response_body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = publish_attestation(
            _minimal_sealed(),
            public_key_pem=b"fake-pem",
            rekor_url="http://localhost:3000",
        )
    # Missing logIndex/logID keys → KeyError → is_published=False
    assert not result.is_published
    assert result.error is not None


def test_sigstore_available_flag():
    """_SIGSTORE_AVAILABLE is a bool."""
    assert isinstance(_SIGSTORE_AVAILABLE, bool)
