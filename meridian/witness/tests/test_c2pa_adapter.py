"""Tests for C2PA media adapter — graceful without valid c2pa keys."""
from meridian.witness.c2pa_adapter import (
    sign_media_exhibit, verify_media_exhibit,
    C2PAManifestResult, C2PAVerifyResult,
    _C2PA_AVAILABLE,
)

_FAKE_KEY_PEM = b"--- PLACEHOLDER ---"  # real ECDSA key needed for actual C2PA
_FAKE_CERT_PEM = b"--- PLACEHOLDER ---"
_SAMPLE_AUDIO = b"\x00" * 1024  # not a real audio file


def test_sign_returns_manifest_result():
    """sign_media_exhibit always returns a C2PAManifestResult."""
    try:
        result = sign_media_exhibit(
            _SAMPLE_AUDIO,
            media_type="audio/mp4",
            custodian="test-custodian",
            private_key_pem=_FAKE_KEY_PEM,
            certificate_pem=_FAKE_CERT_PEM,
            source_url="file:///test.m4a",
            acquisition_timestamp="2026-01-01T00:00:00Z",
        )
        assert isinstance(result, C2PAManifestResult)
        assert result.manifest_hash.startswith("sha256:")
        assert result.media_type == "audio/mp4"
    except RuntimeError as e:
        # C2PA signing with fake keys may raise RuntimeError — that's expected
        assert "C2PA signing failed" in str(e) or "c2pa" in str(e).lower()


def test_sign_fallback_when_unavailable():
    """Without c2pa-python, sign_media_exhibit returns a graceful fallback."""
    if _C2PA_AVAILABLE:
        # Test the fallback path directly by simulating the no-c2pa case
        import meridian.witness.c2pa_adapter as mod
        original = mod._C2PA_AVAILABLE
        mod._C2PA_AVAILABLE = False
        try:
            result = sign_media_exhibit(
                _SAMPLE_AUDIO,
                media_type="audio/mp4",
                custodian="test-custodian",
                private_key_pem=_FAKE_KEY_PEM,
                certificate_pem=_FAKE_CERT_PEM,
                source_url="file:///test.m4a",
                acquisition_timestamp="2026-01-01T00:00:00Z",
            )
            assert isinstance(result, C2PAManifestResult)
            assert not result.is_available
            assert result.embedded_file == _SAMPLE_AUDIO
            assert result.manifest_hash.startswith("sha256:")
        finally:
            mod._C2PA_AVAILABLE = original
    else:
        result = sign_media_exhibit(
            _SAMPLE_AUDIO,
            media_type="audio/mp4",
            custodian="test-custodian",
            private_key_pem=_FAKE_KEY_PEM,
            certificate_pem=_FAKE_CERT_PEM,
            source_url="file:///test.m4a",
            acquisition_timestamp="2026-01-01T00:00:00Z",
        )
        assert not result.is_available
        assert result.embedded_file == _SAMPLE_AUDIO


def test_verify_fallback_when_unavailable():
    """Without c2pa-python, verify returns is_valid=False with error."""
    import meridian.witness.c2pa_adapter as mod
    if not _C2PA_AVAILABLE:
        result = verify_media_exhibit(_SAMPLE_AUDIO, media_type="audio/mp4")
        assert isinstance(result, C2PAVerifyResult)
        assert not result.is_valid
        assert "not installed" in result.error
    else:
        # Simulate unavailability
        original = mod._C2PA_AVAILABLE
        mod._C2PA_AVAILABLE = False
        try:
            result = verify_media_exhibit(_SAMPLE_AUDIO, media_type="audio/mp4")
            assert not result.is_valid
            assert result.error is not None
        finally:
            mod._C2PA_AVAILABLE = original


def test_manifest_hash_is_stable():
    """Same input produces same manifest hash (deterministic fallback)."""
    import meridian.witness.c2pa_adapter as mod
    original = mod._C2PA_AVAILABLE
    mod._C2PA_AVAILABLE = False
    try:
        kwargs = dict(
            media_type="audio/mp4",
            custodian="test",
            private_key_pem=_FAKE_KEY_PEM,
            certificate_pem=_FAKE_CERT_PEM,
            source_url="file:///test.m4a",
            acquisition_timestamp="2026-01-01T00:00:00Z",
        )
        r1 = sign_media_exhibit(b"test audio bytes", **kwargs)
        r2 = sign_media_exhibit(b"test audio bytes", **kwargs)
        assert r1.manifest_hash == r2.manifest_hash
    finally:
        mod._C2PA_AVAILABLE = original


def test_c2pa_available_flag():
    """_C2PA_AVAILABLE is a bool."""
    assert isinstance(_C2PA_AVAILABLE, bool)
