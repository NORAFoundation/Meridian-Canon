"""C2PA (Content Authenticity Initiative) provenance for media exhibits.

C2PA embeds a signed manifest inside media files (JUMBF container in JPEG/MP4/WAV).
The manifest records: custodian, timestamp, software, and hash of each version.
This is stronger than external hashing because provenance travels with the file.

Supported formats: image/jpeg, image/png, video/mp4, audio/mp4, audio/wav
Standards: C2PA 1.3, JUMBF ISO/IEC 19566-5

Install: pip install c2pa-python>=0.6
Note: c2pa-python requires Rust toolchain for native compilation.
      macOS: pip install c2pa-python (pre-built wheel available on PyPI)

Usage:
    result = sign_media_exhibit(audio_bytes, media_type="audio/mp4", custodian="acme-corp", ...)
    # result.embedded_file has the C2PA manifest baked in
    # result.manifest_hash is stored in WitnessEntry for chain binding
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from typing import Optional

try:
    import c2pa
    from c2pa import Builder, Reader, Signer, C2paSignerInfo, C2paSigningAlg
    _C2PA_AVAILABLE = True
except ImportError:
    _C2PA_AVAILABLE = False

MERIDIAN_CLAIM_GENERATOR = "Meridian-Canon/v0.2.0 (https://github.com/NORAFoundation/Meridian-Canon)"


@dataclass
class C2PAManifestResult:
    """Result of C2PA signing a media exhibit."""
    manifest_json: str          # the C2PA manifest as JSON string
    manifest_hash: str          # sha256: of manifest_json bytes — store in WitnessEntry
    embedded_file: bytes        # original media with C2PA manifest embedded
    media_type: str
    is_available: bool = True   # False if c2pa-python not installed


@dataclass
class C2PAVerifyResult:
    """Result of C2PA verification."""
    is_valid: bool
    manifest_json: Optional[str]
    error: Optional[str] = None


def sign_media_exhibit(
    media_bytes: bytes,
    *,
    media_type: str,
    custodian: str,
    private_key_pem: bytes,
    certificate_pem: bytes,
    source_url: str,
    acquisition_timestamp: str,  # RFC 3339 UTC
    description: Optional[str] = None,
) -> C2PAManifestResult:
    """Embed C2PA provenance manifest into a media file.

    Args:
        media_bytes: raw media bytes (audio, image, video)
        media_type: MIME type, e.g. "audio/mp4", "image/jpeg", "video/mp4"
        custodian: identifier of the entity holding the exhibit
        private_key_pem: ECDSA-P256 private key PEM (C2PA requires ECDSA or RSA; Ed25519 not supported)
        certificate_pem: X.509 certificate PEM matching private_key_pem
        source_url: URI identifying the original source of this media
        acquisition_timestamp: RFC 3339 timestamp of original acquisition

    Returns:
        C2PAManifestResult with the signed file and manifest hash.
        If c2pa-python not installed, returns a graceful fallback with is_available=False.
    """
    if not _C2PA_AVAILABLE:
        # Graceful fallback: compute hash of raw bytes, return unsigned
        raw_hash = "sha256:" + hashlib.sha256(media_bytes).hexdigest()
        fallback_manifest = json.dumps({
            "note": "c2pa-python not available — provenance recorded via SHA-256 only",
            "source_url": source_url,
            "custodian": custodian,
            "acquisition_timestamp": acquisition_timestamp,
            "media_type": media_type,
            "raw_hash": raw_hash,
        }, sort_keys=True)
        return C2PAManifestResult(
            manifest_json=fallback_manifest,
            manifest_hash="sha256:" + hashlib.sha256(fallback_manifest.encode()).hexdigest(),
            embedded_file=media_bytes,
            media_type=media_type,
            is_available=False,
        )

    manifest_def = {
        "claim_generator": MERIDIAN_CLAIM_GENERATOR,
        "claim_generator_info": [{"name": "Meridian-Canon", "version": "0.2.0"}],
        "assertions": [
            {
                "label": "stds.schema-org.CreativeWork",
                "data": {
                    "@context": "https://schema.org",
                    "@type": "MediaObject",
                    "url": source_url,
                    "dateCreated": acquisition_timestamp,
                    "description": description or f"Legal evidence exhibit. Custodian: {custodian}",
                    "author": {
                        "@type": "Organization",
                        "name": custodian,
                    },
                },
            },
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.opened",
                            "when": acquisition_timestamp,
                            "softwareAgent": {"name": "Meridian-Canon", "version": "0.2.0"},
                        },
                    ]
                },
            },
        ],
    }

    try:
        import io
        signer_info = C2paSignerInfo(
            alg=C2paSigningAlg.Es256,
            sign_cert=certificate_pem.decode("utf-8") if isinstance(certificate_pem, bytes) else certificate_pem,
            private_key=private_key_pem.decode("utf-8") if isinstance(private_key_pem, bytes) else private_key_pem,
            ta_url=b"http://timestamp.digicert.com",
        )
        signer = Signer.from_info(signer_info)
        builder = Builder(manifest_def)

        output_buf = io.BytesIO()
        builder.sign(signer, media_type, io.BytesIO(media_bytes), output_buf)
        signed_bytes = output_buf.getvalue()

        # Read back manifest
        output_buf.seek(0)
        reader = Reader(media_type, output_buf)
        manifest_json = reader.json()
        manifest_hash = "sha256:" + hashlib.sha256(manifest_json.encode()).hexdigest()

        return C2PAManifestResult(
            manifest_json=manifest_json,
            manifest_hash=manifest_hash,
            embedded_file=signed_bytes,
            media_type=media_type,
            is_available=True,
        )
    except Exception as e:
        raise RuntimeError(f"C2PA signing failed for {media_type}: {e}") from e


def verify_media_exhibit(
    media_bytes: bytes,
    *,
    media_type: str,
) -> C2PAVerifyResult:
    """Verify C2PA manifest embedded in a media file.

    Returns C2PAVerifyResult with is_valid=True if manifest validates.
    Returns is_valid=False with error if validation fails or c2pa not available.
    """
    if not _C2PA_AVAILABLE:
        return C2PAVerifyResult(
            is_valid=False,
            manifest_json=None,
            error="c2pa-python not installed — cannot verify C2PA manifest",
        )
    try:
        import io
        reader = Reader(media_type, io.BytesIO(media_bytes))
        manifest_json = reader.json()
        return C2PAVerifyResult(is_valid=True, manifest_json=manifest_json)
    except Exception as e:
        return C2PAVerifyResult(is_valid=False, manifest_json=None, error=str(e))
