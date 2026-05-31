"""AUDIT-FIX (K2#1): out-of-band pinned trust anchor tests.

These tests target audit finding C3: walk() step 1 previously compared the
fetched key's fingerprint ONLY to the in-band `public_key_fingerprint` taken
from the same attestation the issuer signed. That is circular — whoever
controls `public_key_url` serves their own key, writes the matching fingerprint
into the seal, and every step passes. The fix lets a verifier pin the issuer's
real key fingerprint OUT OF BAND and compare against that instead.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from meridian.canon import emit, keys, signing, walk
from meridian.canon.hashing import sha256_hex


LEGIT_CUSTODIAN = "legit-issuer-2026"
FORGER_CUSTODIAN = "forger-2026"


def _add_inline_content(att: dict) -> dict:
    import base64
    raw = b"This is the observed bytes for trust-anchor tests."
    digest = "sha256:" + sha256_hex(raw)
    att["witness"][0]["content_hash"] = digest
    att["witness"][0]["content_ref"] = None
    att["witness"][0]["content_inline"] = base64.b64encode(raw).decode("ascii")
    return att


@pytest.fixture
def legit_keypair(tmp_path: Path) -> tuple[str, str]:
    """A legitimate issuer keypair published at a file:// URL."""
    _, public, fingerprint = keys.keygen(LEGIT_CUSTODIAN)
    pem = signing.public_key_to_pem(public)
    url_path = tmp_path / "legit.pem"
    url_path.write_bytes(pem)
    return fingerprint, f"file://{url_path}"


@pytest.fixture
def forged_keypair(tmp_path: Path) -> tuple[str, str]:
    """An attacker keypair published at a SUBSTITUTED URL. The attacker writes
    a self-consistent in-band fingerprint matching THIS key, so the legacy
    in-band check passes."""
    _, public, fingerprint = keys.keygen(FORGER_CUSTODIAN)
    pem = signing.public_key_to_pem(public)
    url_path = tmp_path / "forged.pem"
    url_path.write_bytes(pem)
    return fingerprint, f"file://{url_path}"


def test_forged_key_rejected_when_correct_anchor_pinned(
    sample_attestation_dict: dict,
    legit_keypair: tuple[str, str],
    forged_keypair: tuple[str, str],
) -> None:
    """The forgery: attacker seals with their OWN key at a substituted URL and
    writes the matching in-band fingerprint. Without an anchor this would walk
    to valid (integrity holds). With the LEGIT fingerprint pinned out-of-band,
    step 1 must reject it — the fetched (forged) key does not match the pin."""
    legit_fp, _ = legit_keypair
    forged_fp, forged_url = forged_keypair

    att = _add_inline_content(copy.deepcopy(sample_attestation_dict))
    # Attacker emits a fully self-consistent attestation under their own key.
    sealed = emit.emit(
        att, custodian=FORGER_CUSTODIAN, public_key_url=forged_url, fingerprint=forged_fp
    )

    # Sanity: in-band only (no anchor) -> integrity passes, verdict valid.
    no_anchor = walk.walk(sealed)
    assert no_anchor["verdict"] == "valid", no_anchor
    assert no_anchor["steps"]["step1_public_key_fetch"] == "pass"

    # Pin the LEGIT issuer key out of band -> forgery rejected.
    pinned = walk.walk(sealed, trust_anchor=legit_fp)
    assert pinned["verdict"] == "invalid", pinned
    s1 = pinned["steps"]["step1_public_key_fetch"]
    assert "step1_key_not_trusted" in s1
    assert forged_fp in s1 and legit_fp in s1
    # No spurious trust_warning when an anchor was actually supplied.
    assert "trust_warning" not in pinned
    assert pinned["trust_basis"] == "pinned"


def test_correctly_pinned_legit_key_passes(
    sample_attestation_dict: dict, legit_keypair: tuple[str, str]
) -> None:
    """A legitimately-issued attestation with its real key pinned out-of-band
    walks to valid with trust_basis 'pinned'."""
    legit_fp, legit_url = legit_keypair
    att = _add_inline_content(copy.deepcopy(sample_attestation_dict))
    sealed = emit.emit(
        att, custodian=LEGIT_CUSTODIAN, public_key_url=legit_url, fingerprint=legit_fp
    )

    result = walk.walk(sealed, trust_anchor=legit_fp)
    assert result["verdict"] == "valid", result
    assert result["steps"]["step1_public_key_fetch"] == "pass"
    assert result["trust_basis"] == "pinned"
    assert "trust_warning" not in result


def test_no_anchor_validates_but_warns(
    sample_attestation_dict: dict, legit_keypair: tuple[str, str]
) -> None:
    """No trust_anchor: integrity still verifies (verdict valid) but the result
    MUST carry the machine-readable trust_warning and trust_basis 'in-band' so a
    caller cannot mistake integrity for authenticity."""
    legit_fp, legit_url = legit_keypair
    att = _add_inline_content(copy.deepcopy(sample_attestation_dict))
    sealed = emit.emit(
        att, custodian=LEGIT_CUSTODIAN, public_key_url=legit_url, fingerprint=legit_fp
    )

    result = walk.walk(sealed)
    assert result["verdict"] == "valid", result
    assert result["trust_basis"] == "in-band"
    assert result["trust_warning"] == walk.TRUST_WARNING
    assert "self-certified" in result["trust_warning"]


def test_trust_store_mapping_resolves_right_issuer(
    sample_attestation_dict: dict,
    legit_keypair: tuple[str, str],
    forged_keypair: tuple[str, str],
) -> None:
    """Mapping form {issuer_or_url: fingerprint}: the verifier resolves the pin
    by the attestation's public_key_url. A store that pins the legit url to the
    legit fingerprint rejects a forgery served from a different url."""
    legit_fp, legit_url = legit_keypair
    forged_fp, forged_url = forged_keypair

    att = _add_inline_content(copy.deepcopy(sample_attestation_dict))

    # Legit attestation -> mapping pins its url to its fingerprint -> valid.
    legit_sealed = emit.emit(
        att, custodian=LEGIT_CUSTODIAN, public_key_url=legit_url, fingerprint=legit_fp
    )
    store = {legit_url: legit_fp, "some-other-issuer": "sha256:" + "b" * 64}
    ok = walk.walk(legit_sealed, trust_anchor=store)
    assert ok["verdict"] == "valid", ok
    assert ok["trust_basis"] == "pinned"

    # Forged attestation served from forged_url: the store has the legit url's
    # pin but the forged url is absent -> fail closed (not in trust store).
    att2 = _add_inline_content(copy.deepcopy(sample_attestation_dict))
    forged_sealed = emit.emit(
        att2, custodian=FORGER_CUSTODIAN, public_key_url=forged_url, fingerprint=forged_fp
    )
    rejected = walk.walk(forged_sealed, trust_anchor=store)
    assert rejected["verdict"] == "invalid", rejected
    assert "step1_key_not_trusted" in rejected["steps"]["step1_public_key_fetch"]


def test_trust_store_resolves_by_issuer_id(
    sample_attestation_dict: dict, legit_keypair: tuple[str, str]
) -> None:
    """When the url isn't in the store but the attestation's issuer id is, the
    mapping resolves by issuer id."""
    legit_fp, legit_url = legit_keypair
    att = _add_inline_content(copy.deepcopy(sample_attestation_dict))
    issuer_id = att["issuer"]
    sealed = emit.emit(
        att, custodian=LEGIT_CUSTODIAN, public_key_url=legit_url, fingerprint=legit_fp
    )
    store = {issuer_id: legit_fp}
    result = walk.walk(sealed, trust_anchor=store)
    assert result["verdict"] == "valid", result
    assert result["trust_basis"] == "pinned"


# --- DSSE path -------------------------------------------------------------


def _dsse_obs_with_real_hash() -> dict:
    """A _minimal_obs() whose witness content_hash matches its inline bytes so
    step 4 (content re-hash) passes — _minimal_obs uses a placeholder hash."""
    import base64
    from meridian.canon.tests.test_dsse import _minimal_obs

    att = _minimal_obs()
    raw = base64.b64decode(att["witness"][0]["content_inline"])
    att["witness"][0]["content_hash"] = "sha256:" + sha256_hex(raw)
    return att


def test_dsse_forged_key_rejected_when_anchor_pinned(tmp_path: Path) -> None:
    """The DSSE envelope path must honor the trust anchor too."""
    # Legit + forger keypairs published to file:// urls.
    _, legit_pub, legit_fp = keys.keygen("dsse-legit-2026")
    legit_url = f"file://{tmp_path / 'legit_dsse.pem'}"
    (tmp_path / "legit_dsse.pem").write_bytes(signing.public_key_to_pem(legit_pub))

    _, forger_pub, forger_fp = keys.keygen("dsse-forger-2026")
    forger_url = f"file://{tmp_path / 'forged_dsse.pem'}"
    (tmp_path / "forged_dsse.pem").write_bytes(signing.public_key_to_pem(forger_pub))

    att = _dsse_obs_with_real_hash()
    envelope = emit.emit_dsse(
        att, custodian="dsse-forger-2026", public_key_url=forger_url, fingerprint=forger_fp
    )

    # No anchor: integrity-valid + warning.
    no_anchor = walk.walk(envelope)
    assert no_anchor["verdict"] == "valid", no_anchor
    assert no_anchor["trust_basis"] == "in-band"
    assert no_anchor["trust_warning"] == walk.TRUST_WARNING

    # Pin the legit key out of band: forged envelope rejected at step 1.
    pinned = walk.walk(envelope, trust_anchor=legit_fp)
    assert pinned["verdict"] == "invalid", pinned
    assert "step1_key_not_trusted" in pinned["steps"]["step1_public_key_fetch"]


def test_dsse_correctly_pinned_passes(tmp_path: Path) -> None:
    _, pub, fp = keys.keygen("dsse-legit-pass-2026")
    url = f"file://{tmp_path / 'k.pem'}"
    (tmp_path / "k.pem").write_bytes(signing.public_key_to_pem(pub))

    att = _dsse_obs_with_real_hash()
    envelope = emit.emit_dsse(
        att, custodian="dsse-legit-pass-2026", public_key_url=url, fingerprint=fp
    )
    result = walk.walk(envelope, trust_anchor=fp)
    assert result["verdict"] == "valid", result
    assert result["trust_basis"] == "pinned"
    assert "trust_warning" not in result


# --- trust-store loader ----------------------------------------------------


def test_load_trust_store_valid(tmp_path: Path) -> None:
    p = tmp_path / "store.json"
    fp = "sha256:" + "a" * 64
    p.write_text(json.dumps({"acme-2026": fp, "https://acme/key.pem": fp}))
    store = keys.load_trust_store(p)
    assert store == {"acme-2026": fp, "https://acme/key.pem": fp}


def test_load_trust_store_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not found"):
        keys.load_trust_store(tmp_path / "nope.json")


def test_load_trust_store_not_json(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        keys.load_trust_store(p)


def test_load_trust_store_not_object(tmp_path: Path) -> None:
    p = tmp_path / "arr.json"
    p.write_text(json.dumps(["a", "b"]))
    with pytest.raises(ValueError, match="must be a JSON object"):
        keys.load_trust_store(p)


def test_load_trust_store_bad_fingerprint(tmp_path: Path) -> None:
    p = tmp_path / "badfp.json"
    p.write_text(json.dumps({"acme": "not-a-fingerprint"}))
    with pytest.raises(ValueError, match="not a valid"):
        keys.load_trust_store(p)


def test_load_trust_store_non_string_value(tmp_path: Path) -> None:
    p = tmp_path / "nonstr.json"
    p.write_text(json.dumps({"acme": 123}))
    with pytest.raises(ValueError, match="must be a string"):
        keys.load_trust_store(p)


def test_load_trust_store_resolves_in_walk(
    sample_attestation_dict: dict, legit_keypair: tuple[str, str], tmp_path: Path
) -> None:
    """End to end: a trust store loaded from disk drives a walk() verdict."""
    legit_fp, legit_url = legit_keypair
    att = _add_inline_content(copy.deepcopy(sample_attestation_dict))
    sealed = emit.emit(
        att, custodian=LEGIT_CUSTODIAN, public_key_url=legit_url, fingerprint=legit_fp
    )
    store_path = tmp_path / "trust.json"
    store_path.write_text(json.dumps({legit_url: legit_fp}))
    store = keys.load_trust_store(store_path)
    result = walk.walk(sealed, trust_anchor=store)
    assert result["verdict"] == "valid", result
    assert result["trust_basis"] == "pinned"
