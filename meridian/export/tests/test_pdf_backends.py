"""Tests for multi-backend PDF rendering."""
import base64
import pytest
from pathlib import Path
from meridian.export.pdf import render_brief_pdf, _brief_to_html


def _minimal_brief():
    body = base64.b64encode(b"This is the synthesis text.\n\nSecond paragraph.").decode()
    return {
        "attestation_id": "TEST01234",
        "kind": "brief",
        "subject": "Test Brief Subject",
        "issuer": "test-issuer",
        "issued_at": "2026-01-01T00:00:00.000000Z",
        "seal": {"chain_hash": "sha256:" + "b" * 64},
        "witness": [
            {
                "observation_id": "obs-1",
                "source": "synthesis://body",
                "content_inline": body,
                "content_hash": "sha256:" + "c" * 64,
            },
            {
                "observation_id": "obs-2",
                "source": "attestation://prior-01",
                "content_inline": body,
                "content_hash": "sha256:" + "d" * 64,
            },
        ],
    }


def test_brief_to_html_contains_chain_hash():
    brief = _minimal_brief()
    html = _brief_to_html(brief)
    assert "b" * 40 in html  # chain hash fragment
    assert "Test Brief Subject" in html


def test_brief_to_html_contains_synthesis():
    brief = _minimal_brief()
    html = _brief_to_html(brief)
    assert "synthesis" in html.lower() or "Synthesis" in html


def test_render_reportlab(tmp_path):
    out = tmp_path / "brief.pdf"
    render_brief_pdf(_minimal_brief(), out_path=out, backend="reportlab")
    assert out.exists()
    assert out.stat().st_size > 1000


def test_render_unknown_backend_raises():
    with pytest.raises(ValueError, match="Unknown backend"):
        render_brief_pdf(_minimal_brief(), out_path=Path("/tmp/x.pdf"), backend="invalid")


def test_render_weasyprint_or_skip(tmp_path):
    try:
        import weasyprint
    except ImportError:
        pytest.skip("weasyprint not installed")
    out = tmp_path / "brief_wp.pdf"
    render_brief_pdf(_minimal_brief(), out_path=out, backend="weasyprint")
    assert out.exists()
    assert out.stat().st_size > 1000


def test_render_typst_or_skip(tmp_path):
    import shutil
    if not shutil.which("typst"):
        pytest.skip("typst binary not on PATH")
    out = tmp_path / "brief_typst.pdf"
    render_brief_pdf(_minimal_brief(), out_path=out, backend="typst")
    assert out.exists()
    assert out.stat().st_size > 1000
