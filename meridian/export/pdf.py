"""PDF rendering for BriefAttestation (Phase G).

Pure-Python rendering via reportlab. The PDF embeds the BriefAttestation's
chain_hash in the footer so the printed artifact is bound to its sealed
JSON form.

Layout: cover page with subject and metadata; body with the synthesis
prose; per-source appendix listing every contributing attestation_id with
chain_hash and issued_at.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any


def render_brief_pdf(
    sealed_brief: dict[str, Any],
    *,
    out_path: Path,
    backend: str = "reportlab",
) -> Path:
    """Render a sealed BriefAttestation to a PDF on disk.

    Args:
        sealed_brief: a sealed Canon Attestation of kind="brief" produced
            by emit.emit() over a build_brief_attestation() output.
        out_path: where to write the PDF.
        backend: "reportlab" (default, always available), "weasyprint" (better typography),
                 "typst" (near-LaTeX quality, requires typst binary on PATH)

    Returns:
        out_path on success.
    """
    dispatch = {
        "reportlab": _render_brief_pdf_reportlab,
        "weasyprint": render_brief_pdf_weasyprint,
        "typst": render_brief_pdf_typst,
    }
    if backend not in dispatch:
        raise ValueError(f"Unknown backend {backend!r}. Choose: {list(dispatch)}")
    return dispatch[backend](sealed_brief, out_path=out_path)


def _render_brief_pdf_reportlab(
    sealed_brief: dict[str, Any],
    *,
    out_path: Path,
) -> Path:
    """ReportLab-based PDF renderer (original implementation)."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            PageBreak,
            Preformatted,
        )
        from reportlab.lib.enums import TA_LEFT
    except ImportError as e:
        raise RuntimeError(
            "reportlab not installed. Add 'reportlab>=4' to dependencies "
            "or pip install reportlab."
        ) from e

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    body_text = _decode_body(sealed_brief)
    chain_hash = sealed_brief.get("seal", {}).get("chain_hash", "<unsealed>")
    att_id = sealed_brief.get("attestation_id", "<no-id>")
    subject = sealed_brief.get("subject", "<no subject>")
    issuer = sealed_brief.get("issuer", "<no issuer>")
    issued_at = sealed_brief.get("issued_at", "")

    styles = getSampleStyleSheet()
    body_style = ParagraphStyle(
        "BodyText",
        parent=styles["BodyText"],
        leading=14,
        fontSize=11,
        alignment=TA_LEFT,
        spaceAfter=6,
    )
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=9, leading=11)

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=letter,
        leftMargin=1 * inch,
        rightMargin=1 * inch,
        topMargin=1 * inch,
        bottomMargin=1 * inch,
        title=subject,
        author=issuer,
    )

    story: list = []
    # Cover.
    story.append(Paragraph(_escape(subject), h1))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph(
        f"<b>Issuer:</b> {_escape(issuer)}<br/>"
        f"<b>Issued at:</b> {_escape(issued_at)}<br/>"
        f"<b>Attestation ID:</b> {_escape(att_id)}<br/>"
        f"<b>Chain hash:</b> {_escape(chain_hash)}",
        small,
    ))
    story.append(Spacer(1, 0.3 * inch))

    # Body — paragraph per blank-line-separated chunk.
    story.append(Paragraph("<b>Synthesis</b>", h2))
    story.append(Spacer(1, 0.1 * inch))
    for paragraph in body_text.split("\n\n"):
        text = paragraph.strip()
        if not text:
            continue
        story.append(Paragraph(_escape(text).replace("\n", "<br/>"), body_style))

    # Sources appendix.
    story.append(PageBreak())
    story.append(Paragraph("Source Attestations", h2))
    story.append(Spacer(1, 0.1 * inch))
    sources = _list_source_witness_entries(sealed_brief)
    for src in sources:
        story.append(Paragraph(
            f"<b>{_escape(src['observation_id'])}</b> &nbsp;&nbsp; "
            f"<font face='Courier'>{_escape(src['content_hash'])}</font>",
            small,
        ))
        story.append(Paragraph(
            f"source URI: {_escape(src.get('source', ''))}",
            small,
        ))
        story.append(Spacer(1, 0.06 * inch))

    # Verification note.
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph("Independent verification", h2))
    story.append(Paragraph(
        "This document is a rendering of a Canon-conformant Attestation. "
        "The sealed JSON form is the authoritative artifact; this PDF is a "
        "convenience for human review. To independently verify the chain "
        "of evidence, install the standalone verifier "
        "<font face='Courier'>nora-canon-verifier</font> and run "
        "<font face='Courier'>nora-canon-verifier walk attestation.json</font> "
        "against the sealed JSON. The verifier checks the Ed25519 signature, "
        "the RFC 8785 canonical chain hash, the content hashes of every "
        "witness entry, and the supports / refutation graph closure.",
        body_style,
    ))
    story.append(Paragraph(
        f"This rendering is bound to chain_hash <font face='Courier'>{_escape(chain_hash)}</font>. "
        f"If the rendering is altered, the binding does not.",
        small,
    ))

    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        footer_text = f"BriefAttestation att:{att_id} | {chain_hash[:24]}... | page {doc.page}"
        canvas.drawCentredString(letter[0] / 2.0, 0.5 * inch, footer_text)
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return out_path


def _decode_body(sealed_brief: dict[str, Any]) -> str:
    for w in sealed_brief.get("witness", []):
        if w.get("source", "").startswith("synthesis://"):
            inline = w.get("content_inline")
            if inline:
                try:
                    return base64.b64decode(inline).decode("utf-8", errors="replace")
                except Exception:
                    return "<<failed to decode synthesis body>>"
    return "<<no synthesis body found in witness>>"


def _list_source_witness_entries(sealed_brief: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        w for w in sealed_brief.get("witness", [])
        if w.get("source", "").startswith("attestation://")
    ]


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# ─── WeasyPrint renderer ──────────────────────────────────────────────────────

_COURT_CSS = """
@page {
    size: letter;
    margin: 1in 1in 1in 1.5in;
}
body {
    font-family: "Times New Roman", Times, serif;
    font-size: 12pt;
    line-height: 2;
}
h1 { font-size: 14pt; text-align: center; margin-bottom: 0.5em; }
h2 { font-size: 12pt; margin-top: 1em; }
.meta { font-size: 10pt; font-family: monospace; margin-bottom: 1em; }
.body-paragraph { margin-bottom: 1em; }
.source-entry { font-size: 10pt; margin-bottom: 0.5em; }
.verification-note { font-size: 10pt; font-style: italic; margin-top: 2em;
    border-top: 1px solid #ccc; padding-top: 1em; }
.chain-hash { font-family: monospace; font-size: 9pt; word-break: break-all; }
"""


def _brief_to_html(sealed_brief: dict[str, Any]) -> str:
    """Render a sealed BriefAttestation to HTML string for WeasyPrint."""
    body_text = _decode_body(sealed_brief)
    chain_hash = sealed_brief.get("seal", {}).get("chain_hash", "<unsealed>")
    att_id = sealed_brief.get("attestation_id", "<no-id>")
    subject = sealed_brief.get("subject", "<no subject>")
    issuer = sealed_brief.get("issuer", "<no issuer>")
    issued_at = sealed_brief.get("issued_at", "")
    sources = _list_source_witness_entries(sealed_brief)

    import html as _html
    esc = _html.escape

    paragraphs = "\n".join(
        f'<p class="body-paragraph">{esc(p.strip()).replace(chr(10), "<br/>")}</p>'
        for p in body_text.split("\n\n")
        if p.strip()
    )

    source_entries = "\n".join(
        f'<div class="source-entry">'
        f'<strong>{esc(s.get("observation_id", ""))}</strong> '
        f'<span class="chain-hash">{esc(s.get("content_hash", ""))}</span><br/>'
        f'<em>{esc(s.get("source", ""))}</em>'
        f'</div>'
        for s in sources
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<style>{_COURT_CSS}</style>
</head>
<body>
<h1>{esc(subject)}</h1>
<div class="meta">
<strong>Issuer:</strong> {esc(issuer)}<br/>
<strong>Issued at:</strong> {esc(issued_at)}<br/>
<strong>Attestation ID:</strong> {esc(att_id)}<br/>
<strong>Chain hash:</strong> <span class="chain-hash">{esc(chain_hash)}</span>
</div>
<h2>Synthesis</h2>
{paragraphs}
<h2>Source Attestations</h2>
{source_entries if source_entries else "<p><em>No source entries.</em></p>"}
<div class="verification-note">
This document is a rendering of a Canon-conformant Attestation. The sealed JSON
is the authoritative artifact. To verify independently, run
<code>meridian-canon walk attestation.json</code> against the sealed JSON.
This rendering is bound to chain_hash <span class="chain-hash">{esc(chain_hash)}</span>.
</div>
</body>
</html>"""


def render_brief_pdf_weasyprint(sealed_brief: dict[str, Any], *, out_path: Path) -> Path:
    """Render a BriefAttestation to PDF via WeasyPrint (HTML→PDF).

    Produces court-quality output with proper typography and chain_hash binding.
    Requires: pip install weasyprint
    System deps:
      macOS:   brew install pango cairo
      Ubuntu:  apt-get install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
      Windows: install GTK3 runtime from https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer
    """
    try:
        from weasyprint import HTML
    except ImportError:
        import sys
        _platform_hint = {
            "darwin": "macOS: brew install pango cairo",
            "linux":  "Ubuntu/Debian: apt-get install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0",
            "win32":  "Windows: install GTK3 runtime from https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer",
        }.get(sys.platform, "see https://doc.courtbouillon.org/weasyprint/stable/first_steps.html")
        raise RuntimeError(
            f"weasyprint not installed. Run: pip install weasyprint\n{_platform_hint}"
        )
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    html_str = _brief_to_html(sealed_brief)
    HTML(string=html_str).write_pdf(str(out_path))
    return out_path


# ─── Typst renderer ───────────────────────────────────────────────────────────


def render_brief_pdf_typst(sealed_brief: dict[str, Any], *, out_path: Path) -> Path:
    """Render a BriefAttestation to PDF via Typst typesetting engine.

    Produces near-LaTeX quality output.
    Requires: typst binary on PATH.
    Install:
      macOS:   brew install typst
      Windows: winget install Typst.Typst  (or choco install typst)
      Linux:   snap install typst  (or download from https://github.com/typst/typst/releases)
    """
    import sys
    import subprocess
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    body_text = _decode_body(sealed_brief)
    chain_hash = sealed_brief.get("seal", {}).get("chain_hash", "<unsealed>")
    att_id = sealed_brief.get("attestation_id", "<no-id>")
    subject = sealed_brief.get("subject", "<no subject>")
    issuer = sealed_brief.get("issuer", "<no issuer>")
    issued_at = sealed_brief.get("issued_at", "")
    sources = _list_source_witness_entries(sealed_brief)

    def _typ_escape(s: str) -> str:
        return (
            s.replace("\\", "\\\\")
            .replace("#", "\\#")
            .replace("@", "\\@")
            .replace("[", "\\[")
            .replace("]", "\\]")
        )

    source_items = "\n".join(
        f'- *{_typ_escape(s.get("observation_id", ""))}* — '
        f'`{_typ_escape(s.get("content_hash", "")[:40])}...` \\ '
        f'{_typ_escape(s.get("source", ""))}'
        for s in sources
    )

    typst_src = f"""#set page(paper: "us-letter", margin: (left: 1.5in, right: 1in, top: 1in, bottom: 1in))
#set text(size: 12pt)
#set par(leading: 0.8em)

#align(center)[= {_typ_escape(subject)}]

#grid(columns: (auto, 1fr), gutter: 0.5em,
  [*Issuer:*], [{_typ_escape(issuer)}],
  [*Issued at:*], [{_typ_escape(issued_at)}],
  [*Attestation ID:*], [#text(font: "Courier New", size: 9pt)[{_typ_escape(att_id)}]],
  [*Chain hash:*], [#text(font: "Courier New", size: 8pt)[{_typ_escape(chain_hash)}]],
)

== Synthesis

{_typ_escape(body_text)}

#pagebreak()
== Source Attestations

{source_items if source_items else "_No source entries._"}

#v(2em)
#line(length: 100%)
#text(size: 9pt, style: "italic")[
This document is a rendering of a Canon-conformant Attestation. The sealed JSON is the authoritative artifact.
Bound to chain\\_hash: #text(font: "Courier New")[{_typ_escape(chain_hash[:40])}...]
]
"""
    typ_path = out_path.with_suffix(".typ")
    typ_path.write_text(typst_src, encoding="utf-8")
    try:
        subprocess.run(
            ["typst", "compile", str(typ_path), str(out_path)],
            capture_output=True, check=True, timeout=60,
        )
    except FileNotFoundError:
        typ_path.unlink(missing_ok=True)
        _typst_hint = {
            "darwin": "brew install typst",
            "linux":  "snap install typst  OR  download from https://github.com/typst/typst/releases",
            "win32":  "winget install Typst.Typst  OR  choco install typst",
        }.get(sys.platform, "https://github.com/typst/typst/releases")
        raise RuntimeError(f"typst binary not found. Install: {_typst_hint}")
    except subprocess.CalledProcessError as e:
        typ_path.unlink(missing_ok=True)
        raise RuntimeError(f"typst compile failed: {e.stderr.decode()}")
    finally:
        typ_path.unlink(missing_ok=True)
    return out_path
