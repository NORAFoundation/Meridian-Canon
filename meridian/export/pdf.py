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
) -> Path:
    """Render a sealed BriefAttestation to a PDF on disk.

    Args:
        sealed_brief: a sealed Canon Attestation of kind="brief" produced
            by emit.emit() over a build_brief_attestation() output.
        out_path: where to write the PDF.

    Returns:
        out_path on success.
    """
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
