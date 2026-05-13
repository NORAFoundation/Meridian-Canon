"""Source-span propagation for Findings claims.

The Canon schema represents a Claim as ``{statement, supports, inference_type, gaps}``.
Per the 2026-05-07 plan we propagate character-offset spans from the
source text into the Claim's ``gaps`` list with a stable, parseable shape:

    source_span:char[<start>-<end>]                 # single span
    source_span:char[12-45]
    source_span:char[12-45,67-89]                   # multiple spans on one claim

This is opt-in -- claims built without span info behave exactly as before.
A future schema bump (canon_version 0.1.2) may promote spans to a
first-class field on Claim; this representation is the no-schema-bump
intermediate per the plan's decision #5.

The helpers here are pure functions; they do not depend on LangExtract
or any other extraction backend.
"""

from __future__ import annotations

import re
from typing import Iterable

# A span is a half-open or closed character interval [start, end] over the
# original source text.  We do not enforce a convention here; each
# extractor documents whether end is inclusive or exclusive in its own
# method docstring.  The shape on the wire is identical either way.

_SPAN_PREFIX = "source_span:char"
_SPAN_RE = re.compile(r"^source_span:char\[((?:\d+-\d+)(?:,\d+-\d+)*)\]$")


def format_span_gap(spans: Iterable[tuple[int, int]]) -> str:
    """Render an iterable of (start, end) tuples as a single gap entry.

    Returns the empty string if the iterable is empty so callers can
    skip appending; we never emit ``source_span:char[]``.
    """
    pairs = [(int(s), int(e)) for s, e in spans]
    if not pairs:
        return ""
    return f"{_SPAN_PREFIX}[" + ",".join(f"{s}-{e}" for s, e in pairs) + "]"


def parse_span_gap(gap: str) -> list[tuple[int, int]]:
    """Inverse of ``format_span_gap``; returns [] for non-span gap strings."""
    m = _SPAN_RE.match(gap.strip())
    if not m:
        return []
    out: list[tuple[int, int]] = []
    for piece in m.group(1).split(","):
        s, e = piece.split("-", 1)
        out.append((int(s), int(e)))
    return out


def claim_spans(claim: dict) -> list[tuple[int, int]]:
    """Collect all spans declared in a Claim's gaps."""
    out: list[tuple[int, int]] = []
    for g in claim.get("gaps") or []:
        out.extend(parse_span_gap(g))
    return out


def attach_spans_to_claim(claim: dict, spans: Iterable[tuple[int, int]]) -> dict:
    """Append a single source-span gap entry to a Claim, in place.

    No-ops when ``spans`` is empty.  Returns the claim for chaining.
    """
    formatted = format_span_gap(spans)
    if formatted:
        claim.setdefault("gaps", []).append(formatted)
    return claim
