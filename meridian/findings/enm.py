"""Epistemic Neutrality Masking (paper §6.5.2 + paper §6.5.2 'masking tradeoff').

Pre-process: scan input for sensitive entities (names, addresses, specific
identifiers); replace with generic S_n tokens. Maintain an entity_id -> S_n
map so post-inference re-association is exact.

Post-process: scan LM output for S_n tokens; replace with the original
entities. Add 'masked_entity_dependency' as a gap on any claim whose
correctness depends on entity-specific reasoning.

The default extractor uses regex for emails, phones, and capitalized
multi-word names. Production callers should pass a smarter extractor
(spaCy NER, an entity recognizer trained on legal-discovery corpora,
or the L3 Time-Aware Relationship Graph from the existing schema).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable


# Default entity patterns. Order matters — more specific patterns first.
_PHONE_RE = re.compile(r"\+?\d[\d\s().\-]{8,}\d")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
# Conservative name pattern: two-or-more capitalized words, not at sentence start of a long stretch.
_NAME_RE = re.compile(r"\b(?:[A-Z][a-z]+\s+){1,2}[A-Z][a-z]+\b")


def _default_extract(text: str) -> list[tuple[str, str]]:
    """Return list of (entity_kind, entity_text) tuples in scan order."""
    found: list[tuple[str, str]] = []
    for kind, pattern in (("email", _EMAIL_RE), ("phone", _PHONE_RE), ("name", _NAME_RE)):
        for m in pattern.finditer(text):
            found.append((kind, m.group(0)))
    return found


@dataclass
class EntityMap:
    """Bijective map between original entities and their S_n tokens."""

    original_to_token: dict[str, str] = field(default_factory=dict)
    token_to_original: dict[str, str] = field(default_factory=dict)
    token_to_kind: dict[str, str] = field(default_factory=dict)

    def add(self, kind: str, original: str) -> str:
        if original in self.original_to_token:
            return self.original_to_token[original]
        n = len(self.original_to_token) + 1
        token = f"S_{n}"
        self.original_to_token[original] = token
        self.token_to_original[token] = original
        self.token_to_kind[token] = kind
        return token

    def __len__(self) -> int:
        return len(self.original_to_token)

    def tokens(self) -> Iterable[str]:
        return self.token_to_original.keys()


@dataclass
class EntityMasker:
    """Round-trip masker: text → masked text + map → re-associated text.

    Attributes:
        extractor: callable returning [(kind, text), ...]; defaults to a
            regex-based extractor.
    """

    extractor: Callable[[str], list[tuple[str, str]]] = _default_extract

    def mask(self, text: str) -> tuple[str, EntityMap]:
        """Replace entities with S_n tokens; return (masked_text, map)."""
        emap = EntityMap()
        # Sort by length descending so we replace the longest match first
        # (avoids partial-overlap issues, e.g. replacing "Alice" inside "Alice Smith").
        entities = sorted(self.extractor(text), key=lambda kv: len(kv[1]), reverse=True)
        masked = text
        for kind, orig in entities:
            token = emap.add(kind, orig)
            # Use simple string replace; word-boundary regex would mishandle emails/phones.
            masked = masked.replace(orig, token)
        return masked, emap

    def unmask(self, text: str, emap: EntityMap) -> str:
        """Re-associate S_n tokens to original entities."""
        out = text
        # Replace longest tokens first so S_10 isn't partially matched by S_1.
        for token in sorted(emap.tokens(), key=len, reverse=True):
            out = out.replace(token, emap.token_to_original[token])
        return out

    def is_entity_dependent(self, statement: str, emap: EntityMap) -> bool:
        """Return True if `statement` references any S_n token from emap.

        Used by extractors to decide whether to add 'masked_entity_dependency'
        as a gap on the claim (paper §6.5.2 'masking tradeoff').
        """
        return any(token in statement for token in emap.tokens())
