"""Deterministic regex pre-extraction.

Free, fast, high-precision pass that extracts fields the LM doesn't need
to handle. The output of this module seeds the LM call (the LM sees what
the regex already found and is asked to verify and augment) and is also
cross-validated against the LM output for confidence scoring.

Conventions:
  - Each extractor returns a list[T] of candidates with source spans.
  - Functions are pure: text in, structured out. No side effects.
  - Patterns are conservative: prefer false negatives over false positives.
"""

from __future__ import annotations

import re
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Iterable

from .rich_schema import (
    CaseNumber, DateReference, MonetaryAmount, SourceSpan,
    StatuteCitation, CaseLawCitation,
)


# --------------------------------------------------------------------------- #
# Case numbers — Wisconsin / Minnesota / generic federal                      #
# --------------------------------------------------------------------------- #

# Wisconsin: YYYY[CTYPE]NNNNNN  e.g. EXAMPLE-MATTER-001, EXAMPLE-MATTER-003, EXAMPLE-MATTER-002
_WI_CASE_RE = re.compile(
    r"\b(?P<year>20\d{2})(?P<type>JC|TP|CF|FA|JD|CV|CR|TR|FO|GN|JV|ME|PA|PR|SC)(?P<seq>\d{5,7})\b"
)

# Minnesota: NN-CC-NN-NNN  e.g. EXAMPLE-MATTER-004, EXAMPLE-MATTER-005
_MN_CASE_RE = re.compile(
    r"\b(?P<county>\d{2})-(?P<type>CR|CV|FA|JV|PR|GR)-(?P<year>\d{2})-(?P<seq>\d{3,5})\b"
)

# Federal: N:NN-CC-NNNNN  e.g. 1:24-cv-00123
_FED_CASE_RE = re.compile(
    r"\b(?P<court>\d):(?P<year>\d{2})-(?P<type>cv|cr|mc|md|pq)-(?P<seq>\d{4,6})\b",
    re.IGNORECASE,
)

_WI_TYPE_DESC = {
    "JC": "juvenile/CHIPS", "TP": "termination of parental rights",
    "CF": "criminal felony", "FA": "family", "JD": "juvenile delinquency",
    "CV": "civil", "CR": "criminal misdemeanor", "TR": "traffic",
    "FO": "forfeiture", "GN": "guardianship", "JV": "juvenile",
    "ME": "mental commitment", "PA": "paternity", "PR": "probate",
    "SC": "small claims",
}


def find_case_numbers(text: str) -> list[CaseNumber]:
    out: list[CaseNumber] = []
    seen: set[str] = set()

    for m in _WI_CASE_RE.finditer(text):
        raw = m.group(0)
        canonical = raw  # WI form is already canonical
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append(CaseNumber(
            raw=raw,
            canonical=canonical,
            year=int(m.group("year")),
            case_type_code=m.group("type"),
            sequence=int(m.group("seq")),
            jurisdiction="Wisconsin",
            court=None,
            confidence=0.95,
            source=SourceSpan(char_start=m.start(), char_end=m.end(),
                              quoted_text=_quote_around(text, m.start(), m.end())),
        ))

    for m in _MN_CASE_RE.finditer(text):
        raw = m.group(0)
        canonical = raw.upper()
        if canonical in seen:
            continue
        seen.add(canonical)
        # 2-digit year → 4-digit (window: 50→1950, 51→2051 to 99→1999, 00→2000)
        yy = int(m.group("year"))
        full_year = 2000 + yy if yy < 50 else 1900 + yy
        out.append(CaseNumber(
            raw=raw, canonical=canonical,
            year=full_year,
            case_type_code=m.group("type").upper(),
            sequence=int(m.group("seq")),
            jurisdiction="Minnesota",
            court=f"County {m.group('county')}",
            confidence=0.92,
            source=SourceSpan(char_start=m.start(), char_end=m.end(),
                              quoted_text=_quote_around(text, m.start(), m.end())),
        ))

    for m in _FED_CASE_RE.finditer(text):
        raw = m.group(0)
        canonical = raw.lower()
        if canonical in seen:
            continue
        seen.add(canonical)
        yy = int(m.group("year"))
        full_year = 2000 + yy if yy < 50 else 1900 + yy
        out.append(CaseNumber(
            raw=raw, canonical=canonical,
            year=full_year,
            case_type_code=m.group("type").lower(),
            sequence=int(m.group("seq")),
            jurisdiction="Federal",
            confidence=0.90,
            source=SourceSpan(char_start=m.start(), char_end=m.end(),
                              quoted_text=_quote_around(text, m.start(), m.end())),
        ))
    return out


# --------------------------------------------------------------------------- #
# Statutes                                                                    #
# --------------------------------------------------------------------------- #

# Wis. Stat. § 48.42(1)  /  Wisconsin Statutes 48.42  /  ch. 48
_WI_STAT_RE = re.compile(
    r"\bWis\.?\s*Stat\.?(?:utes?)?\s*(?:§|sec\.?|chapter|ch\.?)?\s*"
    r"(?P<title>\d+)(?:\.(?P<section>\d+))?(?:\((?P<sub>[\w\d]+)\))?",
    re.IGNORECASE,
)
_USC_RE = re.compile(
    r"\b(?P<title>\d{1,2})\s*U\.?S\.?C\.?\s*§+\s*(?P<section>\d+(?:\.\d+)?)"
    r"(?:\((?P<sub>[\w\d]+)\))?",
    re.IGNORECASE,
)
_CFR_RE = re.compile(
    r"\b(?P<title>\d{1,2})\s*C\.?F\.?R\.?\s*§+\s*(?P<section>\d+(?:\.\d+)?)",
    re.IGNORECASE,
)


def find_statutes(text: str) -> list[StatuteCitation]:
    out: list[StatuteCitation] = []
    seen: set[str] = set()

    for m in _WI_STAT_RE.finditer(text):
        title = m.group("title")
        section = m.group("section") or ""
        sub = m.group("sub") or ""
        canonical = f"wis.stat.{title}" + (f".{section}" if section else "") + (f".{sub}" if sub else "")
        key = canonical
        if key in seen:
            continue
        seen.add(key)
        out.append(StatuteCitation(
            raw=m.group(0),
            canonical=canonical,
            jurisdiction="wisconsin",
            code="WisStat",
            title=title,
            section=section or None,
            subsection=sub or None,
            source=SourceSpan(char_start=m.start(), char_end=m.end(),
                              quoted_text=_quote_around(text, m.start(), m.end())),
        ))

    for m in _USC_RE.finditer(text):
        title = m.group("title")
        section = m.group("section")
        sub = m.group("sub") or ""
        canonical = f"usc.{title}.{section}" + (f".{sub}" if sub else "")
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append(StatuteCitation(
            raw=m.group(0), canonical=canonical,
            jurisdiction="federal", code="USC",
            title=title, section=section, subsection=sub or None,
            source=SourceSpan(char_start=m.start(), char_end=m.end(),
                              quoted_text=_quote_around(text, m.start(), m.end())),
        ))

    for m in _CFR_RE.finditer(text):
        title = m.group("title")
        section = m.group("section")
        canonical = f"cfr.{title}.{section}"
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append(StatuteCitation(
            raw=m.group(0), canonical=canonical,
            jurisdiction="federal", code="CFR",
            title=title, section=section,
            source=SourceSpan(char_start=m.start(), char_end=m.end(),
                              quoted_text=_quote_around(text, m.start(), m.end())),
        ))
    return out


# --------------------------------------------------------------------------- #
# Case-law citations (rough)                                                  #
# --------------------------------------------------------------------------- #

# e.g. "Smith v. Jones, 123 Wis. 2d 456 (2019)"
_CASE_LAW_RE = re.compile(
    r"\b(?P<name>[A-Z][\w'\.-]+(?:\s+[A-Z][\w'\.-]+)*)\s+v\.?\s+"
    r"(?P<name2>[A-Z][\w'\.-]+(?:\s+[A-Z][\w'\.-]+)*)"
    r"(?:,\s*(?P<vol>\d+)\s+(?P<reporter>[A-Z][\w\.\s]+?)\s+(?P<page>\d+))?"
    r"(?:\s*\((?P<court>[\w\s\.]+?)?\s*(?P<year>\d{4})\))?"
)


def find_case_law(text: str) -> list[CaseLawCitation]:
    out: list[CaseLawCitation] = []
    seen: set[str] = set()
    for m in _CASE_LAW_RE.finditer(text):
        case_name = f"{m.group('name')} v. {m.group('name2')}"
        if case_name.lower() in seen:
            continue
        seen.add(case_name.lower())
        out.append(CaseLawCitation(
            raw=m.group(0),
            case_name=case_name,
            reporter=(m.group("reporter") or None) and m.group("reporter").strip(),
            volume=int(m.group("vol")) if m.group("vol") else None,
            page=int(m.group("page")) if m.group("page") else None,
            year=int(m.group("year")) if m.group("year") else None,
            court=(m.group("court") or None) and m.group("court").strip() or None,
            source=SourceSpan(char_start=m.start(), char_end=m.end()),
        ))
    return out


# --------------------------------------------------------------------------- #
# Dates                                                                       #
# --------------------------------------------------------------------------- #

# MM/DD/YYYY or MM-DD-YYYY
_DATE_NUM_RE = re.compile(r"\b(?P<m>\d{1,2})[/\-](?P<d>\d{1,2})[/\-](?P<y>(?:19|20)\d{2})\b")
# YYYY-MM-DD
_DATE_ISO_RE = re.compile(r"\b(?P<y>(?:19|20)\d{2})-(?P<m>\d{2})-(?P<d>\d{2})\b")
# Month DD, YYYY  (also "Month DDth")
_DATE_LONG_RE = re.compile(
    r"\b(?P<mon>January|February|March|April|May|June|July|August|"
    r"September|October|November|December|"
    r"Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?\s+"
    r"(?P<d>\d{1,2})(?:st|nd|rd|th)?,?\s+(?P<y>(?:19|20)\d{2})\b",
    re.IGNORECASE,
)

_MONTH = {
    "january": 1, "jan": 1, "february": 2, "feb": 2, "march": 3, "mar": 3,
    "april": 4, "apr": 4, "may": 5, "june": 6, "jun": 6, "july": 7, "jul": 7,
    "august": 8, "aug": 8, "september": 9, "sep": 9, "sept": 9,
    "october": 10, "oct": 10, "november": 11, "nov": 11, "december": 12, "dec": 12,
}


def _norm_date(y: int, m: int, d: int) -> str | None:
    try:
        return datetime(y, m, d).date().isoformat()
    except ValueError:
        return None


def find_dates(text: str) -> list[DateReference]:
    out: list[DateReference] = []
    seen: set[str] = set()
    for m in _DATE_ISO_RE.finditer(text):
        iso = _norm_date(int(m.group("y")), int(m.group("m")), int(m.group("d")))
        if not iso or iso in seen:
            continue
        seen.add(iso)
        out.append(DateReference(
            iso=iso, raw=m.group(0), certainty="explicit",
            source=SourceSpan(char_start=m.start(), char_end=m.end(),
                              quoted_text=_quote_around(text, m.start(), m.end())),
        ))
    for m in _DATE_NUM_RE.finditer(text):
        iso = _norm_date(int(m.group("y")), int(m.group("m")), int(m.group("d")))
        if not iso or iso in seen:
            continue
        seen.add(iso)
        out.append(DateReference(
            iso=iso, raw=m.group(0), certainty="explicit",
            source=SourceSpan(char_start=m.start(), char_end=m.end(),
                              quoted_text=_quote_around(text, m.start(), m.end())),
        ))
    for m in _DATE_LONG_RE.finditer(text):
        mon_idx = _MONTH.get(m.group("mon").lower())
        if not mon_idx:
            continue
        iso = _norm_date(int(m.group("y")), mon_idx, int(m.group("d")))
        if not iso or iso in seen:
            continue
        seen.add(iso)
        out.append(DateReference(
            iso=iso, raw=m.group(0), certainty="explicit",
            source=SourceSpan(char_start=m.start(), char_end=m.end(),
                              quoted_text=_quote_around(text, m.start(), m.end())),
        ))
    return out


# --------------------------------------------------------------------------- #
# Money                                                                       #
# --------------------------------------------------------------------------- #

# $1,234.56  /  $1234  /  USD 1,234.56  /  1,234.56 USD
_MONEY_DOLLAR_RE = re.compile(
    r"(?<![\w\.])\$\s*(?P<amt>\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?)\b"
)
_MONEY_USD_RE = re.compile(
    r"\bUSD\s*\$?\s*(?P<amt>\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?)\b",
    re.IGNORECASE,
)
_MONEY_TRAILING_RE = re.compile(
    r"\b(?P<amt>\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?|\d+\.\d{1,2})\s*USD\b",
    re.IGNORECASE,
)


def _parse_amount(s: str) -> Decimal | None:
    try:
        return Decimal(s.replace(",", ""))
    except (InvalidOperation, ValueError):
        return None


def find_monetary(text: str) -> list[MonetaryAmount]:
    out: list[MonetaryAmount] = []
    seen: set[str] = set()
    for pat, cur in ((_MONEY_DOLLAR_RE, "USD"), (_MONEY_USD_RE, "USD"), (_MONEY_TRAILING_RE, "USD")):
        for m in pat.finditer(text):
            amt = _parse_amount(m.group("amt"))
            if amt is None:
                continue
            key = f"{amt}-{m.start()}"
            if key in seen:
                continue
            seen.add(key)
            out.append(MonetaryAmount(
                value=amt, currency=cur, raw=m.group(0),
                source=SourceSpan(char_start=m.start(), char_end=m.end(),
                                  quoted_text=_quote_around(text, m.start(), m.end())),
            ))
    return out


# --------------------------------------------------------------------------- #
# Bates / production numbering                                                #
# --------------------------------------------------------------------------- #

_BATES_RE = re.compile(r"\b(?P<prefix>[A-Z]{2,})[\s_-]?(?P<num>\d{4,8})\b")


def find_bates(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in _BATES_RE.finditer(text):
        prefix = m.group("prefix")
        if prefix in {"USA", "PDF", "RFP", "RFA", "FBI", "DOC"}:  # noisy
            continue
        bates = f"{prefix}{m.group('num')}"
        if bates in seen:
            continue
        seen.add(bates)
        out.append(bates)
    return out


# --------------------------------------------------------------------------- #
# Misc                                                                        #
# --------------------------------------------------------------------------- #

_PHONE_RE = re.compile(
    r"\b(?:\+?1[-.\s]?)?\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b"
)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
_BAR_NUM_RE = re.compile(
    r"\b(?:WI|MN|IL)\s*Bar(?:\s*No\.?|\s*Number)?\s*[:#]?\s*(\d{6,8})\b",
    re.IGNORECASE,
)
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def find_phones(text: str) -> list[str]:
    return [f"({a}) {b}-{c}" for a, b, c in _PHONE_RE.findall(text)]


def find_emails(text: str) -> list[str]:
    return list({m.group(0) for m in _EMAIL_RE.finditer(text)})


def find_bar_numbers(text: str) -> list[str]:
    return [m.group(1) for m in _BAR_NUM_RE.finditer(text)]


def has_ssn(text: str) -> bool:
    return bool(_SSN_RE.search(text))


# --------------------------------------------------------------------------- #
# Aggregator                                                                  #
# --------------------------------------------------------------------------- #

def extract_all(text: str) -> dict:
    """Run every extractor; return a dict matching RichFindings field names."""
    return {
        "case_numbers": find_case_numbers(text),
        "statutes": find_statutes(text),
        "case_law": find_case_law(text),
        "dates": find_dates(text),
        "monetary_amounts": find_monetary(text),
        "bates": find_bates(text),
        "phones": find_phones(text),
        "emails": find_emails(text),
        "bar_numbers": find_bar_numbers(text),
        "has_ssn": has_ssn(text),
    }


# --------------------------------------------------------------------------- #
# helpers                                                                     #
# --------------------------------------------------------------------------- #

def _quote_around(text: str, start: int, end: int, pad: int = 50) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    snip = text[a:b].replace("\n", " ").strip()
    return snip[:200]


__all__ = [
    "extract_all",
    "find_case_numbers", "find_statutes", "find_case_law",
    "find_dates", "find_monetary", "find_bates",
    "find_phones", "find_emails", "find_bar_numbers", "has_ssn",
]
