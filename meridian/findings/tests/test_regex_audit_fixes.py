"""AUDIT-FIX regression tests for regex_extract silent-loss / mis-parse defects.

Covers:
  - bare WI statute forms (`ch. 48`, `§ 48.415(2)`, `section 48.415`)
  - case-law `Wis. 2d` ordinal-suffix page mis-parse
  - find_phones de-duplication
"""

from __future__ import annotations

from meridian.findings.regex_extract import (
    find_statutes,
    find_case_law,
    find_phones,
    find_emails,
)


# --------------------------------------------------------------------------- #
# Statutes: dominant bare WI forms in TPR/DHS docs                            #
# --------------------------------------------------------------------------- #

def test_bare_chapter_form_matched():
    """`ch. 48` — the dominant CHIPS/TPR shorthand — must be extracted."""
    stats = find_statutes("The petition was filed under ch. 48 of the statutes.")
    canon = {s.canonical for s in stats}
    assert "wis.stat.48" in canon
    s = next(s for s in stats if s.canonical == "wis.stat.48")
    assert s.title == "48"
    assert s.section is None
    assert 0.0 < s.confidence < 0.95  # bare → moderate, below prefixed


def test_bare_section_form_with_subsection():
    """`§ 48.415(2)` — bare section with subsection — must parse fully."""
    stats = find_statutes("Grounds for termination exist under § 48.415(2).")
    s = next(s for s in stats if s.canonical == "wis.stat.48.415.2")
    assert s.title == "48"
    assert s.section == "415"
    assert s.subsection == "2"
    assert s.confidence < 0.95


def test_bare_section_word_form():
    """`section 48.415` spelled out must parse."""
    stats = find_statutes("See section 48.415 for the grounds.")
    canon = {s.canonical for s in stats}
    assert "wis.stat.48.415" in canon


def test_realistic_chips_string():
    """Real WI-CHIPS-style sentence with multiple bare forms."""
    text = (
        "Pursuant to ch. 48 and § 48.415(2), and consistent with the "
        "reasonable-efforts requirement of section 48.426, the Department "
        "petitions for termination."
    )
    canon = {s.canonical for s in find_statutes(text)}
    assert "wis.stat.48" in canon
    assert "wis.stat.48.415.2" in canon
    assert "wis.stat.48.426" in canon


def test_prefixed_form_higher_confidence_and_not_double_counted():
    """`Wis. Stat. § 48.415(2)` parses once at high confidence even though the
    bare `§ 48.415(2)` substring also matches."""
    stats = find_statutes("Wis. Stat. § 48.415(2) governs.")
    matches = [s for s in stats if s.canonical == "wis.stat.48.415.2"]
    assert len(matches) == 1  # deduped, not double-counted
    assert matches[0].confidence == 0.95


# --------------------------------------------------------------------------- #
# Case law: ordinal-suffix reporter page mis-parse                            #
# --------------------------------------------------------------------------- #

def test_wis_2d_page_not_corrupted():
    """`123 Wis. 2d 456` → page=456, NOT 2 (the ordinal)."""
    cites = find_case_law("See Smith v. Jones, 123 Wis. 2d 456 (2019).")
    assert cites
    c = cites[0]
    assert c.volume == 123
    assert c.page == 456, f"page corrupted: got {c.page}"
    assert c.year == 2019
    assert c.confidence == 0.85


def test_n_w_2d_reporter():
    """`N.W.2d` style reporters also parse the page correctly."""
    cites = find_case_law("State v. Roe, 900 N.W. 2d 100 (Wis. 2018).")
    c = cites[0]
    assert c.page == 100


def test_bare_case_name_low_confidence():
    """A bare `X v. Y` with no reporter still matches but at low confidence."""
    cites = find_case_law("As held in Brown v. Board, the rule applies.")
    assert cites
    assert cites[0].confidence == 0.5


# --------------------------------------------------------------------------- #
# Phones: de-duplication parity with emails                                   #
# --------------------------------------------------------------------------- #

def test_find_phones_dedups():
    text = "Call (612) 555-1212 or 612-555-1212 or (612) 555-9999."
    phones = find_phones(text)
    assert phones.count("(612) 555-1212") == 1
    assert "(612) 555-9999" in phones
    assert len(phones) == len(set(phones))


def test_find_phones_matches_email_dedup_behavior():
    """Both find_phones and find_emails return de-duplicated lists."""
    assert find_phones("(612) 555-1212 (612) 555-1212") == ["(612) 555-1212"]
    assert find_emails("a@b.com a@b.com") == ["a@b.com"]
