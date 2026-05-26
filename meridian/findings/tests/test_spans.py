"""Tests for source-span propagation in Findings claims."""

from __future__ import annotations

from meridian.findings._base import claim, is_spans_aware
from meridian.findings._spans import (
    attach_spans_to_claim,
    claim_spans,
    format_span_gap,
    parse_span_gap,
)


# --- format_span_gap / parse_span_gap roundtrip -------------------------

def test_format_single_span():
    assert format_span_gap([(12, 45)]) == "source_span:char[12-45]"


def test_format_multiple_spans():
    assert format_span_gap([(12, 45), (67, 89)]) == "source_span:char[12-45,67-89]"


def test_format_empty_returns_empty_string():
    assert format_span_gap([]) == ""


def test_parse_round_trip():
    spans = [(0, 10), (20, 30), (100, 200)]
    assert parse_span_gap(format_span_gap(spans)) == spans


def test_parse_returns_empty_for_non_span_gap():
    assert parse_span_gap("DKIM/SPF authentication not verified by this layer") == []


def test_parse_handles_whitespace():
    assert parse_span_gap("  source_span:char[1-2]  ") == [(1, 2)]


# --- attach_spans_to_claim + claim_spans --------------------------------

def test_attach_appends_to_existing_gaps():
    c = {"gaps": ["existing gap"]}
    attach_spans_to_claim(c, [(1, 2), (5, 10)])
    assert c["gaps"] == ["existing gap", "source_span:char[1-2,5-10]"]


def test_attach_creates_gaps_when_absent():
    c: dict = {}
    attach_spans_to_claim(c, [(0, 5)])
    assert c["gaps"] == ["source_span:char[0-5]"]


def test_attach_noop_when_no_spans():
    c = {"gaps": ["existing"]}
    attach_spans_to_claim(c, [])
    assert c["gaps"] == ["existing"]


def test_claim_spans_collects_across_gap_entries():
    c = {"gaps": ["unrelated", "source_span:char[1-2]", "source_span:char[5-10,20-30]"]}
    assert claim_spans(c) == [(1, 2), (5, 10), (20, 30)]


# --- claim() builder integration ---------------------------------------

def test_claim_builder_appends_span_gap():
    c = claim(
        "Sender is alice@example.com",
        inference_type="deduction",
        supports=["obs-1"],
        gaps=["pre-existing"],
        source_spans=[(12, 31)],
    )
    assert c["gaps"][0] == "pre-existing"
    assert c["gaps"][-1] == "source_span:char[12-31]"


def test_claim_builder_observation_with_no_gaps_still_gets_span():
    c = claim(
        "Observation",
        inference_type="observation",
        supports=["obs-1"],
        source_spans=[(0, 5)],
    )
    assert c["gaps"] == ["source_span:char[0-5]"]


def test_claim_builder_legacy_no_spans_unchanged():
    c = claim(
        "x",
        inference_type="observation",
        supports=["obs-1"],
    )
    assert c["gaps"] == []


# --- is_spans_aware runtime check --------------------------------------

class _LegacyAdapter:
    name = "legacy"

    def complete_json(self, prompt, schema_model, **kwargs):
        raise NotImplementedError


class _SpansAwareAdapter:
    name = "spans-aware"

    def complete_json(self, prompt, schema_model, **kwargs):
        raise NotImplementedError

    def complete_json_with_spans(self, prompt, schema_model, source_text, **kwargs):
        raise NotImplementedError


def test_is_spans_aware_true_for_spans_aware():
    assert is_spans_aware(_SpansAwareAdapter()) is True


def test_is_spans_aware_false_for_legacy():
    assert is_spans_aware(_LegacyAdapter()) is False
