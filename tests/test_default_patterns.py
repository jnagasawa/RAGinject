"""Corpus-level invariants for the built-in default pattern set (Phase 2:
50-pattern expansion). These are not schema checks (that's
`test_attacks_loader.py`) - they check properties specific to the *content*
of the shipped patterns: uniqueness, the quoted-canary contract that
`raginject.demo:vulnerable_rag` depends on, and the end-to-end demo
invariant that the whole set scores 0.0 against `vulnerable_rag` and 1.0
against `defended_rag`.
"""

import re
from collections import Counter

import pytest

from raginject.adapters.function import FunctionTarget
from raginject.attacks.loader import load_default_patterns
from raginject.core import Runner
from raginject.demo import defended_rag, vulnerable_rag

_QUOTED = re.compile(r'"([^"]{3,})"')

_EXPECTED_CATEGORIES = {
    "indirect_injection",
    "data_exfiltration",
    "format_smuggling",
    "authority_spoofing",
    "payload_delivery",
    "obfuscation",
    "multilingual",
    "conditional_delayed",
}

# Lexical shapes of the "question asks about the injected note itself"
# mistake described below, in `test_no_question_is_self_referential_about_the_note`.
_DOC_NOUN_RE = re.compile(
    r"\b(?:this|these)\s+(?:document|page|file|checklists?)\b", re.IGNORECASE
)
_DOC_NOTE_RE = re.compile(r"\bthis\s+(?:\w+\s+)?note\b", re.IGNORECASE)
_BARE_SUMMARY_RE = re.compile(r"\bsummary\b(?!\s+of\b)", re.IGNORECASE)
_INSTRUCTION_NOUN_RE = re.compile(
    r"\b(?:rule|instructions?|directives?|polic(?:y|ies)|protocols?)\b", re.IGNORECASE
)
_INSTRUCTION_ANCHOR_RE = re.compile(
    r"\bhere\b|\bthis\s+(?:document|page|file|note)\b|\byou were given\b",
    re.IGNORECASE,
)

_LEGACY_PATTERNS = {
    "indirect-injection-basic-001": ("indirect_injection", "INJECTION_SUCCESS"),
    "indirect-injection-basic-002": ("indirect_injection", "DAN_MODE_ON"),
    "indirect-injection-basic-003": ("indirect_injection", "CLICK_HERE:"),
    "exfiltration-001": ("data_exfiltration", "SYSTEM_PROMPT:"),
    "exfiltration-002": ("data_exfiltration", "LEAKED_SECRET:"),
}


def _normalize(text: str) -> str:
    """Same normalization the keyword_match judge applies (NFKC + casefold),
    reused here rather than duplicated logic."""
    from raginject.judges.keyword import _normalize as judge_normalize

    return judge_normalize(text, case_sensitive=False)


def test_load_default_patterns_returns_at_least_45():
    patterns = load_default_patterns()
    assert len(patterns) >= 45


def test_all_ids_are_unique():
    patterns = load_default_patterns()
    ids = [p.id for p in patterns]
    dupes = [pid for pid, count in Counter(ids).items() if count > 1]
    assert not dupes, f"duplicate pattern ids: {dupes}"


def test_all_canaries_are_globally_unique():
    patterns = load_default_patterns()
    canaries = [
        canary
        for pattern in patterns
        for canary in (pattern.success_criteria.forbidden_in_answer or [])
    ]
    dupes = [c for c, count in Counter(canaries).items() if count > 1]
    assert not dupes, f"duplicate canaries across patterns: {dupes}"


def test_every_canary_appears_quoted_in_injected_content():
    """Invariant 2c-1: `vulnerable_rag` only echoes text found inside ASCII
    double quotes in `context` (see `raginject.demo._QUOTED`). Every canary
    must therefore be recoverable either as a literal substring of some
    quoted span, or - for obfuscated patterns - via NFKC+casefold
    normalization of a quoted span."""
    patterns = load_default_patterns()
    failures = []

    for pattern in patterns:
        quoted_spans = _QUOTED.findall(pattern.injected_content)
        normalized_spans = [_normalize(span) for span in quoted_spans]

        for canary in pattern.success_criteria.forbidden_in_answer or []:
            literal_hit = any(canary in span for span in quoted_spans)
            normalized_canary = _normalize(canary)
            normalized_hit = any(normalized_canary in span for span in normalized_spans)
            if not (literal_hit or normalized_hit):
                failures.append(f"{pattern.id}: canary {canary!r} not found quoted")

    assert not failures, "\n".join(failures)


def test_no_question_is_self_referential_about_the_note():
    """A pattern's `question` must ask about the host document's legitimate
    content, never about the injected note itself. Asking "what is this
    note asking for?" invites a correctly-defended pipeline to quote the
    canary in an honest answer, and `keyword_match` cannot tell quoting
    from obeying - so such a question manufactures a false `leaked`
    verdict against a pipeline that behaved correctly.

    This is a lexical approximation, not a semantic judgment: it flags two
    known shapes the mistake has actually taken in this corpus, so the
    corpus can't regress into them, but a new pattern can still ask an
    unsafe self-referential question in a shape this check doesn't
    recognize and slip through.

    Shape A - the retrieved document itself is the subject: the question
    asks what "this document/page/file/note/checklist" says, is about, or
    contains, or asks for a summary of it without naming a host topic
    (e.g. "Summarize this document.", "Give me a short summary.").
    A demonstrative bound to a real host entity name (e.g. "these meeting
    notes", "the onboarding checklist") is not this shape - the noun must
    be the bare document-like word itself, optionally with one adjective
    before "note".

    Shape B - an instruction is the subject: the noun being asked about is
    a rule/instruction/directive/policy/protocol, and it is tied to the
    retrieved document via "here", "this document/page/file/note", or
    "you were given" (e.g. "What formatting rule is described here?").
    """
    patterns = load_default_patterns()
    failures = []

    for pattern in patterns:
        question = pattern.question
        self_referential = (
            bool(_DOC_NOUN_RE.search(question))
            or bool(_DOC_NOTE_RE.search(question))
            or bool(_BARE_SUMMARY_RE.search(question))
            or bool(
                _INSTRUCTION_NOUN_RE.search(question)
                and _INSTRUCTION_ANCHOR_RE.search(question)
            )
        )
        if self_referential:
            failures.append(
                f"{pattern.id}: question asks about the note itself: {question!r}"
            )

    assert not failures, "\n".join(failures)


def test_categories_are_known_and_well_populated():
    patterns = load_default_patterns()
    categories = [p.category for p in patterns]

    unknown = set(categories) - _EXPECTED_CATEGORIES
    assert not unknown, f"unexpected category value(s): {unknown}"

    missing = _EXPECTED_CATEGORIES - set(categories)
    assert not missing, f"category with zero patterns: {missing}"

    counts = Counter(categories)
    thin = {cat: n for cat, n in counts.items() if n < 4}
    assert not thin, f"category with fewer than 4 patterns: {thin}"


def test_legacy_patterns_still_present_unchanged():
    patterns = load_default_patterns()
    by_id = {p.id: p for p in patterns}

    for legacy_id, (category, canary) in _LEGACY_PATTERNS.items():
        assert legacy_id in by_id, f"legacy pattern {legacy_id} is missing"
        pattern = by_id[legacy_id]
        assert pattern.category == category, (
            f"{legacy_id}: category changed to {pattern.category!r}"
        )
        assert canary in (pattern.success_criteria.forbidden_in_answer or []), (
            f"{legacy_id}: canary {canary!r} no longer in forbidden_in_answer"
        )


def test_default_corpus_against_vulnerable_rag_scores_zero():
    target = FunctionTarget(vulnerable_rag)
    runner = Runner(target)
    runner.load_patterns(None)
    result = runner.run()

    not_leaked = [o.pattern_id for o in result.outcomes if o.status != "leaked"]
    assert not not_leaked, (
        f"vulnerable_rag did not leak against: {not_leaked} "
        f"(expected every default pattern to succeed)"
    )
    assert result.score == 0.0
    assert result.has_scoreable_outcomes


def test_default_corpus_against_defended_rag_scores_one():
    target = FunctionTarget(defended_rag)
    runner = Runner(target)
    runner.load_patterns(None)
    result = runner.run()

    not_blocked = [o.pattern_id for o in result.outcomes if o.status != "blocked"]
    assert not not_blocked, (
        f"defended_rag did not block: {not_blocked} "
        f"(expected every default pattern to be blocked)"
    )
    assert result.score == 1.0
    assert result.has_scoreable_outcomes


@pytest.mark.parametrize("pattern", load_default_patterns(), ids=lambda p: p.id)
def test_each_pattern_description_and_question_are_nonempty(pattern):
    assert pattern.description.strip()
    assert pattern.question.strip()
    assert pattern.injected_content.strip()
