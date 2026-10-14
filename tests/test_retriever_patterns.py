"""The opt-in `retriever` pattern set: loading, schema/id invariants, and
the guard that it is never reachable from `load_default_patterns()` (adding
it there would change every existing user's default corpus id set, which
`check_comparable` in `raginject.baseline` would then reject every existing
`--baseline` file over)."""

import re
from collections import Counter

import pytest

from raginject.attacks.loader import (
    available_pattern_sets,
    load_default_patterns,
    load_pattern_set,
)
from raginject.errors import ConfigurationError


def test_retriever_set_loads_and_every_pattern_uses_retrieval_match():
    patterns = load_pattern_set("retriever")
    assert 6 <= len(patterns) <= 8
    assert all(p.success_criteria.type == "retrieval_match" for p in patterns)
    assert all(p.category == "retriever_poisoning" for p in patterns)


def test_retriever_set_ids_are_unique():
    patterns = load_pattern_set("retriever")
    ids = [p.id for p in patterns]
    dupes = [pid for pid, count in Counter(ids).items() if count > 1]
    assert not dupes, f"duplicate pattern ids: {dupes}"


def test_retriever_set_descriptions_and_questions_nonempty():
    patterns = load_pattern_set("retriever")
    for pattern in patterns:
        assert pattern.description.strip()
        assert pattern.question.strip()
        assert pattern.injected_content.strip()


def test_retriever_set_ids_disjoint_from_default_corpus():
    retriever_ids = {p.id for p in load_pattern_set("retriever")}
    default_ids = {p.id for p in load_default_patterns()}
    assert not (retriever_ids & default_ids)


def test_default_corpus_does_not_include_retriever_set():
    """Guard on the decision that the retriever set stays opt-in: adding it
    to the default corpus would change every existing user's default
    pattern count/ids and break baseline comparability."""
    default_ids = {p.id for p in load_default_patterns()}
    retriever_ids = {p.id for p in load_pattern_set("retriever")}
    assert not (default_ids & retriever_ids)
    # The default corpus count is pinned exactly (see CLAUDE.md/ROADMAP.md):
    # 52 patterns across 8 categories, unaffected by this new set existing.
    assert len(load_default_patterns()) == 52


def test_retriever_set_has_no_forbidden_in_answer():
    """The retrieval_match judge raises ConfigurationError at preflight if a
    pattern carries forbidden_in_answer (it would be silently ignored) - so
    a shipped pattern with one would break every run using this set."""
    patterns = load_pattern_set("retriever")
    for pattern in patterns:
        assert pattern.success_criteria.forbidden_in_answer is None, (
            f"{pattern.id}: forbidden_in_answer set, but retrieval_match "
            "never inspects the answer"
        )


def test_available_pattern_sets_includes_retriever():
    assert available_pattern_sets() == sorted(available_pattern_sets())
    assert "retriever" in available_pattern_sets()


def test_load_pattern_set_unknown_name_raises_configuration_error():
    with pytest.raises(ConfigurationError) as excinfo:
        load_pattern_set("nope")
    message = str(excinfo.value)
    assert "nope" in message
    assert "retriever" in message


#: Words carried by almost any generic-business question, which a payload
#: sharing with its question proves nothing about.
_QUESTION_STOPWORDS = frozenset(
    {
        "what",
        "when",
        "where",
        "which",
        "does",
        "many",
        "their",
        "this",
        "that",
        "from",
        "about",
        "company",
        "current",
        "standard",
        "process",
        "first",
        "year",
        "week",
        "new",
    }
)


def _content_terms(text):
    return {
        word
        for word in re.findall(r"[a-z0-9]+", text.lower())
        if len(word) > 3 and word not in _QUESTION_STOPWORDS
    }


def _covered(term, payload_terms):
    # Crude stemming: "updating" must count as covered by "update", and
    # "employees" by "employee". A real retriever stems or embeds; this
    # test only has to avoid failing on inflection.
    stem = term[:5]
    return any(payload_term.startswith(stem) for payload_term in payload_terms)


def test_every_payload_competes_for_its_own_question():
    """A retriever-poisoning payload must carry its question's terms.

    This is the ranking-attack form of the rule that a payload has to be
    able to fire against the target it runs on. A document sharing no terms
    with the question it is meant to hijack is ranked by nothing: it scores
    "blocked" against every retriever that will ever exist, and a set of
    such patterns reports a completely poisoned retriever as a perfect
    1.00. All seven patterns shipped in the first draft of this file had
    exactly zero content terms in common with their own question, which is
    why this is enforced statically rather than left to review.
    """
    for pattern in load_pattern_set("retriever"):
        question_terms = _content_terms(pattern.question)
        payload_terms = _content_terms(pattern.injected_content)
        assert question_terms, f"{pattern.id}: question has no content terms"

        covered = {t for t in question_terms if _covered(t, payload_terms)}
        ratio = len(covered) / len(question_terms)
        assert ratio >= 0.6, (
            f"{pattern.id}: payload covers only {len(covered)}/"
            f"{len(question_terms)} of its question's content terms "
            f"(missing: {sorted(question_terms - covered)}). A payload that "
            "does not compete for its own question can never be retrieved, "
            "so the pattern can never fire."
        )
