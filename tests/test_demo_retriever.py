"""Tests for the `vulnerable_retriever_rag` / `defended_retriever_rag` demo
pair (`raginject.demo`), driven through `Runner` end to end against the
built-in `retriever` pattern set - the same shape as
`test_default_patterns.py`'s checks on `vulnerable_rag`/`defended_rag`, just
for the retriever set instead of the default corpus."""

from raginject.adapters.function import FunctionTarget
from raginject.attacks.loader import load_pattern_set
from raginject.core import Runner
from raginject.demo import (
    _BENIGN_CORPUS,
    _rank_bm25_filtered,
    _rank_by_term_frequency,
    defended_retriever_rag,
    demo_corpus_injector,
    vulnerable_retriever_rag,
)


def _run(target_fn):
    target = FunctionTarget(target_fn)
    runner = Runner(target, corpus_injector=demo_corpus_injector)
    runner.add_patterns(load_pattern_set("retriever"))
    return runner.run()


def test_vulnerable_retriever_rag_scores_zero_against_retriever_set():
    result = _run(vulnerable_retriever_rag)

    not_leaked = [o.pattern_id for o in result.outcomes if o.status != "leaked"]
    assert not not_leaked, (
        f"vulnerable_retriever_rag did not leak against: {not_leaked} "
        f"(expected every retriever-set pattern to hijack the top-k)"
    )
    assert result.score == 0.0
    assert result.has_scoreable_outcomes


def test_defended_retriever_rag_scores_one_against_retriever_set():
    result = _run(defended_retriever_rag)

    not_blocked = [o.pattern_id for o in result.outcomes if o.status != "blocked"]
    assert not not_blocked, (
        f"defended_retriever_rag did not block: {not_blocked} "
        f"(expected the stuffing/priority-claim filters plus BM25 ranking "
        f"to keep every retriever-set payload out of the top-k)"
    )
    assert result.score == 1.0
    assert result.has_scoreable_outcomes


def test_defended_retriever_rag_still_surfaces_a_real_benign_document():
    """The defended demo must not hit 1.00 by simply retrieving nothing -
    when nothing is injected, at least one of the retriever set's questions
    must still surface the benign document that actually answers it."""
    expected_top_doc = {
        "retriever-poisoning-001": "hr-expenses",
        "retriever-poisoning-002": "hr-vacation",
        "retriever-poisoning-003": "hr-onboarding",
        "retriever-poisoning-004": "fin-po",
        "retriever-poisoning-005": "hr-travel",
        "retriever-poisoning-006": "hr-payroll",
        "retriever-poisoning-007": "cs-escalation",
    }
    patterns = load_pattern_set("retriever")
    assert set(expected_top_doc) == {p.id for p in patterns}

    any_correct = False
    for pattern in patterns:
        result = defended_retriever_rag(pattern.question)
        if expected_top_doc[pattern.id] in result["sources"]:
            any_correct = True
    assert any_correct, (
        "defended_retriever_rag never surfaced the correct benign document "
        "for any question with nothing injected - it may be achieving its "
        "1.00 score by filtering everything out rather than by actually "
        "ranking correctly"
    )


def test_retrieve_ranked_returns_at_most_k_documents():
    """`_BENIGN_CORPUS` alone already has 7 documents, more than the
    default k=3 - `retrieve_ranked` must cap at k regardless of how many
    documents are in the combined corpus."""
    assert len(_BENIGN_CORPUS) > 3

    for rank_ids in (_rank_by_term_frequency, _rank_bm25_filtered):
        retrieved = demo_corpus_injector.retrieve_ranked(
            "What is the company's policy on expense reimbursement?", rank_ids
        )
        assert len(retrieved) <= 3
