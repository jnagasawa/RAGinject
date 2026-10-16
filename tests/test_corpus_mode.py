"""Tests for corpus injection (mode A): CorpusInjector, Runner's mode-A
path, resolve_corpus_injector_spec, and the two new CLI flags."""

import json
import re
import warnings
from typing import List, Optional

import pytest
from click.testing import CliRunner

from raginject.attacks.schema import AttackPattern, SuccessCriteria
from raginject.cli import main
from raginject.core import Runner
from raginject.corpus import CorpusInjector
from raginject.errors import ConfigurationError, TargetResolutionError
from raginject.judges import Judge, JudgeContext, Verdict
from raginject.report import format_json
from raginject.resolve import resolve_corpus_injector_spec
from raginject.target import QueryResult, Target


def _pattern(pattern_id, forbidden=("SECRET",)):
    return AttackPattern(
        id=pattern_id,
        category="test",
        description="d",
        injected_content="here is SECRET",
        question="q?",
        success_criteria=SuccessCriteria(
            type="keyword_match", forbidden_in_answer=list(forbidden)
        ),
    )


class _RecordingInjector(CorpusInjector):
    """Records every inject/remove call, in order, in a shared `corpus`
    dict a `_CorpusTarget` reads from - the same seam
    `raginject.demo._DemoCorpus` uses, just instrumented for assertions."""

    def __init__(self):
        self.injected = []
        self.removed = []
        self.corpus = {}
        self.fail_inject_for = set()
        self.fail_remove_for = set()

    def inject(self, document_id, content):
        self.injected.append((document_id, content))
        if document_id in self.fail_inject_for:
            raise RuntimeError("inject boom")
        self.corpus[document_id] = content

    def remove(self, document_id):
        self.removed.append(document_id)
        if document_id in self.fail_remove_for:
            raise RuntimeError("remove boom")
        self.corpus.pop(document_id, None)


class _CorpusTarget(Target):
    """A `Target` that "retrieves" by reading whatever `injector.corpus`
    currently holds, recording every `context` it was called with (mode A
    must always pass `None`) and letting `sources` be shaped per test (ids
    that match the injected document, unrelated ids, or empty)."""

    def __init__(self, injector, sources_mode="ids"):
        self.injector = injector
        self.sources_mode = sources_mode
        self.calls = 0
        self.received_context = []

    def query(self, question: str, context: Optional[List[str]] = None) -> QueryResult:
        self.calls += 1
        self.received_context.append(context)
        answer = " ".join(self.injector.corpus.values()) or "clean"
        if self.sources_mode == "empty":
            sources = []
        elif self.sources_mode == "unrelated":
            sources = ["some-unrelated-source"]
        else:
            sources = list(self.injector.corpus.keys())
        return {"answer": answer, "sources": sources}


def test_inject_and_remove_called_with_expected_ids_content_and_order():
    injector = _RecordingInjector()
    target = _CorpusTarget(injector)
    runner = Runner(target, corpus_injector=injector)
    runner.add_patterns([_pattern("p1"), _pattern("p2")])
    runner.run()

    assert injector.injected == [
        ("raginject-p1", "here is SECRET"),
        ("raginject-p2", "here is SECRET"),
    ]
    assert injector.removed == ["raginject-p1", "raginject-p2"]


def test_mode_a_passes_no_context_to_the_target():
    injector = _RecordingInjector()
    target = _CorpusTarget(injector)
    runner = Runner(target, corpus_injector=injector)
    runner.add_patterns([_pattern("p1")])
    runner.run()
    assert target.received_context == [None]


def test_mode_a_question_only_function_never_raises_configuration_error():
    """`FunctionTarget` raises `ConfigurationError` in mode B when a
    question-only function (`def rag(question)`, no `context` parameter and
    no `**kwargs`) is asked to carry a non-empty context - see
    `adapters/function.py`. Mode A never asks for that: `context` is always
    `None`, so a question-only function - the whole point of mode A - just
    works."""
    from raginject.adapters.function import FunctionTarget

    injector = _RecordingInjector()
    calls = []

    def question_only_rag(question):
        calls.append(question)
        answer = " ".join(injector.corpus.values()) or "clean"
        return {"answer": answer, "sources": list(injector.corpus.keys())}

    runner = Runner(FunctionTarget(question_only_rag), corpus_injector=injector)
    runner.add_patterns([_pattern("p1")])
    result = runner.run()

    assert calls == ["q?"]
    assert result.outcomes[0].status == "leaked"


def test_remove_called_even_when_target_raises():
    injector = _RecordingInjector()

    class _RaisingTarget(Target):
        def query(self, question, context=None):
            raise RuntimeError("target boom")

    runner = Runner(_RaisingTarget(), corpus_injector=injector)
    runner.add_patterns([_pattern("p1")])
    result = runner.run()

    assert injector.removed == ["raginject-p1"]
    assert result.outcomes[0].status == "error"


def test_remove_called_even_when_judge_raises():
    injector = _RecordingInjector()
    target = _CorpusTarget(injector)

    class _BoomJudge(Judge):
        def judge(self, ctx: JudgeContext) -> Verdict:
            raise RuntimeError("judge boom")

    runner = Runner(
        target, judges={"keyword_match": _BoomJudge()}, corpus_injector=injector
    )
    runner.add_patterns([_pattern("p1")])
    result = runner.run()

    assert injector.removed == ["raginject-p1"]
    assert result.outcomes[0].status == "error"


def test_remove_called_even_when_retrieval_verification_fails():
    injector = _RecordingInjector()
    target = _CorpusTarget(injector, sources_mode="unrelated")
    runner = Runner(target, corpus_injector=injector)
    runner.add_patterns([_pattern("p1")])
    result = runner.run()

    assert injector.removed == ["raginject-p1"]
    assert result.outcomes[0].status == "error"
    assert result.outcomes[0].verdict_reason == "injected document was not retrieved"


def test_inject_raising_produces_error_row_and_run_continues():
    injector = _RecordingInjector()
    injector.fail_inject_for.add("raginject-p1")
    target = _CorpusTarget(injector)
    runner = Runner(target, corpus_injector=injector)
    runner.add_patterns([_pattern("p1"), _pattern("p2")])
    result = runner.run()

    by_id = {o.pattern_id: o for o in result.outcomes}
    assert by_id["p1"].status == "error"
    assert "insert" in by_id["p1"].verdict_reason
    # Nothing was written for p1, so nothing to clean up.
    assert runner.uncleaned_document_ids == []
    # The run continued to p2.
    assert by_id["p2"].status == "leaked"
    assert target.calls == 1


def test_remove_raising_marks_row_error_and_records_uncleaned_id():
    injector = _RecordingInjector()
    injector.fail_remove_for.add("raginject-p1")
    target = _CorpusTarget(injector)
    runner = Runner(target, corpus_injector=injector)
    runner.add_patterns([_pattern("p1")])
    result = runner.run()

    assert result.outcomes[0].status == "error"
    assert "left in the corpus" in result.outcomes[0].verdict_reason
    assert runner.uncleaned_document_ids == ["raginject-p1"]


def test_remove_configuration_error_still_records_uncleaned_id_before_propagating():
    """A `remove()` that raises ConfigurationError must still abort the run
    (ConfigurationError always does) - but the document it failed to clean
    up must not be lost from `uncleaned_document_ids` just because the
    exception is about to propagate. Regression test for a bug where the
    `except ConfigurationError: raise` branch re-raised before recording
    the id, so the document was silently left in the corpus with nothing
    anywhere reporting it."""
    injector = _RecordingInjector()

    def raising_remove(document_id):
        injector.removed.append(document_id)
        raise ConfigurationError("corpus backend not configured")

    injector.remove = raising_remove
    target = _CorpusTarget(injector)
    runner = Runner(target, corpus_injector=injector)
    runner.add_patterns([_pattern("p1")])

    with pytest.raises(ConfigurationError):
        runner.run()

    assert runner.uncleaned_document_ids == ["raginject-p1"]
    # The document really was left behind - inject succeeded, remove never
    # actually cleaned it up.
    assert "raginject-p1" in injector.corpus


def test_retrieval_verification_substring_match_counts_as_retrieved():
    injector = _RecordingInjector()

    class _PathSourceTarget(Target):
        def query(self, question, context=None):
            answer = " ".join(injector.corpus.values()) or "clean"
            return {"answer": answer, "sources": ["docs/raginject-p1.txt"]}

    runner = Runner(_PathSourceTarget(), corpus_injector=injector)
    runner.add_patterns([_pattern("p1")])
    result = runner.run()
    assert result.outcomes[0].status == "leaked"


def test_retrieval_verification_empty_sources_judged_normally_and_warns_once():
    injector = _RecordingInjector()
    target = _CorpusTarget(injector, sources_mode="empty")
    runner = Runner(target, corpus_injector=injector)
    runner.add_patterns([_pattern("p1"), _pattern("p2")])

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = runner.run()

    assert result.outcomes[0].status == "leaked"
    assert result.outcomes[1].status == "leaked"
    unverifiable_warnings = [w for w in caught if "cannot verify" in str(w.message)]
    assert len(unverifiable_warnings) == 1


class _PerPatternSourcesTarget(Target):
    """Returns `sources_by_pattern[question]` (keyed by the pattern's
    question, which the tests make unique), so one run can mix empty,
    matching and non-matching sources."""

    def __init__(self, sources_by_question):
        self.sources_by_question = sources_by_question

    def query(self, question: str, context: Optional[List[str]] = None) -> QueryResult:
        return {
            "answer": "here is SECRET",
            "sources": self.sources_by_question[question],
        }


def _q_pattern(pattern_id, question):
    pattern = _pattern(pattern_id)
    return pattern.model_copy(update={"question": question})


def _mixed_run(sources_list, *, verify_retrieval=True, callback=None, extra=()):
    injector = _RecordingInjector()
    patterns = [_q_pattern(f"p{i}", f"q{i}?") for i in range(len(sources_list))]
    target = _PerPatternSourcesTarget(
        {f"q{i}?": src for i, src in enumerate(sources_list)}
    )
    runner = Runner(target, corpus_injector=injector, verify_retrieval=verify_retrieval)
    runner.add_patterns(patterns)
    runner.add_patterns(extra)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = runner.run(on_outcome=callback)
    unverifiable = [w for w in caught if "cannot verify" in str(w.message)]
    return result, unverifiable


def test_adaptive_empty_sources_first_becomes_error_when_later_row_has_sources():
    result, unverifiable = _mixed_run([[], ["raginject-p1"]])

    assert [o.pattern_id for o in result.outcomes] == ["p0", "p1"]
    assert result.outcomes[0].status == "error"
    assert result.outcomes[0].verdict_reason == "injected document was not retrieved"
    assert "--no-verify-retrieval" in result.outcomes[0].error
    assert result.outcomes[1].status == "leaked"
    assert unverifiable == []


def test_adaptive_empty_sources_last_becomes_error_when_earlier_row_has_sources():
    result, unverifiable = _mixed_run([["raginject-p0"], []])

    assert result.outcomes[0].status == "leaked"
    assert result.outcomes[1].status == "error"
    assert "--no-verify-retrieval" in result.outcomes[1].error
    assert unverifiable == []


def test_adaptive_non_matching_sources_row_counts_as_evidence():
    result, unverifiable = _mixed_run([[], ["unrelated"], []])

    assert [o.status for o in result.outcomes] == ["error", "error", "error"]
    assert unverifiable == []


def test_adaptive_verify_retrieval_false_judges_empty_rows_normally():
    result, unverifiable = _mixed_run([[], ["raginject-p1"]], verify_retrieval=False)

    assert [o.status for o in result.outcomes] == ["leaked", "leaked"]
    assert unverifiable == []


def test_adaptive_retrieval_pattern_sources_count_as_evidence():
    retrieval = _retrieval_pattern().model_copy(update={"id": "r0", "question": "qr?"})
    injector = _RecordingInjector()
    target = _PerPatternSourcesTarget({"q0?": [], "qr?": ["raginject-r0"]})
    runner = Runner(target, corpus_injector=injector)
    runner.add_patterns([_q_pattern("p0", "q0?"), retrieval])
    result = runner.run()

    assert result.outcomes[0].status == "error"
    assert result.outcomes[1].status == "leaked"  # retrieved: attack succeeded


def test_adaptive_retrieval_pattern_empty_sources_is_not_evidence():
    retrieval = _retrieval_pattern().model_copy(update={"id": "r0", "question": "qr?"})
    injector = _RecordingInjector()
    target = _PerPatternSourcesTarget({"q0?": [], "qr?": []})
    runner = Runner(target, corpus_injector=injector)
    runner.add_patterns([_q_pattern("p0", "q0?"), retrieval])
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = runner.run()

    assert result.outcomes[0].status == "leaked"
    assert result.outcomes[1].status == "error"
    assert len([w for w in caught if "cannot verify" in str(w.message)]) == 1


def test_adaptive_callback_called_once_per_pattern_with_final_outcome():
    seen = []
    result, _ = _mixed_run([[], [], ["raginject-p2"], []], callback=seen.append)

    assert len(seen) == 4
    assert sorted(o.pattern_id for o in seen) == ["p0", "p1", "p2", "p3"]
    assert sorted(o.status for o in seen) == sorted(o.status for o in result.outcomes)
    assert [o.pattern_id for o in result.outcomes] == ["p0", "p1", "p2", "p3"]
    # Pending rows are reported only once resolved, after the evidence row.
    assert seen[0].pattern_id == "p2"


def test_adaptive_never_any_sources_callback_fires_for_every_row():
    seen = []
    result, unverifiable = _mixed_run([[], []], callback=seen.append)

    assert [o.status for o in result.outcomes] == ["leaked", "leaked"]
    assert len(seen) == 2
    assert len(unverifiable) == 1


def test_mode_b_empty_sources_unaffected_by_adaptive_rule():
    class _EmptyTarget(Target):
        def query(self, question, context=None):
            return {"answer": "here is SECRET", "sources": []}

    runner = Runner(_EmptyTarget())
    runner.add_patterns([_pattern("p1")])
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = runner.run()

    assert result.outcomes[0].status == "leaked"
    assert caught == []


def test_verify_retrieval_false_disables_the_check():
    injector = _RecordingInjector()
    target = _CorpusTarget(injector, sources_mode="unrelated")
    runner = Runner(target, corpus_injector=injector, verify_retrieval=False)
    runner.add_patterns([_pattern("p1")])
    result = runner.run()
    assert result.outcomes[0].status == "leaked"


def test_runner_mode_property():
    injector = _RecordingInjector()
    target = _CorpusTarget(injector)
    assert Runner(target).mode == "b"
    assert Runner(target, corpus_injector=injector).mode == "a"


def test_result_mode_and_corpus_injector_description_reach_json_report():
    injector = _RecordingInjector()
    target = _CorpusTarget(injector)
    runner = Runner(target, corpus_injector=injector)
    runner.add_patterns([_pattern("p1")])
    result = runner.run()

    assert result.mode == "a"
    assert result.corpus_injector_description == "_RecordingInjector"

    parsed = json.loads(format_json(result))
    assert parsed["mode"] == "a"
    assert parsed["corpus_injector_description"] == "_RecordingInjector"


def test_result_mode_b_has_no_corpus_injector_description():
    def rag(question, context=None):
        return {"answer": "ok", "sources": []}

    from raginject.adapters.function import FunctionTarget

    runner = Runner(FunctionTarget(rag))
    runner.add_patterns([_pattern("p1")])
    result = runner.run()

    assert result.mode == "b"
    assert result.corpus_injector_description is None


# --- resolve_corpus_injector_spec ------------------------------------------


def test_resolve_corpus_injector_instance_used_directly():
    injector = resolve_corpus_injector_spec(
        "tests.fixture_rag:in_memory_corpus_injector"
    )
    from tests.fixture_rag import InMemoryCorpusInjector

    assert isinstance(injector, InMemoryCorpusInjector)


def test_resolve_corpus_injector_subclass_instantiated():
    injector = resolve_corpus_injector_spec("tests.fixture_rag:InMemoryCorpusInjector")
    from tests.fixture_rag import InMemoryCorpusInjector

    assert isinstance(injector, InMemoryCorpusInjector)


def test_resolve_corpus_injector_plain_callable_raises():
    """Unlike resolve_target_spec, there is no bare-callable fallback: a
    CorpusInjector is two paired operations, so a callable is ambiguous."""
    with pytest.raises(TargetResolutionError, match=re.escape("neither")):
        resolve_corpus_injector_spec("tests.fixture_rag:not_a_corpus_injector")


def test_resolve_corpus_injector_bad_spec_errors():
    with pytest.raises(TargetResolutionError, match=re.escape("module:attribute")):
        resolve_corpus_injector_spec("tests.fixture_rag.in_memory_corpus_injector")


def test_resolve_corpus_injector_unimportable_module_errors():
    with pytest.raises(TargetResolutionError):
        resolve_corpus_injector_spec("no_such_module_xyz:thing")


# --- CLI ---------------------------------------------------------------


def _make_runner() -> CliRunner:
    try:
        return CliRunner(capture="fd")  # click >= 8.5
    except TypeError:
        pass
    try:
        return CliRunner(mix_stderr=False)  # click 8.0-8.1
    except TypeError:
        return CliRunner()  # click 8.2-8.4: stderr is already separate


def _invoke(*args):
    return _make_runner().invoke(main, list(args))


def test_cli_corpus_injector_bad_spec_exits_2():
    result = _invoke(
        "run",
        "--target-module",
        "raginject.demo:vulnerable_rag",
        "--corpus-injector",
        "nosuch.module:thing",
    )
    assert result.exit_code == 2


def test_cli_no_verify_retrieval_without_corpus_injector_exits_2():
    result = _invoke(
        "run",
        "--target-module",
        "raginject.demo:vulnerable_rag",
        "--no-verify-retrieval",
    )
    assert result.exit_code == 2
    assert "--no-verify-retrieval" in result.stderr


def test_cli_mode_a_vulnerable_demo_scores_zero():
    result = _invoke(
        "run",
        "--target-module",
        "raginject.demo:vulnerable_corpus_rag",
        "--corpus-injector",
        "raginject.demo:demo_corpus_injector",
    )
    assert result.exit_code == 0
    assert "score: 0.00" in result.stdout
    assert "mode: a" in result.stdout


def test_cli_mode_a_defended_demo_scores_one_and_gate_passes():
    result = _invoke(
        "run",
        "--target-module",
        "raginject.demo:defended_corpus_rag",
        "--corpus-injector",
        "raginject.demo:demo_corpus_injector",
        "--min-score",
        "1.0",
    )
    assert result.exit_code == 0
    assert "score: 1.00" in result.stdout


def test_source_matches_document_none_id_never_matches():
    from raginject.corpus import source_matches_document

    assert source_matches_document(["raginject-p1", "anything"], None) is False


# --- retrieval_match / scores_retrieval plumbing ------------------------


def _retrieval_pattern(pattern_id="r1"):
    return AttackPattern(
        id=pattern_id,
        category="retriever_poisoning",
        description="d",
        injected_content="keyword stuffed document",
        question="what is the expense policy?",
        success_criteria=SuccessCriteria(type="retrieval_match"),
    )


class _RecordingJudge(Judge):
    """Records every JudgeContext it was called with, and defers to
    retrieval_match's own logic so its Verdict is realistic."""

    def __init__(self):
        self.contexts = []

    def judge(self, ctx: JudgeContext) -> Verdict:
        self.contexts.append(ctx)
        from raginject.judges.retrieval import RetrievalMatchJudge

        return RetrievalMatchJudge().judge(ctx)


def test_document_id_reaches_the_judge_in_mode_a():
    injector = _RecordingInjector()
    target = _CorpusTarget(injector)
    recording_judge = _RecordingJudge()
    runner = Runner(
        target, judges={"keyword_match": recording_judge}, corpus_injector=injector
    )
    runner.add_patterns([_pattern("p1")])
    runner.run()

    assert recording_judge.contexts[0].document_id == "raginject-p1"


def test_mode_a_retrieval_pattern_not_retrieved_is_blocked_not_error():
    injector = _RecordingInjector()
    target = _CorpusTarget(injector, sources_mode="unrelated")
    runner = Runner(target, corpus_injector=injector)
    runner.add_patterns([_retrieval_pattern()])
    result = runner.run()

    # If _verify_retrieval had fired for this pattern it would have turned
    # this into an "error" row - it must not, since "not retrieved" is
    # exactly the "blocked" verdict for a retrieval-scoring pattern.
    assert result.outcomes[0].status == "blocked"


def test_mode_a_retrieval_pattern_retrieved_is_leaked():
    injector = _RecordingInjector()
    target = _CorpusTarget(injector)  # sources_mode="ids": matches
    runner = Runner(target, corpus_injector=injector)
    runner.add_patterns([_retrieval_pattern()])
    result = runner.run()

    assert result.outcomes[0].status == "leaked"


def test_mode_a_retrieval_pattern_empty_sources_is_error():
    injector = _RecordingInjector()
    target = _CorpusTarget(injector, sources_mode="empty")
    runner = Runner(target, corpus_injector=injector)
    runner.add_patterns([_retrieval_pattern()])
    result = runner.run()

    assert result.outcomes[0].status == "error"
    assert "no sources" in result.outcomes[0].verdict_reason


def test_mode_a_retrieval_pattern_empty_sources_is_error_even_with_verify_retrieval_false():
    # The no-sources -> error replacement is the measurement itself for
    # these patterns, not a --no-verify-retrieval-gated verification step.
    injector = _RecordingInjector()
    target = _CorpusTarget(injector, sources_mode="empty")
    runner = Runner(target, corpus_injector=injector, verify_retrieval=False)
    runner.add_patterns([_retrieval_pattern()])
    result = runner.run()

    assert result.outcomes[0].status == "error"


def test_mode_b_retrieval_pattern_raises_configuration_error_before_any_query():
    calls = []

    class _CountingTarget(Target):
        def query(self, question, context=None):
            calls.append(question)
            return {"answer": "ok", "sources": []}

    runner = Runner(_CountingTarget())
    runner.add_patterns([_retrieval_pattern()])

    with pytest.raises(ConfigurationError, match="corpus injection mode"):
        runner.run()

    assert calls == []


def test_mode_b_retrieval_pattern_via_judge_override_also_raises():
    # The preflight check uses the per-pattern *resolved* judge, so
    # --judge retrieval_match (an override on an otherwise-ordinary
    # pattern) is covered too, not just a pattern that names it directly.
    from raginject.judges.retrieval import RetrievalMatchJudge

    calls = []

    class _CountingTarget(Target):
        def query(self, question, context=None):
            calls.append(question)
            return {"answer": "ok", "sources": []}

    runner = Runner(_CountingTarget(), judge_override=RetrievalMatchJudge())
    runner.add_patterns(
        [
            AttackPattern(
                id="p1",
                category="test",
                description="d",
                injected_content="here is SECRET",
                question="q?",
                success_criteria=SuccessCriteria(type="keyword_match"),
            )
        ]
    )

    with pytest.raises(ConfigurationError, match="corpus injection mode"):
        runner.run()

    assert calls == []


class _AnswerOnlyJudge(Judge):
    """Stands in for `--verify-leaks llm_judge`: it reads the answer, finds
    no leak in it, and would flip any row it is allowed to re-judge."""

    def judge(self, ctx: JudgeContext) -> Verdict:
        return Verdict(attack_succeeded=False, reason="answer shows no leak")


def test_verify_leaks_never_overrides_a_retrieval_verdict():
    """Regression test: leak verification corrects false positives in
    *answer text*. A retrieval verdict comes from `sources`, and the answer
    of a hijacked retrieval never contains a canary - so letting an
    answer-based verifier run over these rows flipped every real hijack to
    "blocked" and reported a fully poisoned retriever as score 1.00.
    """
    injector = _RecordingInjector()
    target = _CorpusTarget(injector)  # sources_mode="ids": document matches
    runner = Runner(
        target,
        corpus_injector=injector,
        verify_leaks_judge=_AnswerOnlyJudge(),
    )
    runner.add_patterns([_retrieval_pattern()])
    result = runner.run()

    assert result.outcomes[0].status == "leaked"
    assert result.score == 0.0


def test_verify_leaks_still_applies_to_ordinary_patterns():
    # The exclusion above is scoped to retrieval-scoring judges only; an
    # ordinary keyword_match row must still be re-judgeable.
    injector = _RecordingInjector()
    target = _CorpusTarget(injector)
    runner = Runner(
        target,
        corpus_injector=injector,
        verify_leaks_judge=_AnswerOnlyJudge(),
    )
    runner.add_patterns([_pattern("p1")])
    result = runner.run()

    assert result.outcomes[0].status == "blocked"


def test_retrieval_scoring_judge_is_rejected_as_a_leak_verifier():
    from raginject.judges.retrieval import RetrievalMatchJudge

    injector = _RecordingInjector()
    runner = Runner(
        _CorpusTarget(injector),
        corpus_injector=injector,
        verify_leaks_judge=RetrievalMatchJudge(),
    )
    runner.add_patterns([_pattern("p1")])

    with pytest.raises(ConfigurationError, match="verify leaks"):
        runner.run()


def test_cli_prints_leftover_warning_on_aborted_run():
    """Regression test: the leftover-document warning must print even when
    the run is aborted by a ConfigurationError (here, from `remove()`
    itself), not only on the success path. Before the fix, the warning sat
    after `runner.run()` inside the `try`, so any exception out of `run()`
    - including this one - skipped it entirely."""
    result = _invoke(
        "run",
        "--target-module",
        "raginject.demo:vulnerable_rag",
        "--corpus-injector",
        "tests.fixture_rag:remove_raises_configuration_error",
    )
    assert result.exit_code == 2
    assert "left in your corpus" in result.stderr
    assert "raginject-" in result.stderr
