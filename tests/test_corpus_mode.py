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
