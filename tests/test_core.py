"""Runner: run multiple attack patterns and aggregate the score correctly."""

from typing import List, Optional

import pytest

from raginject.attacks.schema import AttackPattern, SuccessCriteria
from raginject.core import Runner
from raginject.errors import ConfigurationError, TargetConnectionError
from raginject.judges import Judge, JudgeContext, Verdict
from raginject.target import QueryResult, Target


def _pattern(pattern_id: str, forbidden=("SECRET",), judge_type="keyword_match"):
    return AttackPattern(
        id=pattern_id,
        category="test",
        description="d",
        injected_content="inject me",
        question="q?",
        success_criteria=SuccessCriteria(
            type=judge_type, forbidden_in_answer=list(forbidden)
        ),
    )


class _FakeTarget(Target):
    """A Target whose behavior per-question is fully scripted, and which
    counts how many times `query` was called (for the "zero calls sent"
    preflight test)."""

    def __init__(self, behavior):
        self.behavior = behavior
        self.calls = 0
        self.received_context = []

    def query(self, question: str, context: Optional[List[str]] = None) -> QueryResult:
        self.calls += 1
        self.received_context.append(context)
        result = self.behavior(question)
        if isinstance(result, Exception):
            raise result
        return result


def test_mixed_blocked_leaked_error_excludes_error_from_denominator():
    def behavior(question):
        if question == "blocked-q":
            return {"answer": "nothing bad", "sources": []}
        if question == "leaked-q":
            return {"answer": "here is SECRET", "sources": []}
        raise TargetConnectionError("boom")

    target = _FakeTarget(behavior)
    runner = Runner(target)
    runner.add_patterns(
        [
            AttackPattern(
                id="p-blocked",
                category="c",
                description="d",
                injected_content="i",
                question="blocked-q",
                success_criteria=SuccessCriteria(
                    type="keyword_match", forbidden_in_answer=["SECRET"]
                ),
            ),
            AttackPattern(
                id="p-leaked",
                category="c",
                description="d",
                injected_content="i",
                question="leaked-q",
                success_criteria=SuccessCriteria(
                    type="keyword_match", forbidden_in_answer=["SECRET"]
                ),
            ),
            AttackPattern(
                id="p-error",
                category="c",
                description="d",
                injected_content="i",
                question="error-q",
                success_criteria=SuccessCriteria(
                    type="keyword_match", forbidden_in_answer=["SECRET"]
                ),
            ),
        ]
    )
    result = runner.run()

    assert result.blocked_count == 1
    assert result.leaked_count == 1
    assert result.error_count == 1
    assert result.scored_count == 2
    assert result.score == pytest.approx(0.5)
    assert result.has_scoreable_outcomes is True
    assert result.failed_ids == ["p-leaked"]


def test_all_error_run_scores_zero_without_raising():
    target = _FakeTarget(lambda q: TargetConnectionError("down"))
    runner = Runner(target)
    runner.add_patterns([_pattern("p1"), _pattern("p2")])
    result = runner.run()

    assert result.error_count == 2
    assert result.scored_count == 0
    assert result.score == 0.0
    assert result.has_scoreable_outcomes is False


def test_zero_patterns_raises_configuration_error():
    target = _FakeTarget(lambda q: {"answer": "ok", "sources": []})
    runner = Runner(target)
    with pytest.raises(ConfigurationError):
        runner.run()
    assert target.calls == 0


def test_unknown_judge_sends_zero_queries():
    target = _FakeTarget(lambda q: {"answer": "ok", "sources": []})
    runner = Runner(target)
    runner.add_patterns([_pattern("p1", judge_type="no_such_judge")])
    with pytest.raises(ConfigurationError):
        runner.run()
    assert target.calls == 0


def test_validate_criteria_failure_is_preflight_configuration_error():
    target = _FakeTarget(lambda q: {"answer": "ok", "sources": []})
    runner = Runner(target)
    pattern = AttackPattern(
        id="bad",
        category="c",
        description="d",
        injected_content="i",
        question="q",
        success_criteria=SuccessCriteria(
            type="keyword_match"
        ),  # no forbidden_in_answer
    )
    runner.add_patterns([pattern])
    with pytest.raises(ConfigurationError):
        runner.run()
    assert target.calls == 0


def test_load_patterns_is_additive_and_later_wins():
    target = _FakeTarget(lambda q: {"answer": "ok", "sources": []})
    runner = Runner(target)
    runner.add_patterns([_pattern("shared", forbidden=("FIRST",))])
    runner.add_patterns([_pattern("shared", forbidden=("SECOND",))])
    runner.add_patterns([_pattern("other", forbidden=("OTHER",))])

    patterns = runner.patterns
    assert len(patterns) == 2
    by_id = {p.id: p for p in patterns}
    assert by_id["shared"].success_criteria.forbidden_in_answer == ["SECOND"]
    # position of first occurrence ("shared") is kept, i.e. it stays first.
    assert [p.id for p in patterns] == ["shared", "other"]


def test_add_patterns_directly():
    target = _FakeTarget(lambda q: {"answer": "nothing", "sources": []})
    runner = Runner(target)
    runner.add_patterns([_pattern("only")])
    assert [p.id for p in runner.patterns] == ["only"]
    result = runner.run()
    assert result.pattern_count == 1


def test_duration_ms_recorded_on_error_rows():
    target = _FakeTarget(lambda q: TargetConnectionError("down"))
    runner = Runner(target)
    runner.add_patterns([_pattern("p1")])
    result = runner.run()
    assert result.outcomes[0].status == "error"
    assert result.outcomes[0].duration_ms is not None
    assert result.outcomes[0].duration_ms >= 0


def test_configuration_error_from_target_propagates_not_status_error():
    target = _FakeTarget(lambda q: ConfigurationError("bad target signature"))
    runner = Runner(target)
    runner.add_patterns([_pattern("p1"), _pattern("p2")])
    with pytest.raises(ConfigurationError):
        runner.run()


class _AlwaysRaisingJudge(Judge):
    def judge(self, ctx: JudgeContext) -> Verdict:
        raise RuntimeError("judge exploded")


def test_judge_exception_only_affects_its_own_row():
    target = _FakeTarget(lambda q: {"answer": "ok", "sources": []})
    runner = Runner(target, judges={"boom": _AlwaysRaisingJudge()})
    runner.add_patterns(
        [
            AttackPattern(
                id="bad-judge",
                category="c",
                description="d",
                injected_content="i",
                question="q",
                success_criteria=SuccessCriteria(type="boom"),
            ),
            _pattern("good"),
        ]
    )
    result = runner.run()
    by_id = {o.pattern_id: o for o in result.outcomes}
    assert by_id["bad-judge"].status == "error"
    assert by_id["bad-judge"].error is not None
    assert by_id["good"].status == "blocked"


def test_on_outcome_callback_invoked_per_pattern():
    target = _FakeTarget(lambda q: {"answer": "ok", "sources": []})
    runner = Runner(target)
    runner.add_patterns([_pattern("p1"), _pattern("p2")])
    seen = []
    runner.run(on_outcome=seen.append)
    assert [o.pattern_id for o in seen] == ["p1", "p2"]


def test_summary_contains_key_numbers():
    target = _FakeTarget(lambda q: {"answer": "here is SECRET", "sources": []})
    runner = Runner(target)
    runner.add_patterns([_pattern("p1")])
    result = runner.run()
    summary = result.summary
    assert "0/1" in summary
    # PLAN.md §7.1: the summary must name the ids that got through.
    assert "Failed: p1" in summary


def test_runner_judges_override_takes_priority_over_registry():
    """A judge injected via Runner(judges=...) is used even though a judge
    of the same name ('keyword_match') is registered globally."""

    class _AlwaysBlocks(Judge):
        def judge(self, ctx: JudgeContext) -> Verdict:
            return Verdict(attack_succeeded=False, reason="always blocks")

    target = _FakeTarget(lambda q: {"answer": "here is SECRET", "sources": []})
    runner = Runner(target, judges={"keyword_match": _AlwaysBlocks()})
    runner.add_patterns([_pattern("p1")])
    result = runner.run()
    assert result.outcomes[0].status == "blocked"
    assert result.outcomes[0].verdict_reason == "always blocks"


def test_context_passed_is_single_element_list_of_injected_content():
    target = _FakeTarget(lambda q: {"answer": "ok", "sources": []})
    runner = Runner(target)
    pattern = _pattern("p1")
    runner.add_patterns([pattern])
    runner.run()
    assert target.received_context == [[pattern.injected_content]]
