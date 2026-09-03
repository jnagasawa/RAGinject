"""Tests for raginject.report: schema_version, counts, truncation, secret
hygiene, non-ASCII preservation, and the formatter registry."""

import json

import pytest

from raginject.core import AttackOutcome, Result
from raginject.errors import ConfigurationError
from raginject.report import (
    REPORT_SCHEMA_VERSION,
    ReportOptions,
    available_formatters,
    format_json,
    format_text,
    get_formatter,
    register_formatter,
    result_to_dict,
)


def _outcome(**overrides) -> AttackOutcome:
    defaults = dict(
        pattern_id="p1",
        category="cat",
        status="blocked",
        question="q?",
        injected_content="inject",
        answer="answer",
        sources=[],
        verdict_reason="reason",
        error=None,
        duration_ms=1.23,
    )
    defaults.update(overrides)
    return AttackOutcome(**defaults)


def _result(outcomes) -> Result:
    return Result(
        outcomes=outcomes,
        started_at="2026-01-01T00:00:00+00:00",
        raginject_version="0.2.0",
        target_description="FunctionTarget(demo)",
        pattern_count=len(outcomes),
    )


def test_result_to_dict_schema_version():
    result = _result([_outcome()])
    d = result_to_dict(result)
    assert d["schema_version"] == REPORT_SCHEMA_VERSION == 2


def test_result_to_dict_counts():
    outcomes = [
        _outcome(pattern_id="a", status="blocked"),
        _outcome(pattern_id="b", status="leaked"),
        _outcome(pattern_id="c", status="error"),
    ]
    d = result_to_dict(_result(outcomes))
    assert d["counts"] == {"blocked": 1, "leaked": 1, "error": 1, "scored": 2}
    assert d["score"] == pytest.approx(0.5)


def test_truncation_sets_answer_truncated_flag():
    long_answer = "x" * 3000
    outcomes = [_outcome(answer=long_answer)]
    options = ReportOptions(max_answer_chars=100)
    d = result_to_dict(_result(outcomes), options)
    out = d["outcomes"][0]
    assert out["answer_truncated"] is True
    assert len(out["answer"]) == 100


def test_short_answer_not_truncated():
    outcomes = [_outcome(answer="short")]
    d = result_to_dict(_result(outcomes), ReportOptions(max_answer_chars=2000))
    assert d["outcomes"][0]["answer_truncated"] is False
    assert d["outcomes"][0]["answer"] == "short"


def test_json_report_has_no_secret_fields():
    """Result/AttackOutcome never carry HTTP headers, so the JSON report
    can't leak them - this test locks that shape down at the report layer."""
    outcomes = [_outcome(answer="the answer is 42")]
    rendered = format_json(_result(outcomes))
    parsed = json.loads(rendered)
    dumped = json.dumps(parsed)
    assert "Authorization" not in dumped
    assert "headers" not in dumped
    # Only known top-level keys are present.
    assert set(parsed.keys()) == {
        "schema_version",
        "raginject_version",
        "started_at",
        "target_description",
        "pattern_count",
        "mode",
        "corpus_injector_description",
        "score",
        "counts",
        "outcomes",
    }


def test_json_preserves_non_ascii():
    outcomes = [_outcome(question="日本語の質問", answer="日本語の回答です")]
    rendered = format_json(_result(outcomes))
    assert "日本語の質問" in rendered
    assert "日本語の回答です" in rendered
    assert "\\u" not in rendered


def test_format_text_includes_summary_and_outcomes():
    outcomes = [_outcome(pattern_id="p1", status="leaked", verdict_reason="oops")]
    text = format_text(_result(outcomes))
    assert "p1" in text
    assert "LEAKED" in text
    assert "oops" in text


def test_format_text_default_omits_blocked_outcomes():
    outcomes = [
        _outcome(pattern_id="b1", status="blocked"),
        _outcome(pattern_id="l1", status="leaked", verdict_reason="leaked!"),
    ]
    text = format_text(_result(outcomes))
    assert "b1" not in text
    assert "l1" in text
    assert "leaked!" in text


def test_format_text_verbose_includes_blocked_outcomes():
    outcomes = [
        _outcome(pattern_id="b1", status="blocked"),
        _outcome(pattern_id="l1", status="leaked", verdict_reason="leaked!"),
    ]
    text = format_text(_result(outcomes), ReportOptions(verbose=True))
    assert "b1" in text
    assert "l1" in text


def test_format_text_default_lists_leaked_and_error():
    outcomes = [
        _outcome(pattern_id="l1", status="leaked", verdict_reason="leaked!"),
        _outcome(pattern_id="e1", status="error", error="boom"),
    ]
    text = format_text(_result(outcomes))
    assert "l1" in text
    assert "e1" in text
    assert "boom" in text


def test_format_text_category_breakdown():
    outcomes = [
        _outcome(pattern_id="a1", category="cat_a", status="blocked"),
        _outcome(pattern_id="a2", category="cat_a", status="blocked"),
        _outcome(pattern_id="a3", category="cat_a", status="leaked"),
        _outcome(pattern_id="b1", category="cat_b", status="blocked"),
        _outcome(pattern_id="b2", category="cat_b", status="error", error="boom"),
    ]
    text = format_text(_result(outcomes))
    assert "by category:" in text
    assert "cat_a" in text
    assert "2/3 blocked" in text
    assert "cat_b" in text
    # cat_b has one blocked (scoreable) and one error, which must not be
    # silently dropped from the score denominator's visibility.
    assert "1/1 blocked" in text
    assert "1 error" in text


def test_format_text_all_blocked_is_short_and_clear():
    outcomes = [
        _outcome(pattern_id="a1", status="blocked"),
        _outcome(pattern_id="a2", status="blocked"),
    ]
    text = format_text(_result(outcomes))
    assert "all 2 attacks blocked" in text
    assert "a1" not in text
    assert "a2" not in text


def test_format_text_verbose_includes_answer():
    outcomes = [_outcome(answer="the secret answer")]
    text_default = format_text(_result(outcomes), ReportOptions(verbose=False))
    text_verbose = format_text(_result(outcomes), ReportOptions(verbose=True))
    assert "the secret answer" not in text_default
    assert "the secret answer" in text_verbose


def test_format_json_unaffected_by_text_report_changes():
    """format_json/result_to_dict must stay byte-identical regardless of
    verbose or category breakdown changes to format_text - the JSON shape
    is frozen and category_counts is a text-report-only concern."""
    outcomes = [
        _outcome(pattern_id="a1", category="cat_a", status="blocked"),
        _outcome(pattern_id="a2", category="cat_a", status="leaked"),
        _outcome(pattern_id="b1", category="cat_b", status="error", error="boom"),
    ]
    result = _result(outcomes)
    default_json = format_json(result, ReportOptions(verbose=False))
    verbose_json = format_json(result, ReportOptions(verbose=True))
    assert default_json == verbose_json
    parsed = json.loads(default_json)
    assert "category_counts" not in parsed
    assert set(parsed.keys()) == {
        "schema_version",
        "raginject_version",
        "started_at",
        "target_description",
        "pattern_count",
        "mode",
        "corpus_injector_description",
        "score",
        "counts",
        "outcomes",
    }


def test_available_formatters_includes_builtins():
    formatters = available_formatters()
    assert "text" in formatters
    assert "json" in formatters


def test_get_formatter_unknown_raises_configuration_error():
    with pytest.raises(ConfigurationError):
        get_formatter("no-such-format")


def test_register_formatter_adds_new_format():
    @register_formatter("custom")
    def _my_formatter(result, options=None):
        return "custom"

    try:
        assert "custom" in available_formatters()
        assert get_formatter("custom")(_result([_outcome()])) == "custom"
    finally:
        from raginject.report import _FORMATTERS

        _FORMATTERS.pop("custom", None)


def test_max_answer_chars_zero_disables_truncation():
    # 0 must mean "no limit", not "truncate to an empty string".
    result = _result([_outcome(answer="x" * 50)])
    payload = json.loads(format_json(result, ReportOptions(max_answer_chars=0)))
    assert payload["outcomes"][0]["answer"] == "x" * 50
    assert payload["outcomes"][0]["answer_truncated"] is False


def test_max_answer_chars_none_disables_truncation():
    result = _result([_outcome(answer="x" * 50)])
    payload = json.loads(format_json(result, ReportOptions(max_answer_chars=None)))
    assert payload["outcomes"][0]["answer"] == "x" * 50


def test_format_text_lists_every_failed_id_even_when_many():
    """The `failed:` list is never truncated. When a gate fails these ids
    are what the user acts on, and a CI log naming only the first few would
    force a second, verbose run just to learn the rest."""
    outcomes = [
        _outcome(pattern_id=f"pattern-{i:03d}", status="leaked") for i in range(40)
    ]
    # One survivor, so this is a partial failure: the id list is what the
    # user acts on, and the "everything failed" collapse must not kick in.
    outcomes.append(_outcome(pattern_id="survivor", status="blocked"))
    text = format_text(_result(outcomes))

    for i in range(40):
        assert f"pattern-{i:03d}" in text, f"pattern-{i:03d} missing from failed list"
    assert "more (every id is listed above" in text  # details capped, ids not


def test_format_text_failed_ids_wrap_instead_of_one_long_line():
    outcomes = [
        _outcome(pattern_id=f"a-very-long-pattern-id-{i:03d}", status="leaked")
        for i in range(20)
    ]
    outcomes.append(_outcome(pattern_id="survivor", status="blocked"))
    text = format_text(_result(outcomes))

    failed_lines = [
        line
        for line in text.splitlines()
        if line.startswith("failed: ") or line.startswith("        a-very-long")
    ]
    assert len(failed_lines) > 1, "expected the id list to wrap onto several lines"
    assert all(len(line) <= 80 for line in failed_lines), (
        "wrapped failed: lines must stay within a normal terminal width"
    )


def test_format_text_caps_detailed_outcomes_but_verbose_does_not():
    outcomes = [
        _outcome(pattern_id=f"p{i:03d}", status="leaked", verdict_reason=f"why-{i:03d}")
        for i in range(25)
    ]
    outcomes.append(_outcome(pattern_id="survivor", status="blocked"))

    default = format_text(_result(outcomes))
    assert "why-000" in default
    assert "why-024" not in default, "detail list should be capped by default"
    assert "and 15 more" in default

    verbose = format_text(_result(outcomes), ReportOptions(verbose=True))
    assert "why-024" in verbose
    assert "more (every id is listed above" not in verbose


def test_format_text_no_cap_notice_when_few_outcomes():
    outcomes = [_outcome(pattern_id="p1", status="leaked")]
    text = format_text(_result(outcomes))
    assert "more (every id is listed above" not in text


def test_format_text_collapses_failed_ids_when_everything_leaked():
    """When every scoreable pattern leaked, naming each id costs ~20 lines
    and says nothing the per-category breakdown hasn't already said."""
    outcomes = [_outcome(pattern_id=f"p{i:03d}", status="leaked") for i in range(30)]
    text = format_text(_result(outcomes))
    assert "failed: all 30 scoreable patterns" in text
    assert "p029" not in text


def test_format_text_lists_ids_when_only_some_leaked():
    """A partial failure is the case where the ids are actually actionable,
    so they must still be listed in full."""
    outcomes = [_outcome(pattern_id=f"p{i:03d}", status="leaked") for i in range(30)]
    outcomes.append(_outcome(pattern_id="survivor", status="blocked"))
    text = format_text(_result(outcomes))
    assert "failed: all" not in text
    for i in range(30):
        assert f"p{i:03d}" in text
