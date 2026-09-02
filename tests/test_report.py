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
    assert d["schema_version"] == REPORT_SCHEMA_VERSION == 1


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


def test_format_text_verbose_includes_answer():
    outcomes = [_outcome(answer="the secret answer")]
    text_default = format_text(_result(outcomes), ReportOptions(verbose=False))
    text_verbose = format_text(_result(outcomes), ReportOptions(verbose=True))
    assert "the secret answer" not in text_default
    assert "the secret answer" in text_verbose


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
