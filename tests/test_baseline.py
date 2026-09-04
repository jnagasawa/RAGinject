"""Tests for raginject.baseline: load_baseline's error branches,
check_comparable's comparability rules, and compare()'s derived diff."""

import json

import pytest

from raginject.baseline import check_comparable, compare, load_baseline
from raginject.core import AttackOutcome, Result
from raginject.errors import ConfigurationError
from raginject.report import REPORT_SCHEMA_VERSION, result_to_dict


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
        raginject_version="0.5.0",
        target_description="FunctionTarget(demo)",
        pattern_count=len(outcomes),
    )


def _write_report(tmp_path, data, name="baseline.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _baseline_dict(outcomes, **overrides):
    d = result_to_dict(_result(outcomes))
    d.update(overrides)
    return d


# --- load_baseline error branches -------------------------------------


def test_load_baseline_missing_file(tmp_path):
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_baseline(tmp_path / "no-such-file.json")


def test_load_baseline_directory(tmp_path):
    with pytest.raises(ConfigurationError, match="directory"):
        load_baseline(tmp_path)


def test_load_baseline_invalid_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="not valid JSON"):
        load_baseline(path)


def test_load_baseline_not_a_dict(tmp_path):
    path = tmp_path / "list.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="JSON object"):
        load_baseline(path)


def test_load_baseline_missing_schema_version(tmp_path):
    path = _write_report(tmp_path, {"score": 1.0, "counts": {}, "outcomes": []})
    with pytest.raises(ConfigurationError, match="schema_version"):
        load_baseline(path)


def test_load_baseline_schema_version_too_new(tmp_path):
    data = _baseline_dict([_outcome()])
    data["schema_version"] = REPORT_SCHEMA_VERSION + 1
    path = _write_report(tmp_path, data)
    with pytest.raises(ConfigurationError, match="newer than this raginject"):
        load_baseline(path)


@pytest.mark.parametrize("missing_key", ["score", "counts", "outcomes"])
def test_load_baseline_missing_required_key(tmp_path, missing_key):
    data = _baseline_dict([_outcome()])
    del data[missing_key]
    path = _write_report(tmp_path, data)
    with pytest.raises(ConfigurationError, match=missing_key):
        load_baseline(path)


def test_load_baseline_no_scoreable_rows(tmp_path):
    outcomes = [_outcome(pattern_id="e1", status="error", error="boom")]
    data = _baseline_dict(outcomes)
    path = _write_report(tmp_path, data)
    with pytest.raises(ConfigurationError, match="no scoreable rows"):
        load_baseline(path)


def test_load_baseline_v1_report_without_mode_normalizes_to_b(tmp_path):
    data = _baseline_dict([_outcome()])
    del data["mode"]
    del data["corpus_injector_description"]
    data["schema_version"] = 1
    path = _write_report(tmp_path, data)
    loaded = load_baseline(path)
    assert loaded["mode"] == "b"


def test_load_baseline_accepts_current_schema_version(tmp_path):
    data = _baseline_dict([_outcome()])
    path = _write_report(tmp_path, data)
    loaded = load_baseline(path)
    assert loaded["schema_version"] == REPORT_SCHEMA_VERSION
    assert loaded["mode"] == "b"


def test_load_baseline_ignores_existing_baseline_key(tmp_path):
    # A report produced by a --baseline run carries its own "baseline" key
    # (schema v3+); that must not confuse loading it as the *next* baseline.
    data = _baseline_dict([_outcome()])
    data["baseline"] = {"score": 0.5}
    path = _write_report(tmp_path, data)
    loaded = load_baseline(path)
    assert loaded["score"] == data["score"]


# --- check_comparable ---------------------------------------------------


def test_check_comparable_matching_ids_and_mode_ok():
    data = _baseline_dict([_outcome(pattern_id="a"), _outcome(pattern_id="b")])
    warnings = check_comparable(data, pattern_ids=["a", "b"], mode="b")
    assert warnings == []


def test_check_comparable_mismatched_ids_raises_and_lists_both_sides():
    data = _baseline_dict([_outcome(pattern_id="a"), _outcome(pattern_id="b")])
    with pytest.raises(ConfigurationError) as excinfo:
        check_comparable(data, pattern_ids=["a", "c"], mode="b")
    message = str(excinfo.value)
    assert "b" in message
    assert "c" in message
    assert "--output json > baseline.json" in message


def test_check_comparable_mismatched_ids_caps_long_lists():
    baseline_ids = [f"id-{i}" for i in range(20)]
    data = _baseline_dict([_outcome(pattern_id=pid) for pid in baseline_ids])
    with pytest.raises(ConfigurationError) as excinfo:
        check_comparable(data, pattern_ids=["totally-different"], mode="b")
    message = str(excinfo.value)
    assert "and " in message and "more" in message


def test_check_comparable_mode_mismatch_raises():
    data = _baseline_dict([_outcome(pattern_id="a")])
    data["mode"] = "a"
    with pytest.raises(ConfigurationError, match="mode"):
        check_comparable(data, pattern_ids=["a"], mode="b")


def test_check_comparable_version_mismatch_warns():
    data = _baseline_dict([_outcome(pattern_id="a")])
    data["raginject_version"] = "0.0.1"
    warnings = check_comparable(data, pattern_ids=["a"], mode="b")
    assert any("0.0.1" in w for w in warnings)


def test_check_comparable_target_description_mismatch_warns():
    data = _baseline_dict([_outcome(pattern_id="a")], target_description="old target")
    warnings = check_comparable(
        data, pattern_ids=["a"], mode="b", target_description="new target"
    )
    assert any("target" in w for w in warnings)


# --- compare --------------------------------------------------------------


def test_compare_derives_new_leaks_fixed_and_new_errors():
    baseline_outcomes = [
        _outcome(pattern_id="blocked-then-leaked", status="blocked"),
        _outcome(pattern_id="leaked-then-blocked", status="leaked"),
        _outcome(pattern_id="blocked-then-error", status="blocked"),
        _outcome(pattern_id="was-error-stays-error", status="error", error="x"),
        _outcome(pattern_id="was-error-now-blocked", status="error", error="x"),
        _outcome(pattern_id="unchanged-blocked", status="blocked"),
    ]
    baseline_data = _baseline_dict(baseline_outcomes)

    current_outcomes = [
        _outcome(pattern_id="blocked-then-leaked", status="leaked"),
        _outcome(pattern_id="leaked-then-blocked", status="blocked"),
        _outcome(pattern_id="blocked-then-error", status="error", error="y"),
        _outcome(pattern_id="was-error-stays-error", status="error", error="y"),
        _outcome(pattern_id="was-error-now-blocked", status="blocked"),
        _outcome(pattern_id="unchanged-blocked", status="blocked"),
    ]
    result = _result(current_outcomes)

    comparison = compare(result, baseline_data)

    assert comparison.new_leaks == ["blocked-then-leaked"]
    assert comparison.fixed == ["leaked-then-blocked"]
    assert comparison.new_errors == ["blocked-then-error"]
    # baseline-error rows never appear in any list, regardless of what they
    # become in this run.
    assert "was-error-stays-error" not in (
        comparison.new_leaks + comparison.fixed + comparison.new_errors
    )
    assert "was-error-now-blocked" not in (
        comparison.new_leaks + comparison.fixed + comparison.new_errors
    )
    assert "unchanged-blocked" not in (
        comparison.new_leaks + comparison.fixed + comparison.new_errors
    )


def test_compare_score_delta():
    baseline_outcomes = [
        _outcome(pattern_id="a", status="blocked"),
        _outcome(pattern_id="b", status="blocked"),
    ]
    baseline_data = _baseline_dict(baseline_outcomes)  # score 1.0

    current_outcomes = [
        _outcome(pattern_id="a", status="blocked"),
        _outcome(pattern_id="b", status="leaked"),
    ]
    result = _result(current_outcomes)  # score 0.5

    comparison = compare(result, baseline_data)
    assert comparison.baseline_score == pytest.approx(1.0)
    assert comparison.score == pytest.approx(0.5)
    assert comparison.score_delta == pytest.approx(-0.5)


def test_compare_max_drop_boundary_exact_drop_passes():
    baseline_outcomes = [
        _outcome(pattern_id=f"p{i}", status="blocked") for i in range(10)
    ]
    baseline_data = _baseline_dict(baseline_outcomes)  # score 1.0

    # 9/10 blocked -> score 0.9, a drop of exactly 0.1.
    current_outcomes = [
        _outcome(pattern_id=f"p{i}", status="blocked") for i in range(9)
    ] + [_outcome(pattern_id="p9", status="leaked")]
    result = _result(current_outcomes)

    comparison = compare(result, baseline_data, max_drop=0.1)
    assert comparison.regressed is False


def test_compare_max_drop_boundary_one_epsilon_more_fails():
    baseline_outcomes = [
        _outcome(pattern_id=f"p{i}", status="blocked") for i in range(10)
    ]
    baseline_data = _baseline_dict(baseline_outcomes)  # score 1.0

    current_outcomes = [
        _outcome(pattern_id=f"p{i}", status="blocked") for i in range(9)
    ] + [_outcome(pattern_id="p9", status="leaked")]
    result = _result(current_outcomes)  # score 0.9, drop of 0.1

    comparison = compare(result, baseline_data, max_drop=0.1 - 1e-9)
    assert comparison.regressed is True


def test_compare_no_max_drop_never_regresses():
    baseline_outcomes = [_outcome(pattern_id="a", status="blocked")]
    baseline_data = _baseline_dict(baseline_outcomes)
    current_outcomes = [_outcome(pattern_id="a", status="leaked")]
    result = _result(current_outcomes)
    comparison = compare(result, baseline_data, max_drop=None)
    assert comparison.max_drop is None
    assert comparison.regressed is False


# --- malformed baselines must be ConfigurationError, not TypeError ----
#
# Pointing --baseline at some other JSON file is a user setup error, so it
# has to surface as an actionable message. Before these were checked, each
# of the cases below escaped load_baseline() and crashed later as an
# "unexpected TypeError/KeyError" naming nothing the user could act on -
# and the string-valued `counts` case defeated the "no scoreable rows"
# check entirely, because "52" + "0" concatenates to a truthy "520".


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda d: d.update(schema_version="3"), 'non-integer "schema_version"'),
        (lambda d: d.update(schema_version=True), 'non-integer "schema_version"'),
        (lambda d: d.update(score="1.0"), 'non-numeric "score"'),
        (lambda d: d.update(counts="oops"), 'non-object "counts"'),
        (
            lambda d: d.update(counts={"blocked": "52", "leaked": "0"}),
            'non-numeric "counts.blocked"',
        ),
        (lambda d: d.update(outcomes="oops"), 'non-list "outcomes"'),
        (lambda d: d.update(outcomes=["oops"]), "non-object entry at outcomes\\[0\\]"),
        (
            lambda d: d.update(outcomes=[{"status": "blocked"}]),
            'no string "pattern_id" at outcomes\\[0\\]',
        ),
        (
            lambda d: d.update(outcomes=[{"pattern_id": "a", "status": "weird"}]),
            'unknown "status" at outcomes\\[0\\]',
        ),
    ],
)
def test_load_baseline_rejects_malformed_shapes(tmp_path, mutate, expected):
    data = _baseline_dict([_outcome(pattern_id="a", status="blocked")])
    mutate(data)
    path = _write_report(tmp_path, data)
    with pytest.raises(ConfigurationError, match=expected):
        load_baseline(path)
