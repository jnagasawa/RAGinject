"""Baseline regression detection: compare a run against a previously saved
JSON report.

No new file format - the baseline is just a report produced earlier by
`raginject run --output json > baseline.json`. This module reads that dict
back, checks the two runs are actually comparable (same pattern set, same
mode), and derives the per-pattern deltas a CLI/report layer can act on.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .core import Result
from .errors import ConfigurationError

#: How many mismatched pattern ids to name individually before folding the
#: rest into "and N more" - a total corpus swap (e.g. an upgrade that grew
#: the default set) would otherwise print dozens of ids for no benefit.
_MAX_LISTED_IDS = 10


@dataclass
class BaselineComparison:
    baseline_score: float
    baseline_started_at: Optional[str]
    score: float  # this run
    score_delta: float  # this run - baseline
    new_leaks: List[str]  # blocked in baseline -> leaked now
    fixed: List[str]  # leaked in baseline -> blocked now
    new_errors: List[str]  # scoreable in baseline -> error now
    max_drop: Optional[float]
    regressed: bool  # only meaningful when max_drop is not None


def _is_int(value: Any) -> bool:
    """True for a real JSON integer. `bool` is excluded on purpose: `True`
    is an `int` in Python, and a report whose schema_version is `true` is
    malformed, not version 1."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    """True for a real JSON number (`bool` excluded, same reasoning)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def load_baseline(path: Union[str, Path]) -> Dict[str, Any]:
    """Read and validate a baseline report from `path`.

    Accepts any `schema_version <= REPORT_SCHEMA_VERSION` - a baseline
    recorded by an older raginject is exactly the normal use case (you
    record it once on `main`, then compare future runs against it as
    raginject itself gets upgraded). A baseline from a *newer* raginject is
    rejected instead of guessed at: its schema may carry fields this build
    doesn't know how to interpret.

    Imports REPORT_SCHEMA_VERSION lazily to avoid a circular import: report.py
    will need BaselineComparison from this module for its own type hints, so
    this module must not import report.py at module scope.
    """
    from .report import REPORT_SCHEMA_VERSION

    candidate = Path(path)
    if not candidate.exists():
        raise ConfigurationError(
            f"--baseline path {str(candidate)!r} does not exist; record one first "
            f"with: raginject run ... --output json > baseline.json"
        )
    if candidate.is_dir():
        raise ConfigurationError(
            f"--baseline path {str(candidate)!r} is a directory; it must be a JSON "
            f"report file produced by raginject run --output json"
        )
    try:
        raw_text = candidate.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(
            f"could not read --baseline path {str(candidate)!r}: {exc}"
        ) from exc

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ConfigurationError(
            f"--baseline path {str(candidate)!r} is not valid JSON: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ConfigurationError(
            f"--baseline path {str(candidate)!r} does not contain a JSON object "
            f"at the top level; it must be a report produced by "
            f"raginject run --output json"
        )

    def _malformed(detail: str) -> ConfigurationError:
        return ConfigurationError(
            f"--baseline path {str(candidate)!r} {detail}; it does not look "
            f"like a raginject JSON report (record one with: raginject run "
            f"... --output json > baseline.json)"
        )

    # Types are checked, not just key presence. Pointing --baseline at some
    # other JSON file that happens to have these keys must produce an
    # actionable configuration error, not a TypeError/KeyError from deep
    # inside the comparison - the user's setup is what is wrong, and the
    # message has to say so.
    schema_version = data.get("schema_version")
    if schema_version is None:
        raise _malformed('has no "schema_version" key')
    if not _is_int(schema_version):
        raise _malformed(f'has a non-integer "schema_version" ({schema_version!r})')
    if schema_version > REPORT_SCHEMA_VERSION:
        raise ConfigurationError(
            f"--baseline path {str(candidate)!r} has schema_version "
            f"{schema_version}, newer than this raginject's "
            f"{REPORT_SCHEMA_VERSION}; upgrade raginject, or re-record the "
            f"baseline with this version: raginject run ... --output json > "
            f"baseline.json"
        )

    for required_key in ("score", "counts", "outcomes"):
        if required_key not in data:
            raise _malformed(f"is missing the required {required_key!r} key")

    if not _is_number(data["score"]):
        raise _malformed(f'has a non-numeric "score" ({data["score"]!r})')

    counts = data["counts"]
    if not isinstance(counts, dict):
        raise _malformed(f'has a non-object "counts" ({type(counts).__name__})')
    for counts_key in ("blocked", "leaked"):
        if not _is_number(counts.get(counts_key, 0)):
            raise _malformed(
                f'has a non-numeric "counts.{counts_key}" ({counts.get(counts_key)!r})'
            )

    outcomes = data["outcomes"]
    if not isinstance(outcomes, list):
        raise _malformed(f'has a non-list "outcomes" ({type(outcomes).__name__})')
    for index, outcome in enumerate(outcomes):
        if not isinstance(outcome, dict):
            raise _malformed(
                f"has a non-object entry at outcomes[{index}] "
                f"({type(outcome).__name__})"
            )
        if not isinstance(outcome.get("pattern_id"), str):
            raise _malformed(f'has no string "pattern_id" at outcomes[{index}]')
        if outcome.get("status") not in ("blocked", "leaked", "error"):
            raise _malformed(
                f'has an unknown "status" at outcomes[{index}] '
                f"({outcome.get('status')!r}); expected one of blocked, "
                f"leaked, error"
            )

    if counts.get("blocked", 0) + counts.get("leaked", 0) <= 0:
        raise ConfigurationError(
            f"--baseline path {str(candidate)!r} has no scoreable rows "
            f"(blocked + leaked == 0); a report where every row errored does "
            f"not describe a working run and cannot be used as a baseline"
        )

    # v1 predates mode A entirely, so a missing "mode" always means mode B.
    # Normalizing here means every downstream consumer of a loaded baseline
    # dict can assume "mode" is always present.
    if "mode" not in data:
        data = dict(data)
        data["mode"] = "b"

    return data


def _format_id_list(ids: List[str]) -> str:
    ids = sorted(ids)
    if len(ids) <= _MAX_LISTED_IDS:
        return ", ".join(ids)
    shown = ids[:_MAX_LISTED_IDS]
    return f"{', '.join(shown)}, and {len(ids) - _MAX_LISTED_IDS} more"


def check_comparable(
    baseline: Dict[str, Any],
    *,
    pattern_ids: List[str],
    mode: str,
    target_description: Optional[str] = None,
) -> List[str]:
    """Check that `baseline` is comparable to a run over `pattern_ids` in
    `mode`. Returns a list of human-readable warning strings for conditions
    that don't block comparison. Raises ConfigurationError for conditions
    that do.

    `target_description` is optional and only used for the (non-fatal)
    warning below - callers that don't have it yet (or don't care) can omit
    it.

    Called before any query is sent (see cli.py's `run`), so a mismatch
    aborts the run with zero API cost - that's the point of checking this
    ahead of `runner.run()` rather than after.
    """
    baseline_ids = {outcome["pattern_id"] for outcome in baseline.get("outcomes", [])}
    current_ids = set(pattern_ids)

    if baseline_ids != current_ids:
        missing = baseline_ids - current_ids  # in baseline, not this run
        added = current_ids - baseline_ids  # in this run, not baseline
        detail_parts = []
        if missing:
            detail_parts.append(
                f"missing from this run: {_format_id_list(list(missing))}"
            )
        if added:
            detail_parts.append(f"new in this run: {_format_id_list(list(added))}")
        raise ConfigurationError(
            "--baseline pattern set does not match this run's pattern set "
            f"({'; '.join(detail_parts)}). Changing --patterns or upgrading "
            "raginject (which can change the built-in corpus) both require "
            "re-recording the baseline: raginject run ... --output json > "
            "baseline.json"
        )

    baseline_mode = baseline.get("mode", "b")
    if baseline_mode != mode:
        raise ConfigurationError(
            f"--baseline was recorded in mode {baseline_mode!r} but this run is "
            f"mode {mode!r}; corpus injection (mode A) and direct context "
            f"injection (mode B) are different measurements and cannot be "
            f"compared. Re-record the baseline in the mode you are running: "
            f"raginject run ... --output json > baseline.json"
        )

    warnings_list: List[str] = []
    from ._version import __version__

    baseline_version = baseline.get("raginject_version")
    if baseline_version is not None and baseline_version != __version__:
        warnings_list.append(
            f"warning: --baseline was recorded with raginject {baseline_version}, "
            f"this run is {__version__}; scores may differ for reasons unrelated "
            f"to your pipeline"
        )

    baseline_target = baseline.get("target_description")
    if (
        target_description is not None
        and baseline_target is not None
        and baseline_target != target_description
    ):
        warnings_list.append(
            f"warning: --baseline was recorded against target "
            f"{baseline_target!r}, this run's target is "
            f"{target_description!r}; the two may not be measuring the same "
            f"pipeline"
        )

    return warnings_list


def compare(
    result: Result, baseline: Dict[str, Any], *, max_drop: Optional[float] = None
) -> BaselineComparison:
    """Compare `result` (a `raginject.core.Result`) against `baseline` (a
    dict from `load_baseline`).

    The three id lists are built in this run's outcome order (i.e. the
    order patterns were loaded/run), which is deterministic for a given
    pattern set and load order - not sorted, since that would obscure the
    order the report already presents outcomes in.

    A pattern whose *baseline* status was "error" is excluded from all
    three lists: it was never actually measured in the baseline run, so it
    can be neither an improvement nor a regression relative to it.
    """
    baseline_status: Dict[str, str] = {
        outcome["pattern_id"]: outcome["status"]
        for outcome in baseline.get("outcomes", [])
    }

    new_leaks: List[str] = []
    fixed: List[str] = []
    new_errors: List[str] = []

    for outcome in result.outcomes:
        prior = baseline_status.get(outcome.pattern_id)
        if prior == "error" or prior is None:
            continue
        if outcome.status == "leaked" and prior == "blocked":
            new_leaks.append(outcome.pattern_id)
        elif outcome.status == "blocked" and prior == "leaked":
            fixed.append(outcome.pattern_id)
        elif outcome.status == "error" and prior in ("blocked", "leaked"):
            new_errors.append(outcome.pattern_id)

    baseline_score = baseline["score"]
    score = result.score
    score_delta = score - baseline_score

    regressed = False
    if max_drop is not None:
        regressed = score < baseline_score - max_drop

    return BaselineComparison(
        baseline_score=baseline_score,
        baseline_started_at=baseline.get("started_at"),
        score=score,
        score_delta=score_delta,
        new_leaks=new_leaks,
        fixed=fixed,
        new_errors=new_errors,
        max_drop=max_drop,
        regressed=regressed,
    )
