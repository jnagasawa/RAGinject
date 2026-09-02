"""Result output formatting (text/json). See PLAN.md 7.

The JSON shape produced here is frozen (see PLAN.md's report section and
the Task 2 plan): existing keys never change meaning or disappear across a
schema_version. `result_to_dict()` is kept separate from `format_json()` so
future regression detection (Milestone 3) can consume a dict directly
instead of re-parsing JSON text.
"""

import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .core import AttackOutcome, Result
from .errors import ConfigurationError

#: Schema version stamped into JSON reports, so future regression detection
#: (Milestone 3) can tell which report format it is comparing against.
REPORT_SCHEMA_VERSION = 1


@dataclass
class ReportOptions:
    #: Truncate `answer` in reports to this many characters. `None` or 0
    #: disables truncation entirely (see decision E: CI logs are often
    #: public, and a leaked system prompt would otherwise land in one).
    max_answer_chars: Optional[int] = 2000
    verbose: bool = False


def _truncate_answer(answer: str, options: ReportOptions):
    limit = options.max_answer_chars
    if limit and len(answer) > limit:
        return answer[:limit], True
    return answer, False


def _outcome_to_dict(outcome: AttackOutcome, options: ReportOptions) -> Dict[str, Any]:
    answer, truncated = _truncate_answer(outcome.answer, options)
    return {
        "pattern_id": outcome.pattern_id,
        "category": outcome.category,
        "status": outcome.status,
        "question": outcome.question,
        "injected_content": outcome.injected_content,
        "answer": answer,
        "answer_truncated": truncated,
        "sources": outcome.sources,
        "verdict_reason": outcome.verdict_reason,
        "error": outcome.error,
        "duration_ms": outcome.duration_ms,
    }


def result_to_dict(result: Result, options: "ReportOptions" = None) -> Dict[str, Any]:
    """Convert a Result into the frozen report dict shape (see PLAN.md /
    the Task 2 plan for the exact JSON shape). Never includes anything that
    isn't already on Result/AttackOutcome - no target secrets, ever."""
    if options is None:
        options = ReportOptions()

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "raginject_version": result.raginject_version,
        "started_at": result.started_at,
        "target_description": result.target_description,
        "pattern_count": result.pattern_count,
        "score": result.score,
        "counts": {
            "blocked": result.blocked_count,
            "leaked": result.leaked_count,
            "error": result.error_count,
            "scored": result.scored_count,
        },
        "outcomes": [_outcome_to_dict(o, options) for o in result.outcomes],
    }


_FORMATTERS: Dict[str, Callable[..., str]] = {}


def register_formatter(name: str):
    """Decorator: register a report formatter under `name`, so it can be
    selected with `--output <name>`.

    Shaped like `register_judge` on purpose - both extension points work the
    same way. Re-registering a name overwrites the previous formatter.

        @register_formatter("html")
        def format_html(result, options=None): ...
    """

    def _decorator(formatter: Callable[..., str]) -> Callable[..., str]:
        _FORMATTERS[name] = formatter
        return formatter

    return _decorator


@register_formatter("json")
def format_json(result: Result, options: "ReportOptions" = None) -> str:
    """Render `result` as JSON. `ensure_ascii=False` so non-ASCII (e.g.
    Japanese) answers/questions are preserved rather than \\uXXXX-escaped."""
    return json.dumps(result_to_dict(result, options), indent=2, ensure_ascii=False)


@register_formatter("text")
def format_text(result: Result, options: "ReportOptions" = None) -> str:
    """Render `result` as a short human-readable report."""
    if options is None:
        options = ReportOptions()

    lines: List[str] = []
    lines.append(f"raginject report - target: {result.target_description}")
    lines.append(f"patterns: {result.pattern_count}  started_at: {result.started_at}")
    lines.append(
        f"score: {result.score:.2f}  "
        f"blocked={result.blocked_count} leaked={result.leaked_count} "
        f"error={result.error_count}"
    )
    if result.failed_ids:
        lines.append(f"failed: {', '.join(result.failed_ids)}")
    lines.append("")

    for outcome in result.outcomes:
        answer, truncated = _truncate_answer(outcome.answer, options)
        lines.append(
            f"[{outcome.status.upper()}] {outcome.pattern_id} ({outcome.category})"
        )
        if outcome.status == "error":
            lines.append(f"  error: {outcome.error}")
        else:
            lines.append(f"  reason: {outcome.verdict_reason}")
            if options.verbose:
                suffix = " (truncated)" if truncated else ""
                lines.append(f"  answer{suffix}: {answer}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def get_formatter(name: str) -> Callable[..., str]:
    formatter = _FORMATTERS.get(name)
    if formatter is None:
        available = ", ".join(available_formatters())
        raise ConfigurationError(
            f"unknown output format {name!r}; available: {available}"
        )
    return formatter


def available_formatters() -> List[str]:
    return sorted(_FORMATTERS.keys())
