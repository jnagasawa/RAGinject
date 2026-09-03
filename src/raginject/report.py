"""Result output formatting (text/json).

The JSON shape produced here is frozen: existing keys never change meaning
or disappear within a `schema_version`. `result_to_dict()` is kept separate
from `format_json()` so future regression detection (Milestone 3) can
consume a dict directly instead of re-parsing JSON text.
"""

import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .core import AttackOutcome, Result
from .errors import ConfigurationError

#: Schema version stamped into JSON reports, so future regression detection
#: can tell which report format it is comparing against. v2 added the
#: top-level "mode" ("a"/"b") and "corpus_injector_description" keys when
#: corpus injection (mode A) was implemented.
REPORT_SCHEMA_VERSION = 2


@dataclass
class ReportOptions:
    #: Truncate `answer` in reports to this many characters. `None` or 0
    #: disables truncation entirely. CI logs are often public, and a leaked
    #: system prompt would otherwise land in one.
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
    """Convert a Result into the frozen report dict shape. Never includes
    anything that isn't already on Result/AttackOutcome - no target
    secrets, ever."""
    if options is None:
        options = ReportOptions()

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "raginject_version": result.raginject_version,
        "started_at": result.started_at,
        "target_description": result.target_description,
        "pattern_count": result.pattern_count,
        "mode": result.mode,
        "corpus_injector_description": result.corpus_injector_description,
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


#: Width the `failed:` id list wraps at. The full list is always printed -
#: the ids are the actionable output of a failing gate, and they are cheap
#: (a few words each) - so it is wrapped rather than truncated.
_FAILED_IDS_WRAP_WIDTH = 78

#: How many individual outcomes the non-verbose report details. Unlike the
#: id list, each of these costs 2-3 lines, so a 52-pattern total failure
#: would bury the summary. The header, the per-category breakdown and the
#: complete `failed:` list above already say *what* failed; this section
#: only has to show *why*, and a sample does that. `--verbose` lifts the cap.
_MAX_DETAILED_OUTCOMES = 10


def _wrap_failed_ids(failed_ids: List[str]) -> List[str]:
    """Render the complete `failed:` id list, wrapped and indented.

    Not truncated: when a gate fails, these ids are what the user acts on,
    and a CI log that names only the first few forces a second, verbose run
    to learn the rest.
    """
    prefix = "failed: "
    indent = " " * len(prefix)
    lines: List[str] = []
    current = prefix
    for index, pattern_id in enumerate(failed_ids):
        piece = pattern_id + ("," if index < len(failed_ids) - 1 else "")
        if current not in (prefix, indent) and (
            len(current) + 1 + len(piece) > _FAILED_IDS_WRAP_WIDTH
        ):
            lines.append(current)
            current = indent + piece
        else:
            current = current + (" " if current.endswith(",") else "") + piece
    lines.append(current)
    return lines


@register_formatter("text")
def format_text(result: Result, options: "ReportOptions" = None) -> str:
    """Render `result` as a short human-readable report.

    By default only `leaked`/`error` outcomes are listed individually -
    those are what a user must act on - and that list is capped. Every
    failed id is still named in full above it. `options.verbose=True` lists
    every outcome, uncapped, including `blocked` ones and their answers.
    """
    if options is None:
        options = ReportOptions()

    mode_suffix = f"  mode: {result.mode}"
    if result.mode == "a" and result.corpus_injector_description:
        mode_suffix += f" (corpus injector: {result.corpus_injector_description})"

    lines: List[str] = []
    lines.append(f"raginject report - target: {result.target_description}{mode_suffix}")
    lines.append(f"patterns: {result.pattern_count}  started_at: {result.started_at}")
    lines.append(
        f"score: {result.score:.2f}  "
        f"blocked={result.blocked_count} leaked={result.leaked_count} "
        f"error={result.error_count}"
    )

    category_counts = result.category_counts
    if category_counts:
        lines.append("")
        lines.append("by category:")
        name_width = max(len(name) for name in category_counts)
        for category, counts in category_counts.items():
            scored = counts["blocked"] + counts["leaked"]
            detail = f"{counts['blocked']}/{scored} blocked"
            if counts["error"]:
                detail += f", {counts['error']} error"
            lines.append(f"  {category:<{name_width}}  {detail}")

    if result.failed_ids:
        lines.append("")
        if result.leaked_count == result.scored_count:
            # Naming all of them adds nothing the breakdown above hasn't
            # already said, and at 52 patterns it costs ~20 lines.
            lines.append(
                f"failed: all {result.scored_count} scoreable patterns "
                f"(see the breakdown above)"
            )
        else:
            lines.extend(_wrap_failed_ids(result.failed_ids))

    outcomes_to_list = (
        result.outcomes
        if options.verbose
        else [o for o in result.outcomes if o.status in ("leaked", "error")]
    )

    if not outcomes_to_list:
        lines.append("")
        lines.append(f"all {result.scored_count} attacks blocked.")
        return "\n".join(lines).rstrip() + "\n"

    hidden = 0
    if not options.verbose and len(outcomes_to_list) > _MAX_DETAILED_OUTCOMES:
        hidden = len(outcomes_to_list) - _MAX_DETAILED_OUTCOMES
        outcomes_to_list = outcomes_to_list[:_MAX_DETAILED_OUTCOMES]

    lines.append("")
    for outcome in outcomes_to_list:
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

    if hidden:
        lines.append(
            f"... and {hidden} more (every id is listed above; "
            f"run with --verbose for all details)"
        )

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
