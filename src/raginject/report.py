"""Result output formatting (text/json).

The JSON shape produced here is frozen: existing keys never change meaning
or disappear within a `schema_version`. `result_to_dict()` is kept separate
from `format_json()` so future regression detection (Milestone 3) can
consume a dict directly instead of re-parsing JSON text.
"""

import html as _html
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

from .core import AttackOutcome, Result
from .errors import ConfigurationError

if TYPE_CHECKING:
    from .baseline import BaselineComparison

#: Schema version stamped into JSON reports, so future regression detection
#: can tell which report format it is comparing against. v2 added the
#: top-level "mode" ("a"/"b") and "corpus_injector_description" keys when
#: corpus injection (mode A) was implemented. v3 added the top-level
#: "baseline" key (null unless a --baseline comparison was made).
REPORT_SCHEMA_VERSION = 3

#: Plain ANSI SGR codes. report.py stays click-free on purpose (it is the
#: layer the CLI and any future consumer share), so these are hand-rolled
#: rather than pulled from click's color helpers.
_ANSI_RED = "\x1b[31m"
_ANSI_YELLOW = "\x1b[33m"
_ANSI_GREEN = "\x1b[32m"
_ANSI_RESET = "\x1b[0m"

_STATUS_COLOR = {
    "leaked": _ANSI_RED,
    "error": _ANSI_YELLOW,
    "blocked": _ANSI_GREEN,
}


def _colorize(text: str, code: str, *, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{code}{text}{_ANSI_RESET}"


@dataclass
class ReportOptions:
    #: Truncate `answer` in reports to this many characters. `None` or 0
    #: disables truncation entirely. CI logs are often public, and a leaked
    #: system prompt would otherwise land in one.
    max_answer_chars: Optional[int] = 2000
    verbose: bool = False
    #: Set when the CLI was given --baseline; carries the comparison so the
    #: formatter can render it. `TYPE_CHECKING`-only import: `baseline.py`
    #: imports `REPORT_SCHEMA_VERSION` from this module lazily (inside a
    #: function) precisely so this module can reference `BaselineComparison`
    #: for a type hint without a real circular import at runtime.
    baseline_comparison: Optional["BaselineComparison"] = None
    #: Colorize `format_text`'s `[STATUS]` labels and `REGRESSED`. Defaults
    #: to False so every existing caller of `format_text`/`ReportOptions`
    #: keeps working unchanged - report.py does no TTY/env detection itself,
    #: that's the CLI's job (see cli.py's --color/--no-color resolution).
    color: bool = False


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

    comparison = options.baseline_comparison
    baseline_dict = (
        None
        if comparison is None
        else {
            "score": comparison.baseline_score,
            "started_at": comparison.baseline_started_at,
            "score_delta": comparison.score_delta,
            "max_drop": comparison.max_drop,
            "regressed": comparison.regressed,
            "new_leaks": comparison.new_leaks,
            "fixed": comparison.fixed,
            "new_errors": comparison.new_errors,
        }
    )

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
        "baseline": baseline_dict,
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


def _wrap_id_list(ids: List[str], *, prefix: str) -> List[str]:
    """Render a complete id list under `prefix`, wrapped and indented.

    Not truncated: these ids (a failing gate's `failed:` list, or a
    baseline comparison's `new leaks:`/`fixed:`/`new errors:` lines) are
    what the user acts on, and a CI log that names only the first few
    forces a second, verbose run to learn the rest.
    """
    indent = " " * len(prefix)
    lines: List[str] = []
    current = prefix
    for index, pattern_id in enumerate(ids):
        piece = pattern_id + ("," if index < len(ids) - 1 else "")
        if current not in (prefix, indent) and (
            len(current) + 1 + len(piece) > _FAILED_IDS_WRAP_WIDTH
        ):
            lines.append(current)
            current = indent + piece
        else:
            current = current + (" " if current.endswith(",") else "") + piece
    lines.append(current)
    return lines


def _wrap_failed_ids(failed_ids: List[str]) -> List[str]:
    return _wrap_id_list(failed_ids, prefix="failed: ")


def _outcomes_to_render(result: Result, options: "ReportOptions"):
    """Pick which outcomes a report body should detail, and how many were
    hidden by the `_MAX_DETAILED_OUTCOMES` cap.

    Shared by `format_text`/`format_markdown`/`format_html`: by default only
    `leaked`/`error` outcomes are listed individually - those are what a
    user must act on - and that list is capped unless `options.verbose` is
    set, in which case every outcome (including `blocked`) is returned
    uncapped.

    Returns `(outcomes_to_render, hidden_count)`.
    """
    outcomes = (
        result.outcomes
        if options.verbose
        else [o for o in result.outcomes if o.status in ("leaked", "error")]
    )

    hidden = 0
    if not options.verbose and len(outcomes) > _MAX_DETAILED_OUTCOMES:
        hidden = len(outcomes) - _MAX_DETAILED_OUTCOMES
        outcomes = outcomes[:_MAX_DETAILED_OUTCOMES]

    return outcomes, hidden


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

    outcomes_to_list, hidden = _outcomes_to_render(result, options)

    if not outcomes_to_list:
        lines.append("")
        lines.append(f"all {result.scored_count} attacks blocked.")
    else:
        lines.append("")
        for outcome in outcomes_to_list:
            answer, truncated = _truncate_answer(outcome.answer, options)
            status_label = _colorize(
                f"[{outcome.status.upper()}]",
                _STATUS_COLOR.get(outcome.status, ""),
                enabled=options.color,
            )
            lines.append(f"{status_label} {outcome.pattern_id} ({outcome.category})")
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

    comparison = options.baseline_comparison
    if comparison is not None:
        lines.append("")
        if comparison.max_drop is None:
            drop_note = "no --max-drop: not gating"
        else:
            # `:g`, not the `:.2f` used for scores: max_drop is a threshold
            # the user typed, and rounding `--max-drop 0.005` to "0.01" in
            # the report would misreport why a gate did or didn't fire.
            drop_note = f"max-drop {comparison.max_drop:g}"
        status_suffix = (
            " " + _colorize("REGRESSED", _ANSI_RED, enabled=options.color)
            if comparison.regressed
            else ""
        )
        lines.append(
            f"baseline: score {comparison.baseline_score:.2f} -> "
            f"{comparison.score:.2f} ({comparison.score_delta:+.2f}, "
            f"{drop_note}){status_suffix}"
        )
        if comparison.new_leaks:
            lines.extend(_wrap_id_list(comparison.new_leaks, prefix="  new leaks: "))
        if comparison.fixed:
            lines.extend(_wrap_id_list(comparison.fixed, prefix="  fixed:     "))
        if comparison.new_errors:
            lines.extend(_wrap_id_list(comparison.new_errors, prefix="  new errors: "))

    return "\n".join(lines).rstrip() + "\n"


_BACKTICK_RUN = re.compile(r"`+")


def _fence_for(content: str) -> str:
    """Return a backtick fence long enough to safely wrap `content`.

    CommonMark requires a closing code-fence to be at least as long as the
    longest run of backticks inside the fenced content, or that run would
    be read as the closing fence itself. 4 is the floor (one longer than
    the plain triple-backtick fences most Markdown content uses), so a
    fence produced here never collides with ordinary fenced content either.
    """
    longest = max((len(run) for run in _BACKTICK_RUN.findall(content)), default=0)
    return "`" * max(4, longest + 1)


def _md_code_block(content: str) -> str:
    fence = _fence_for(content)
    return f"{fence}\n{content}\n{fence}"


@register_formatter("markdown")
def format_markdown(result: Result, options: "ReportOptions" = None) -> str:
    """Render `result` as plain, universal Markdown - headers, bold, `code`
    spans, and fenced code blocks only. No tables (avoids pipe-escaping
    edge cases), and no fields `format_text` doesn't already show.
    """
    if options is None:
        options = ReportOptions()

    mode_suffix = f"mode: {result.mode}"
    if result.mode == "a" and result.corpus_injector_description:
        mode_suffix += f" (corpus injector: {result.corpus_injector_description})"

    lines: List[str] = []
    lines.append("# raginject report")
    lines.append("")
    lines.append(f"**target:** {result.target_description}  {mode_suffix}")
    lines.append(
        f"**patterns:** {result.pattern_count}  **started at:** {result.started_at}"
    )
    lines.append("")
    lines.append(
        f"**score:** {result.score:.2f}  "
        f"(blocked={result.blocked_count} leaked={result.leaked_count} "
        f"error={result.error_count})"
    )

    category_counts = result.category_counts
    if category_counts:
        lines.append("")
        lines.append("## By category")
        lines.append("")
        for category, counts in category_counts.items():
            scored = counts["blocked"] + counts["leaked"]
            detail = f"{counts['blocked']}/{scored} blocked"
            if counts["error"]:
                detail += f", {counts['error']} error"
            lines.append(f"- `{category}`: {detail}")

    if result.failed_ids:
        lines.append("")
        lines.append("## Failed")
        lines.append("")
        if result.leaked_count == result.scored_count:
            lines.append(
                f"failed: all {result.scored_count} scoreable patterns "
                f"(see the breakdown above)"
            )
        else:
            lines.append(
                ", ".join(f"`{pattern_id}`" for pattern_id in result.failed_ids)
            )

    outcomes_to_list, hidden = _outcomes_to_render(result, options)

    lines.append("")
    lines.append("## Outcomes")
    lines.append("")
    if not outcomes_to_list:
        lines.append(f"all {result.scored_count} attacks blocked.")
    else:
        for outcome in outcomes_to_list:
            answer, truncated = _truncate_answer(outcome.answer, options)
            status_label = outcome.status.upper()
            lines.append(
                f"### **{status_label}** `{outcome.pattern_id}` (`{outcome.category}`)"
            )
            lines.append("")
            if outcome.status == "error":
                lines.append("error:")
                lines.append("")
                lines.append(_md_code_block(outcome.error or ""))
            else:
                lines.append(f"reason: {outcome.verdict_reason}")
                if options.verbose:
                    suffix = " (truncated)" if truncated else ""
                    lines.append("")
                    lines.append(f"answer{suffix}:")
                    lines.append("")
                    lines.append(_md_code_block(answer))
            lines.append("")

        if hidden:
            lines.append(
                f"... and {hidden} more (every id is listed above; "
                f"run with --verbose for all details)"
            )

    comparison = options.baseline_comparison
    if comparison is not None:
        lines.append("")
        lines.append("## Baseline")
        lines.append("")
        if comparison.max_drop is None:
            drop_note = "no --max-drop: not gating"
        else:
            drop_note = f"max-drop {comparison.max_drop:g}"
        status_suffix = " **REGRESSED**" if comparison.regressed else ""
        lines.append(
            f"baseline: score {comparison.baseline_score:.2f} -> "
            f"{comparison.score:.2f} ({comparison.score_delta:+.2f}, "
            f"{drop_note}){status_suffix}"
        )
        if comparison.new_leaks:
            lines.append("")
            lines.append(
                "- new leaks: "
                + ", ".join(f"`{pattern_id}`" for pattern_id in comparison.new_leaks)
            )
        if comparison.fixed:
            lines.append(
                "- fixed: "
                + ", ".join(f"`{pattern_id}`" for pattern_id in comparison.fixed)
            )
        if comparison.new_errors:
            lines.append(
                "- new errors: "
                + ", ".join(f"`{pattern_id}`" for pattern_id in comparison.new_errors)
            )

    return "\n".join(lines).rstrip() + "\n"


_HTML_STYLE = """\
    body { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, \
monospace; background: #1e1e1e; color: #d4d4d4; margin: 2rem; }
    h1, h2, h3 { color: #f0f0f0; }
    pre { white-space: pre-wrap; word-wrap: break-word; background: #262626; \
padding: 0.75rem; border-radius: 4px; }
    .status { font-weight: bold; padding: 0.1rem 0.4rem; border-radius: 3px; }
    .status.leaked { background: #5a1d1d; color: #ff8080; }
    .status.error { background: #5a4a1d; color: #ffd480; }
    .status.blocked { background: #1d5a2a; color: #80ff9a; }
    .regressed { color: #ff8080; font-weight: bold; }
    .outcome { border-top: 1px solid #3a3a3a; padding-top: 0.75rem; \
margin-top: 0.75rem; }
"""


@register_formatter("html")
def format_html(result: Result, options: "ReportOptions" = None) -> str:
    """Render `result` as a single self-contained HTML document - inline
    CSS only, no external stylesheets/scripts/fonts.

    Every free-form string interpolated into the page goes through
    `html.escape()` first: `answer`, `verdict_reason`, `error`,
    `target_description`, `corpus_injector_description`, and (defensively)
    `pattern_id`/`category` are all either literal prompt-injection payloads
    or raw model output, so skipping escaping would turn a raginject HTML
    report into an XSS vector the moment it's opened in a browser.
    """
    if options is None:
        options = ReportOptions()

    esc = _html.escape

    mode_suffix = f"mode: {esc(result.mode)}"
    if result.mode == "a" and result.corpus_injector_description:
        mode_suffix += f" (corpus injector: {esc(result.corpus_injector_description)})"

    body: List[str] = []
    body.append("<h1>raginject report</h1>")
    body.append(
        f"<p><strong>target:</strong> {esc(str(result.target_description))}  "
        f"{mode_suffix}</p>"
    )
    body.append(
        f"<p><strong>patterns:</strong> {result.pattern_count}  "
        f"<strong>started at:</strong> {esc(str(result.started_at))}</p>"
    )
    body.append(
        f"<p><strong>score:</strong> {result.score:.2f} "
        f"(blocked={result.blocked_count} leaked={result.leaked_count} "
        f"error={result.error_count})</p>"
    )

    category_counts = result.category_counts
    if category_counts:
        body.append("<h2>By category</h2>")
        body.append("<ul>")
        for category, counts in category_counts.items():
            scored = counts["blocked"] + counts["leaked"]
            detail = f"{counts['blocked']}/{scored} blocked"
            if counts["error"]:
                detail += f", {counts['error']} error"
            body.append(f"<li><code>{esc(category)}</code>: {detail}</li>")
        body.append("</ul>")

    if result.failed_ids:
        body.append("<h2>Failed</h2>")
        if result.leaked_count == result.scored_count:
            body.append(
                f"<p>failed: all {result.scored_count} scoreable patterns "
                f"(see the breakdown above)</p>"
            )
        else:
            ids_html = ", ".join(
                f"<code>{esc(pattern_id)}</code>" for pattern_id in result.failed_ids
            )
            body.append(f"<p>{ids_html}</p>")

    outcomes_to_list, hidden = _outcomes_to_render(result, options)

    body.append("<h2>Outcomes</h2>")
    if not outcomes_to_list:
        body.append(f"<p>all {result.scored_count} attacks blocked.</p>")
    else:
        for outcome in outcomes_to_list:
            answer, truncated = _truncate_answer(outcome.answer, options)
            status = outcome.status
            body.append('<div class="outcome">')
            body.append(
                f'<h3><span class="status {esc(status)}">{esc(status.upper())}</span> '
                f"<code>{esc(outcome.pattern_id)}</code> "
                f"(<code>{esc(outcome.category)}</code>)</h3>"
            )
            if status == "error":
                body.append(f"<p>error:</p><pre>{esc(outcome.error or '')}</pre>")
            else:
                body.append(f"<p>reason: {esc(outcome.verdict_reason or '')}</p>")
                if options.verbose:
                    suffix = " (truncated)" if truncated else ""
                    body.append(f"<p>answer{suffix}:</p><pre>{esc(answer)}</pre>")
            body.append("</div>")

        if hidden:
            body.append(
                f"<p>... and {hidden} more (every id is listed above; "
                f"run with --verbose for all details)</p>"
            )

    comparison = options.baseline_comparison
    if comparison is not None:
        body.append("<h2>Baseline</h2>")
        if comparison.max_drop is None:
            drop_note = "no --max-drop: not gating"
        else:
            drop_note = f"max-drop {comparison.max_drop:g}"
        status_suffix = (
            ' <span class="regressed">REGRESSED</span>' if comparison.regressed else ""
        )
        body.append(
            f"<p>baseline: score {comparison.baseline_score:.2f} -> "
            f"{comparison.score:.2f} ({comparison.score_delta:+.2f}, "
            f"{drop_note}){status_suffix}</p>"
        )
        if comparison.new_leaks:
            ids_html = ", ".join(
                f"<code>{esc(pattern_id)}</code>" for pattern_id in comparison.new_leaks
            )
            body.append(f"<p>new leaks: {ids_html}</p>")
        if comparison.fixed:
            ids_html = ", ".join(
                f"<code>{esc(pattern_id)}</code>" for pattern_id in comparison.fixed
            )
            body.append(f"<p>fixed: {ids_html}</p>")
        if comparison.new_errors:
            ids_html = ", ".join(
                f"<code>{esc(pattern_id)}</code>"
                for pattern_id in comparison.new_errors
            )
            body.append(f"<p>new errors: {ids_html}</p>")

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        f"<title>raginject report - {esc(str(result.target_description))}</title>\n"
        f"<style>\n{_HTML_STYLE}</style>\n"
        "</head>\n"
        "<body>\n" + "\n".join(body) + "\n</body>\n</html>\n"
    )


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
