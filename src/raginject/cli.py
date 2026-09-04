"""CLI entry point: thin wrapper over core.py.

Exit codes:
- 0: an explicitly requested gate (--min-score and/or --max-drop) passed,
     OR neither gate was given at all (a warning is printed to stderr in
     that case: no gate is in effect)
- 1: --min-score was given and the score is below it, OR --max-drop was
     given and the baseline comparison regressed. This is the only path to
     exit 1.
- 2: any ConfigurationError (bad flags, unknown judge, zero patterns,
     a --baseline that doesn't parse or doesn't match this run's pattern
     set/mode, ...), OR zero scoreable outcomes (every row errored - the
     target was never reached, so returning 1 would misreport connectivity
     failure as a security failure: reporting a run that never reached the
     target as a security failure would be misleading), OR an unexpected
     exception (set RAGINJECT_DEBUG=1 to see the traceback instead).
"""

import importlib
import os
import sys
from typing import Optional, Tuple

import click

from ._version import __version__
from .attacks.loader import load_default_patterns, load_patterns
from .baseline import check_comparable, compare, load_baseline
from .core import Runner
from .errors import ConfigurationError, RagInjectError
from .report import ReportOptions, available_formatters, get_formatter
from .resolve import (
    ensure_cwd_importable,
    resolve_corpus_injector_spec,
    resolve_target_spec,
)

_HTTP_DEFAULTS = {
    "target_method": "POST",
    "request_key": "question",
    "request_context_key": "context",
    "response_answer_key": "answer",
    "response_sources_key": "sources",
    "timeout": 30.0,
}


@click.group(context_settings={"auto_envvar_prefix": "RAGINJECT"})
@click.version_option(__version__, prog_name="raginject")
def main():
    """raginject: evaluate a RAG pipeline's resistance to indirect prompt injection."""


def _parse_header(value: str) -> Tuple[str, str]:
    if ":" not in value:
        raise ConfigurationError(f"invalid --header {value!r}; expected 'Name: value'")
    name, _, val = value.partition(":")
    return name.strip(), val.strip()


def _build_target(
    *,
    target_module: Optional[str],
    target_url: Optional[str],
    target_method: Optional[str],
    request_key: Optional[str],
    request_context_key: Optional[str],
    response_answer_key: Optional[str],
    response_sources_key: Optional[str],
    header: Tuple[str, ...],
    timeout: Optional[float],
):
    http_overrides = {
        "target_method": target_method,
        "request_key": request_key,
        "request_context_key": request_context_key,
        "response_answer_key": response_answer_key,
        "response_sources_key": response_sources_key,
        "timeout": timeout,
    }
    http_flags_given = (
        bool(target_url)
        or bool(header)
        or any(v is not None for v in http_overrides.values())
    )

    if target_module:
        if http_flags_given:
            raise ConfigurationError(
                "--target-module cannot be combined with HTTP-specific flags "
                "(--target-url/--header/--request-key/etc.); choose one target kind"
            )
        return resolve_target_spec(target_module)

    if target_url:
        from .adapters.http import HTTPTarget

        headers = dict(_parse_header(h) for h in header) if header else None
        return HTTPTarget(
            target_url,
            method=http_overrides["target_method"] or _HTTP_DEFAULTS["target_method"],
            request_key=http_overrides["request_key"] or _HTTP_DEFAULTS["request_key"],
            request_context_key=(
                http_overrides["request_context_key"]
                or _HTTP_DEFAULTS["request_context_key"]
            ),
            response_answer_key=(
                http_overrides["response_answer_key"]
                or _HTTP_DEFAULTS["response_answer_key"]
            ),
            response_sources_key=(
                http_overrides["response_sources_key"]
                or _HTTP_DEFAULTS["response_sources_key"]
            ),
            headers=headers,
            timeout=(
                http_overrides["timeout"]
                if http_overrides["timeout"] is not None
                else _HTTP_DEFAULTS["timeout"]
            ),
        )

    raise ConfigurationError("one of --target-module or --target-url is required")


def _load_all_patterns(
    runner: Runner, patterns: Tuple[str, ...], no_default_patterns: bool
) -> None:
    if not no_default_patterns:
        runner.load_patterns(None)
    for path in patterns:
        runner.load_patterns(path)


def _resolve_judge(name: str, *, model, provider, base_url):
    """Resolve a `--judge`/`--verify-leaks` name into a Judge instance.

    `llm_judge` is special-cased so `--judge-model`/`--judge-provider`/
    `--judge-base-url` can configure it without a plugin; any other name
    goes through the normal registry lookup (lazy-imported for built-ins,
    or registered by a `--plugin` module).
    """
    if name == "llm_judge":
        from .judges.llm_judge import LLMJudge

        return LLMJudge(model=model, provider=provider, base_url=base_url)

    from .judges import get_judge

    return get_judge(name)


def _warn_uncleaned_documents(runner: Optional[Runner]) -> None:
    """Print the leftover-document warning if `runner` got far enough to
    exist and ended the run with anything in `uncleaned_document_ids`.

    Called on every exit path out of `run` (success, a below-threshold
    score, and every error branch) - not just the success path - because a
    `CorpusInjector.remove` failure that surfaces as a ConfigurationError
    (or any other exception) must still be reported: an orphaned attack
    document in the user's corpus is exactly what this warning exists to
    surface, and it must not go missing just because the run also failed
    for some other reason.
    """
    if runner is None or not runner.uncleaned_document_ids:
        return
    click.echo(
        "warning: the corpus injector failed to remove "
        f"{len(runner.uncleaned_document_ids)} attack document(s); these "
        "were left in your corpus and must be deleted manually: "
        f"{', '.join(runner.uncleaned_document_ids)}",
        err=True,
    )


def _apply_plugins(plugin: Tuple[str, ...]) -> None:
    """Import each --plugin module so its @register_judge/@register_formatter
    decorators run. Explicit and opt-in: raginject never auto-discovers
    plugins, so one broken third-party package can't break every run."""
    if plugin:
        # Same rule as --target-module: a plugin living in the project the
        # user is running raginject from must be importable without them
        # having to pip-install it or set PYTHONPATH.
        ensure_cwd_importable()
    for module_name in plugin:
        try:
            importlib.import_module(module_name)
        except ImportError as exc:
            raise ConfigurationError(
                f"could not import --plugin {module_name!r}: {exc}"
            ) from exc
        except Exception as exc:
            raise ConfigurationError(
                f"--plugin {module_name!r} raised {type(exc).__name__} while "
                f"being imported: {exc}"
            ) from exc


@main.command()
@click.option("--target-module", default=None, help="module:attribute target spec")
@click.option("--target-url", default=None, help="HTTP endpoint URL")
@click.option("--target-method", default=None, help="default: POST")
@click.option("--request-key", default=None, help="default: question")
@click.option("--request-context-key", default=None, help="default: context")
@click.option("--response-answer-key", default=None, help="default: answer")
@click.option("--response-sources-key", default=None, help="default: sources")
@click.option("--header", multiple=True, help="'Name: value', repeatable")
@click.option("--timeout", default=None, type=float, help="default: 30.0")
@click.option("--patterns", multiple=True, help="pattern file/dir, repeatable")
@click.option("--no-default-patterns", is_flag=True, default=False)
@click.option("--plugin", multiple=True, help="module to import, repeatable")
@click.option("--output", default="text", help="text, json, or a registered formatter")
@click.option("--max-answer-chars", default=2000, show_default=True, type=int)
@click.option("--min-score", default=None, type=float)
@click.option("--verbose", is_flag=True, default=False)
@click.option(
    "--judge", default=None, help="judge name overriding every pattern's judge"
)
@click.option(
    "--verify-leaks",
    default=None,
    help="judge name used to re-judge only the rows the primary judge marked leaked",
)
@click.option("--judge-model", default=None, help="model name, llm_judge only")
@click.option(
    "--judge-provider", default=None, help="'openai' or 'anthropic', llm_judge only"
)
@click.option(
    "--judge-base-url", default=None, help="OpenAI-compatible endpoint, llm_judge only"
)
@click.option(
    "--corpus-injector",
    default=None,
    help="module:attribute CorpusInjector spec; enables corpus injection (mode A)",
)
@click.option(
    "--no-verify-retrieval",
    is_flag=True,
    default=False,
    help="don't error rows whose injected document wasn't in the target's sources "
    "(mode A only)",
)
@click.option(
    "--baseline",
    default=None,
    type=click.Path(),
    help="path to a JSON report from an earlier run, to compare this run against",
)
@click.option(
    "--max-drop",
    default=None,
    type=float,
    help="fail (exit 1) if the score drops below (baseline score - this) - "
    "requires --baseline",
)
def run(
    target_module,
    target_url,
    target_method,
    request_key,
    request_context_key,
    response_answer_key,
    response_sources_key,
    header,
    timeout,
    patterns,
    no_default_patterns,
    plugin,
    output,
    max_answer_chars,
    min_score,
    verbose,
    judge,
    verify_leaks,
    judge_model,
    judge_provider,
    judge_base_url,
    corpus_injector,
    no_verify_retrieval,
    baseline,
    max_drop,
):
    """Run attack patterns against a target and report the result.

    Exit codes: 0 = every requested gate passed (--min-score and/or
    --max-drop), or neither was given; 1 = --min-score not met or
    --max-drop's regression check failed; 2 = configuration error, target
    never reached, or an unexpected crash.
    """
    # Assigned once the target/injector are resolved and Runner() is
    # constructed - stays None if setup itself fails, so the except
    # handlers below can safely check it before warning about leftover
    # documents (there is nothing to have left behind if we never got
    # this far).
    runner: Optional[Runner] = None
    try:
        # Plugins first: a --plugin module may register the formatter that
        # --output names, so validating the format before importing them
        # would make plugin-provided formatters unreachable.
        _apply_plugins(plugin)

        if output not in available_formatters():
            raise ConfigurationError(
                f"unknown --output {output!r}; available: "
                f"{', '.join(available_formatters())}"
            )
        formatter = get_formatter(output)

        judge_flags_given = any(
            v is not None for v in (judge_model, judge_provider, judge_base_url)
        )
        if judge_flags_given and "llm_judge" not in (judge, verify_leaks):
            raise ConfigurationError(
                "--judge-model/--judge-provider/--judge-base-url only apply "
                "to llm_judge; pass --judge llm_judge or --verify-leaks "
                "llm_judge to use them"
            )

        judge_override = (
            _resolve_judge(
                judge,
                model=judge_model,
                provider=judge_provider,
                base_url=judge_base_url,
            )
            if judge is not None
            else None
        )
        verify_leaks_judge = (
            _resolve_judge(
                verify_leaks,
                model=judge_model,
                provider=judge_provider,
                base_url=judge_base_url,
            )
            if verify_leaks is not None
            else None
        )

        if no_verify_retrieval and not corpus_injector:
            # Meaningless in mode B (there is no retrieval step to verify),
            # and silently ignoring a flag the user passed is exactly the
            # failure the --target-module/HTTP-flags check above guards
            # against - so this is a hard error, not a no-op.
            raise ConfigurationError(
                "--no-verify-retrieval only applies to corpus injection mode; "
                "pass --corpus-injector to enable mode A"
            )

        if max_drop is not None and baseline is None:
            # Same "never silently ignore a flag" rule as
            # --no-verify-retrieval above: a --max-drop with nothing to
            # compare against would otherwise just be dropped on the floor.
            raise ConfigurationError(
                "--max-drop requires --baseline (there is nothing to compare "
                "the drop against)"
            )
        if max_drop is not None and max_drop < 0:
            raise ConfigurationError(f"--max-drop must be >= 0, got {max_drop!r}")

        # Loaded before the target is built (and thus before the user's
        # module is imported / any query is sent): a bad --baseline path
        # should fail fast, not after paying the cost of standing up the
        # target.
        baseline_report = load_baseline(baseline) if baseline is not None else None

        target = _build_target(
            target_module=target_module,
            target_url=target_url,
            target_method=target_method,
            request_key=request_key,
            request_context_key=request_context_key,
            response_answer_key=response_answer_key,
            response_sources_key=response_sources_key,
            header=header,
            timeout=timeout,
        )

        injector = (
            resolve_corpus_injector_spec(corpus_injector)
            if corpus_injector is not None
            else None
        )

        runner = Runner(
            target,
            judge_override=judge_override,
            verify_leaks_judge=verify_leaks_judge,
            corpus_injector=injector,
            verify_retrieval=not no_verify_retrieval,
        )
        _load_all_patterns(runner, patterns, no_default_patterns)

        if baseline_report is not None:
            # Comparability is checked before a single query is sent: a
            # mismatched baseline (different pattern set or mode) means
            # the two runs aren't measuring the same thing, and finding
            # that out only makes sense before spending real API money on
            # a run() that will be thrown away.
            comparability_warnings = check_comparable(
                baseline_report,
                pattern_ids=[p.id for p in runner.patterns],
                mode=runner.mode,
                target_description=target.target_description,
            )
            for warning_message in comparability_warnings:
                click.echo(warning_message, err=True)

        try:
            result = runner.run()
        finally:
            closer = getattr(target, "close", None)
            if callable(closer):
                closer()

        comparison = (
            compare(result, baseline_report, max_drop=max_drop)
            if baseline_report is not None
            else None
        )

        options = ReportOptions(
            max_answer_chars=max_answer_chars,
            verbose=verbose,
            baseline_comparison=comparison,
        )
        rendered = formatter(result, options)
        click.echo(rendered)

        _warn_uncleaned_documents(runner)

        if not result.has_scoreable_outcomes:
            click.echo(
                "error: no scoreable outcomes (every attack errored - the "
                "target was never successfully reached)",
                err=True,
            )
            sys.exit(2)

        if min_score is None and max_drop is None:
            click.echo(
                "warning: neither --min-score nor --max-drop is set; this run "
                "does not gate (exit 0 regardless of score)",
                err=True,
            )
            sys.exit(0)

        min_score_failed = min_score is not None and result.score < min_score
        regressed = comparison is not None and comparison.regressed
        sys.exit(1 if (min_score_failed or regressed) else 0)

    except ConfigurationError as exc:
        _warn_uncleaned_documents(runner)
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)
    except SystemExit:
        raise
    except Exception as exc:
        _warn_uncleaned_documents(runner)
        if os.environ.get("RAGINJECT_DEBUG"):
            raise
        click.echo(
            f"error: unexpected {type(exc).__name__}: {exc}; "
            "set RAGINJECT_DEBUG=1 for a traceback",
            err=True,
        )
        sys.exit(2)


@main.command()
@click.argument("paths", nargs=-1, required=True)
def validate(paths):
    """Validate one or more attack pattern files/directories."""
    try:
        for path in paths:
            loaded = load_patterns(path)
            click.echo(f"{path}: ok ({len(loaded)} pattern(s))")
    except RagInjectError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)
    except Exception as exc:
        if os.environ.get("RAGINJECT_DEBUG"):
            raise
        click.echo(
            f"error: unexpected {type(exc).__name__}: {exc}; "
            "set RAGINJECT_DEBUG=1 for a traceback",
            err=True,
        )
        sys.exit(2)


@main.command("list-patterns")
@click.option("--patterns", multiple=True, help="pattern file/dir, repeatable")
@click.option("--no-default-patterns", is_flag=True, default=False)
def list_patterns(patterns, no_default_patterns):
    """List available attack patterns (id / category / judge / description)."""
    try:
        # Merge exactly as `run` does (later wins, first position kept), so
        # this lists what would actually be executed - not duplicate ids.
        merged = {}
        if not no_default_patterns:
            for pattern in load_default_patterns():
                merged[pattern.id] = pattern
        for path in patterns:
            for pattern in load_patterns(path):
                merged[pattern.id] = pattern
        for pattern in merged.values():
            click.echo(
                f"{pattern.id}\t{pattern.category}\t"
                f"{pattern.success_criteria.type}\t{pattern.description}"
            )
    except RagInjectError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)
    except Exception as exc:
        if os.environ.get("RAGINJECT_DEBUG"):
            raise
        click.echo(
            f"error: unexpected {type(exc).__name__}: {exc}; "
            "set RAGINJECT_DEBUG=1 for a traceback",
            err=True,
        )
        sys.exit(2)


if __name__ == "__main__":
    main()
