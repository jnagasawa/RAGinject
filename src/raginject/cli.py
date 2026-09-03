"""CLI entry point: thin wrapper over core.py.

Exit codes:
- 0: score >= --min-score, OR --min-score was not given at all (a warning
     is printed to stderr in that case: no gate is in effect)
- 1: --min-score was given AND the score is below it. This is the only
     path to exit 1.
- 2: any ConfigurationError (bad flags, unknown judge, zero patterns, ...),
     OR zero scoreable outcomes (every row errored - the target was never
     reached, so returning 1 would misreport connectivity failure as a
     security failure: reporting a run that never reached the target as a
     security failure would be misleading), OR an unexpected exception (set
     RAGINJECT_DEBUG=1 to see the traceback instead).
"""

import importlib
import os
import sys
from typing import Optional, Tuple

import click

from ._version import __version__
from .attacks.loader import load_default_patterns, load_patterns
from .core import Runner
from .errors import ConfigurationError, RagInjectError
from .report import ReportOptions, available_formatters, get_formatter
from .resolve import ensure_cwd_importable, resolve_target_spec

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
):
    """Run attack patterns against a target and report the result.

    Exit codes: 0 = passed (score >= --min-score, or no --min-score given);
    1 = score below --min-score; 2 = configuration error, target never
    reached, or an unexpected crash.
    """
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

        runner = Runner(
            target,
            judge_override=judge_override,
            verify_leaks_judge=verify_leaks_judge,
        )
        _load_all_patterns(runner, patterns, no_default_patterns)
        try:
            result = runner.run()
        finally:
            closer = getattr(target, "close", None)
            if callable(closer):
                closer()

        options = ReportOptions(max_answer_chars=max_answer_chars, verbose=verbose)
        rendered = formatter(result, options)
        click.echo(rendered)

        if not result.has_scoreable_outcomes:
            click.echo(
                "error: no scoreable outcomes (every attack errored - the "
                "target was never successfully reached)",
                err=True,
            )
            sys.exit(2)

        if min_score is None:
            click.echo(
                "warning: --min-score not set; this run does not gate (exit 0 "
                "regardless of score)",
                err=True,
            )
            sys.exit(0)

        sys.exit(0 if result.score >= min_score else 1)

    except ConfigurationError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)
    except SystemExit:
        raise
    except Exception as exc:
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
