"""Helpers shared by the framework integrations."""

from typing import Any, Callable, List, Optional

from ..errors import ConfigurationError, TargetError


def reject_context(context: Optional[List[str]], target_name: str, injector: str):
    """These targets are question-only: they cannot be handed documents
    directly, so a non-empty `context` is a setup mistake, not a query failure."""
    if context:
        raise ConfigurationError(
            f"{target_name} is question-only and cannot receive injected context "
            "(this attack pattern needs a non-empty context). Use mode A: pass a "
            f"corpus injector ({injector}) so the document is written into your "
            "real store and retrieved by your own pipeline."
        )


def call_wrapped(fn: Callable[[], Any], target_name: str) -> Any:
    """Run a call into the user's framework object. Raginject's own errors pass
    through; anything else becomes a TargetError so one failing query is an
    "error" row instead of aborting the run."""
    try:
        return fn()
    except (ConfigurationError, TargetError):
        raise
    except Exception as exc:
        raise TargetError(
            f"{target_name}: query failed: {type(exc).__name__}: {exc}"
        ) from exc
