"""FunctionTarget: wrap a Python callable as a Target."""

import inspect
import warnings
from typing import Any, Callable, List, Optional

from .._async import run_coroutine_blocking
from ..errors import ConfigurationError
from ..target import QueryResult, Target, normalize_query_result


class FunctionTarget(Target):
    """Wrap a plain Python callable as a Target.

    How `context` is passed to `fn` is decided once, in `__init__`, by
    inspecting `fn`'s signature - resolved at construction time rather than
    per call, so the call style is fixed and consistent across every query
    made to this target:

    1. a parameter literally named `context` -> called as
       `fn(question, context=context)`
    2. a `**kwargs` parameter -> called as `fn(question, context=context)`
    3. a second positional parameter -> called as `fn(question, context)`
       positionally (a one-time warning is emitted at construction time,
       since e.g. `def rag(question, top_k=5)` would otherwise silently
       bind context to `top_k`)
    4. otherwise, `fn` is treated as question-only: `fn(question)`. If a
       non-empty `context` is ever requested against a question-only
       function, `query` raises `ConfigurationError` rather than silently
       dropping the context.

    When `context` is empty (`None` or `[]`), `fn` is always called with
    just `question`, regardless of which style was detected above.

    If `fn` (or an `async def` it wraps) returns an awaitable, it is
    driven to completion via `run_coroutine_blocking`.
    """

    def __init__(self, fn: Callable[..., Any]):
        self.fn = fn
        self._call_style, self._positional_param_name = self._detect_call_style(fn)

    @staticmethod
    def _detect_call_style(fn: Callable[..., Any]):
        try:
            sig = inspect.signature(fn)
        except (ValueError, TypeError):
            # Some callables (certain builtins/C extensions) don't expose a
            # signature. Fall back to the safe, conservative style.
            return "question_only", None

        params = list(sig.parameters.values())

        has_context_name = any(
            p.name == "context"
            and p.kind
            in (
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            )
            for p in params
        )
        if has_context_name:
            return "context_kw", None

        has_var_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)
        if has_var_kwargs:
            return "kwargs", None

        positional = [
            p
            for p in params
            if p.kind
            in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
        if len(positional) >= 2:
            second = positional[1]
            warnings.warn(
                f"FunctionTarget: {fn!r} has no parameter named 'context' and no "
                f"**kwargs; binding context positionally to parameter {second.name!r}. "
                "Define your function as `def rag(question, context=None): ...` to "
                "avoid ambiguity.",
                stacklevel=3,  # point at the caller's FunctionTarget(...) line
            )
            return "positional", second.name

        return "question_only", None

    def query(self, question: str, context: Optional[List[str]] = None) -> QueryResult:
        if context:
            if self._call_style in ("context_kw", "kwargs"):
                raw = self.fn(question, context=context)
            elif self._call_style == "positional":
                raw = self.fn(question, context)
            else:
                raise ConfigurationError(
                    "this target's function does not accept a 'context' argument, "
                    "but a non-empty context was requested for this attack pattern. "
                    "Define it as `def rag(question, context=None): ...` (or accept "
                    "**kwargs) to receive injected context."
                )
        elif self._call_style in ("context_kw", "kwargs"):
            # Pass the empty context through by name, so a function whose
            # `context` parameter has no default (`def rag(question, context)`)
            # is still callable for an uninjected query.
            raw = self.fn(question, context=context)
        else:
            # question_only, or a positional second parameter that is NOT named
            # `context` - passing an empty context positionally there would
            # clobber an unrelated argument (e.g. `def rag(question, top_k=5)`).
            raw = self.fn(question)

        if inspect.isawaitable(raw):
            raw = run_coroutine_blocking(raw)

        return normalize_query_result(raw, source="FunctionTarget")

    @property
    def target_description(self) -> str:
        name = getattr(self.fn, "__name__", None)
        return f"FunctionTarget({name})" if name else "FunctionTarget"
