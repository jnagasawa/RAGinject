"""Resolve a `module:attribute` spec into a Target or CorpusInjector instance.

`resolve_target_spec` (for `--target-module`) dispatch order matters (a
`Target` subclass may itself define `__call__`, so the `isinstance` check
for an already-built `Target` instance must come first, before the generic
`callable` check):

1. `obj` is already a `Target` instance -> use it directly
2. `obj` is a `Target` subclass -> instantiate it with zero arguments
3. `obj` is callable -> wrap it in `FunctionTarget`
4. otherwise -> `TargetResolutionError`

A zero-argument factory function (e.g. `def make_target(): ...`) is
indistinguishable from a zero-argument RAG function and is therefore *not*
supported - this is a deliberate simplification, not an oversight.

`resolve_corpus_injector_spec` (for `--corpus-injector`) shares the same
`module:attribute` import machinery via `_import_spec_attribute`, but its
dispatch is narrower - see its docstring for why there is no
bare-callable fallback.
"""

import importlib
import inspect
import os
import sys
from typing import Any

from .adapters.function import FunctionTarget
from .corpus import CorpusInjector
from .errors import TargetResolutionError
from .target import Target


def ensure_cwd_importable() -> str:
    """Put the current working directory on `sys.path` (idempotent).

    Without this, user code that lives in the project raginject is being run
    from - a target module, or a `--plugin` module - is only importable when
    the project happens to be pip-installed. Both entry points use this so
    they behave the same way.
    """
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    return cwd


def _import_spec_attribute(spec: str, *, what: str, example: str) -> Any:
    """Import `module.submodule:attribute[.attribute...]` and return the
    resolved attribute, without deciding what kind of object it must be -
    that decision is made by the caller (`resolve_target_spec`,
    `resolve_corpus_injector_spec`).

    Shared so both spec kinds get identical import behavior and error
    messages; `what` names the noun to use in those messages (e.g.
    "target spec", "corpus injector spec") and `example` supplies a
    kind-appropriate `'module:attribute'` example for the "invalid spec"
    message, so a corpus-injector typo isn't shown a Target example.
    """
    if ":" not in spec:
        raise TargetResolutionError(
            f"invalid {what} {spec!r}; expected 'module:attribute', e.g. {example}"
        )

    module_name, _, attr_path = spec.partition(":")
    if not module_name or not attr_path:
        raise TargetResolutionError(
            f"invalid {what} {spec!r}; expected 'module:attribute', e.g. {example}"
        )

    cwd = ensure_cwd_importable()

    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise TargetResolutionError(
            f"could not import module {module_name!r} from {what} {spec!r}: "
            f"{exc} (cwd={cwd}; is it importable from here, or on PYTHONPATH?)"
        ) from exc
    except Exception as exc:
        # The module exists but blew up while being imported - report that as
        # a setup problem rather than letting it surface as an "unexpected"
        # crash with no indication of which module was at fault.
        raise TargetResolutionError(
            f"module {module_name!r} raised {type(exc).__name__} while being "
            f"imported: {exc}"
        ) from exc

    obj: Any = module
    for part in attr_path.split("."):
        try:
            obj = getattr(obj, part)
        except AttributeError as exc:
            raise TargetResolutionError(
                f"module {module_name!r} has no attribute path {attr_path!r} "
                f"(failed at {part!r}): {exc}"
            ) from exc

    return obj


def resolve_target_spec(spec: str) -> Target:
    """Resolve a `module.submodule:attribute[.attribute...]` spec into a
    Target instance."""
    obj = _import_spec_attribute(
        spec,
        what="target spec",
        example="'myapp.rag:answer_question' or 'myapp.rag:MyTarget'",
    )

    if isinstance(obj, Target):
        return obj

    if inspect.isclass(obj) and issubclass(obj, Target):
        return obj()

    if callable(obj):
        return FunctionTarget(obj)

    raise TargetResolutionError(
        f"target spec {spec!r} resolved to {obj!r}, which is neither a Target "
        "instance, a Target subclass, nor a callable"
    )


def resolve_corpus_injector_spec(spec: str) -> CorpusInjector:
    """Resolve a `module.submodule:attribute[.attribute...]` spec into a
    CorpusInjector instance.

    Dispatch, narrower than `resolve_target_spec`'s:

    1. `obj` is already a `CorpusInjector` instance -> use it directly
    2. `obj` is a `CorpusInjector` subclass -> instantiate it with zero
       arguments
    3. otherwise -> `TargetResolutionError`

    Deliberately **no** bare-callable fallback: a `Target` is one operation
    (answer a question), so a bare function is unambiguous. A
    `CorpusInjector` is two paired operations (`inject`/`remove`), so a bare
    callable would be ambiguous about which one it implements - a user who
    needs a callable-shaped injector should wrap it in a small
    `CorpusInjector` subclass instead.
    """
    obj = _import_spec_attribute(
        spec,
        what="corpus injector spec",
        example="'myapp.injector:MyCorpusInjector'",
    )

    if isinstance(obj, CorpusInjector):
        return obj

    if inspect.isclass(obj) and issubclass(obj, CorpusInjector):
        return obj()

    raise TargetResolutionError(
        f"corpus injector spec {spec!r} resolved to {obj!r}, which is neither "
        "a CorpusInjector instance nor a CorpusInjector subclass"
    )
