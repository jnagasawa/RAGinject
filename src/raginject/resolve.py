"""Resolve a `module:attribute` spec (as passed to `--target-module`) into a
Target instance.

Dispatch order matters (a `Target` subclass may itself define `__call__`,
so the `isinstance` check for an already-built `Target` instance must come
first, before the generic `callable` check):

1. `obj` is already a `Target` instance -> use it directly
2. `obj` is a `Target` subclass -> instantiate it with zero arguments
3. `obj` is callable -> wrap it in `FunctionTarget`
4. otherwise -> `TargetResolutionError`

A zero-argument factory function (e.g. `def make_target(): ...`) is
indistinguishable from a zero-argument RAG function and is therefore *not*
supported - this is a deliberate simplification, not an oversight.
"""

import importlib
import inspect
import os
import sys
from typing import Any

from .adapters.function import FunctionTarget
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


def resolve_target_spec(spec: str) -> Target:
    """Resolve a `module.submodule:attribute[.attribute...]` spec into a
    Target instance."""
    if ":" not in spec:
        raise TargetResolutionError(
            f"invalid target spec {spec!r}; expected 'module:attribute', "
            "e.g. 'myapp.rag:answer_question' or 'myapp.rag:MyTarget'"
        )

    module_name, _, attr_path = spec.partition(":")
    if not module_name or not attr_path:
        raise TargetResolutionError(
            f"invalid target spec {spec!r}; expected 'module:attribute', "
            "e.g. 'myapp.rag:answer_question' or 'myapp.rag:MyTarget'"
        )

    cwd = ensure_cwd_importable()

    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise TargetResolutionError(
            f"could not import module {module_name!r} from target spec {spec!r}: "
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
