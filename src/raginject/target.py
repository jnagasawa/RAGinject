"""Target abstraction: the common interface all evaluation targets normalize to."""

from abc import ABC, abstractmethod
from typing import Any, List, Optional, TypedDict

from .errors import TargetResponseError


class _QueryResultOptional(TypedDict, total=False):
    sources: List[str]


class QueryResult(_QueryResultOptional):
    answer: str


class Target(ABC):
    """Common interface all evaluation targets (function-wrapped or HTTP)
    normalize to.

    Thread safety: if this Target is ever driven with concurrency > 1 (a
    future raginject feature; not implemented in Milestone 1), `query` must
    be safe to call concurrently from multiple threads. Implementations
    that hold mutable shared state (e.g. a single HTTP connection with
    request-scoped mutation) must guard it accordingly.
    """

    @property
    def target_description(self) -> str:
        """A short, human-readable description of this target, safe to show
        in reports (must never leak secrets such as auth headers)."""
        return type(self).__name__

    @abstractmethod
    def query(self, question: str, context: Optional[List[str]] = None) -> QueryResult:
        """Send `question` (and optional `context` documents) to the target and
        return a QueryResult.

        `context` is the list of documents that should be treated as if they
        were retrieved for this query. `None` or an empty list means a
        normal, uninjected query.
        """
        ...


def normalize_query_result(
    raw: Any,
    *,
    source: str,
    answer_key: str = "answer",
    sources_key: str = "sources",
) -> QueryResult:
    """Validate and normalize a raw response into a QueryResult.

    Shared between FunctionTarget and HTTPTarget so both adapters raise the
    same, clear errors for the same shape mistakes.

    - `raw` must be a dict/mapping.
    - `raw[answer_key]` must be present (the error lists the keys that
      actually exist) and must be a `str` (not coerced).
    - `raw[sources_key]` is optional; defaults to `[]`. If present, must be
      a list or tuple of strings.

    Raises `TargetResponseError` (source-agnostic message, `source` is used
    only to identify which adapter/target raised it).
    """
    if not isinstance(raw, dict):
        raise TargetResponseError(
            f"{source}: expected a dict-like QueryResult, got {type(raw).__name__}"
        )

    if answer_key not in raw:
        available = ", ".join(sorted(raw.keys())) or "(none)"
        raise TargetResponseError(
            f"{source}: response is missing required key {answer_key!r}; "
            f"available keys: {available}"
        )

    answer = raw[answer_key]
    if not isinstance(answer, str):
        raise TargetResponseError(
            f"{source}: {answer_key!r} must be a str, got {type(answer).__name__}"
        )

    result: QueryResult = {"answer": answer}

    if sources_key in raw and raw[sources_key] is not None:
        sources = raw[sources_key]
        if not isinstance(sources, (list, tuple)) or not all(
            isinstance(s, str) for s in sources
        ):
            raise TargetResponseError(
                f"{source}: {sources_key!r} must be a list of str, got {sources!r}"
            )
        result["sources"] = list(sources)
    else:
        result["sources"] = []

    return result
