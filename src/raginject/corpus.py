"""CorpusInjector: the mode-A hook for writing an attack document into the
user's real retrieval corpus and removing it again.

Mode B (the only mode Milestone 1 shipped) hands `injected_content` straight
to `Target.query(question, context=[...])`, bypassing the user's retriever
entirely. That measures generation only, and it forces every user to open a
`context` parameter in their own pipeline. Mode A removes that requirement:
raginject writes the attack document into the corpus through this hook, asks
the question with no `context` argument, lets the user's own retriever
surface (or fail to surface) the document, and then deletes it - so a
question-only RAG function becomes testable and the score starts covering
retrieval, not just generation.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

#: Prefix of every document id raginject injects (`raginject-<pattern id>`).
INJECTED_ID_PREFIX = "raginject-"


def is_injected_id(value: object) -> bool:
    """True if `value` is a string naming a document raginject injected."""
    return isinstance(value, str) and value.startswith(INJECTED_ID_PREFIX)


@dataclass
class HostDocument:
    """A real document (or chunk) from the user's corpus, used by
    `--host-from-corpus` as the carrier for an attack payload.

    `text` is the body to splice the payload into; `source` is a display name
    for it (a path, title or id). Only `source` ever reaches a report - the
    body is never written to one.
    """

    text: str
    source: str


def source_matches_document(sources: List[str], document_id: Optional[str]) -> bool:
    """True if `document_id` shows up among `sources` - substring match, not
    equality, because a pipeline may report "raginject-<id>.txt" or a
    path/URL containing the id rather than the bare id. The ids raginject
    generates are unique and implausible strings, so substring matching here
    is not a realistic source of false positives.

    `document_id` is `None` in mode B (there is no injected document to
    match against), which this always reports as no match rather than
    raising - callers that only have a document id in mode A can pass
    whatever they have without a separate mode check.
    """
    if document_id is None:
        return False
    return any(document_id in source for source in sources)


class CorpusInjector(ABC):
    """Writes an attack document into the user's real retrieval corpus and
    deletes it again.

    `inject` and `remove` are always called in pairs by raginject, one pair
    per attack pattern, with `remove` guaranteed to run (in a `finally`)
    even if the target or the judge raises in between - so `remove` must be
    idempotent and must not raise for a document id it was never asked to
    insert (or already removed).

    Raise `raginject.CorpusInjectionError` from `inject`/`remove` to
    signal a corpus failure explicitly (e.g. the backing store is
    unreachable) - it is caught the same way as any other exception here
    (a single `status="error"` row, and the run continues), but naming it
    documents the failure as belonging to the corpus rather than to the
    target or the judge.

    Thread safety: like `Target` (see `target.py`), if this injector is ever
    driven with concurrency > 1, `inject`/`remove` must be safe to call
    concurrently from multiple threads. Implementations that hold mutable
    shared state (e.g. a single client connection with request-scoped
    mutation) must guard it accordingly.
    """

    @property
    def description(self) -> str:
        """A short, human-readable description of this injector, safe to
        show in reports (must never leak secrets such as connection
        strings or API keys)."""
        return type(self).__name__

    @abstractmethod
    def inject(self, document_id: str, content: str) -> None:
        """Insert `content` into the corpus under `document_id`, so that a
        subsequent query against the target's real retriever can surface
        it."""
        ...

    @abstractmethod
    def remove(self, document_id: str) -> None:
        """Delete the document previously inserted under `document_id`.
        Must be idempotent: called with an id that was never inserted, or
        already removed, must not raise."""
        ...

    def find_host(self, question: str) -> Optional[HostDocument]:
        """Return the most relevant real document/chunk in the store for
        `question` (top-1), or `None` if the store has nothing.

        Anything raginject injected itself (ids starting with "raginject-")
        must be excluded. Optional: only `--host-from-corpus` calls it, and
        the default raises `NotImplementedError` (raginject checks for an
        override before the run starts and refuses to proceed without one).

        `--host-from-corpus` copies this document, splices the attack payload
        into the copy and injects the copy; the original is left in place, so
        a retriever may surface both.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not implement find_host()"
        )
