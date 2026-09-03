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
