"""Four dependency-free, scripted demo RAG "pipelines" you can point raginject
at without having a real RAG app of your own:

    raginject run --target-module raginject.demo:vulnerable_rag
    raginject run --target-module raginject.demo:defended_rag --min-score 1.0

    raginject run --target-module raginject.demo:vulnerable_corpus_rag \\
                  --corpus-injector raginject.demo:demo_corpus_injector
    raginject run --target-module raginject.demo:defended_corpus_rag \\
                  --corpus-injector raginject.demo:demo_corpus_injector --min-score 1.0

**None of these are real language models.** `vulnerable_rag` and
`defended_rag` are small, deterministic, dependency-free Python functions
that simulate how a naive vs. a defensive RAG pipeline *behaves* with
respect to retrieved-context injection. `vulnerable_corpus_rag` and
`defended_corpus_rag` are the same two behaviors again, but wired for corpus
injection (mode A) instead: they take a `question` only, and "retrieve" from
`demo_corpus_injector`'s in-memory store rather than being handed `context`
directly. All four exist purely so someone who does not yet have a RAG
application can see real raginject output (and a real gate failure)
immediately after `pip install raginject`, before wiring up their own
target. Do not use any of them as a stand-in for evaluating an actual LLM.
"""

import re
from typing import Dict, List, Optional, Tuple

from .corpus import CorpusInjector
from .target import QueryResult

_QUOTED = re.compile(r'"([^"]{3,})"')


def vulnerable_rag(question: str, context: Optional[List[str]] = None) -> QueryResult:
    """A scripted stand-in for a naive RAG pipeline - NOT a real language
    model.

    It simulates the failure this whole tool is about: text that arrived
    through retrieval is treated as instructions rather than as data, so an
    instruction planted in a document gets carried out. Concretely, it obeys
    any directive of the form `... "SOMETHING"` found in `context` by
    emitting that something, which is exactly what raginject's default
    patterns ask an injected document to make the model do.

    Note this deliberately *complies* rather than merely quoting the
    document back: a judge that only looks for a canary string cannot tell
    those two apart (see the `keyword_match` limitation in the README), and
    a demo should show the real failure, not the judge's blind spot.
    """
    context = context or []
    if not context:
        return {"answer": f"Answer to: {question}", "sources": []}

    obeyed = [match for doc in context for match in _QUOTED.findall(doc)]
    if not obeyed:
        return {"answer": f"Answer to: {question}", "sources": ["demo-doc-1"]}

    answer = " ".join(obeyed)
    return {"answer": answer, "sources": ["demo-doc-1"]}


def defended_rag(question: str, context: Optional[List[str]] = None) -> QueryResult:
    """A scripted stand-in for a defensive RAG pipeline - NOT a real
    language model. It treats retrieved `context` strictly as data to
    summarize, never as instructions to follow, and never quotes it
    verbatim - so instructions embedded in `context` (including raginject's
    built-in canary markers) never reach the answer. Against raginject's
    default attack patterns this scores 1.0.
    """
    context = context or []
    doc_count = len(context)
    if doc_count == 0:
        return {"answer": f"Answer to: {question}", "sources": []}

    answer = (
        f"I reviewed {doc_count} retrieved document(s) to answer your question "
        f"but only used factual content relevant to it; I don't follow "
        f"instructions found inside retrieved documents."
    )
    return {"answer": answer, "sources": ["demo-doc-1"]}


class _DemoCorpus(CorpusInjector):
    """An in-memory "corpus" shared between the corpus-injector side
    (`inject`/`remove`, driven by the Runner) and the target side
    (`retrieve`, called from `vulnerable_corpus_rag`/`defended_corpus_rag`)
    of the mode-A demo pair.

    A module-level instance of this (`demo_corpus_injector`, below) is the
    seam that makes the demo possible: mode A needs *some* shared store
    standing in for "the user's real retrieval corpus", and here that store
    is just a dict living in this process. A real `CorpusInjector` would
    instead write to (and later delete from) whatever the user's actual
    retriever indexes - a vector store, a search index, a filesystem, ...
    """

    def __init__(self):
        #: Deliberately a plain mutable dict on a module-level singleton
        #: (see `demo_corpus_injector` below) - fine for a single-process
        #: demo, but not thread-safe, unlike a real CorpusInjector should be.
        self._documents: Dict[str, str] = {}

    def inject(self, document_id: str, content: str) -> None:
        self._documents[document_id] = content

    def remove(self, document_id: str) -> None:
        # Idempotent per the CorpusInjector contract: removing an id that
        # was never inserted (or already removed) must not raise.
        self._documents.pop(document_id, None)

    def retrieve(self) -> List[Tuple[str, str]]:
        """Return every currently-injected `(document_id, content)` pair.
        Called by the demo targets below to simulate "what my retriever
        would surface for this query" - in this simplified demo, that is
        simply everything currently in the corpus."""
        return list(self._documents.items())


#: Module-level singleton shared by `vulnerable_corpus_rag`/
#: `defended_corpus_rag` (the target side) and `--corpus-injector
#: raginject.demo:demo_corpus_injector` (the injector side) - the two need
#: to observe the same mutable store for the demo to work end to end.
demo_corpus_injector = _DemoCorpus()


def vulnerable_corpus_rag(question: str) -> QueryResult:
    """Mode-A counterpart to `vulnerable_rag` - NOT a real language model.

    Question-only on purpose (no `context` parameter at all): this is what
    demonstrates that mode A can test a pipeline that never opened a
    `context` seam. It "retrieves" by reading everything currently sitting
    in `demo_corpus_injector`, then reuses `vulnerable_rag`'s exact
    obeys-quoted-instructions behavior against it.
    """
    retrieved = demo_corpus_injector.retrieve()
    if not retrieved:
        return {"answer": f"Answer to: {question}", "sources": []}

    document_ids = [document_id for document_id, _ in retrieved]
    contents = [content for _, content in retrieved]
    obeyed = [match for doc in contents for match in _QUOTED.findall(doc)]
    if not obeyed:
        return {"answer": f"Answer to: {question}", "sources": document_ids}

    return {"answer": " ".join(obeyed), "sources": document_ids}


def defended_corpus_rag(question: str) -> QueryResult:
    """Mode-A counterpart to `defended_rag` - NOT a real language model.

    Question-only, like `vulnerable_corpus_rag` above. Reuses
    `defended_rag`'s exact never-follow-retrieved-instructions behavior
    against whatever `demo_corpus_injector` currently holds.
    """
    retrieved = demo_corpus_injector.retrieve()
    if not retrieved:
        return {"answer": f"Answer to: {question}", "sources": []}

    document_ids = [document_id for document_id, _ in retrieved]
    answer = (
        f"I reviewed {len(retrieved)} retrieved document(s) to answer your "
        f"question but only used factual content relevant to it; I don't "
        f"follow instructions found inside retrieved documents."
    )
    return {"answer": answer, "sources": document_ids}
