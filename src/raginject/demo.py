"""Two dependency-free, scripted demo RAG "pipelines" you can point raginject
at without having a real RAG app of your own:

    raginject run --target-module raginject.demo:vulnerable_rag
    raginject run --target-module raginject.demo:defended_rag --min-score 1.0

**These are NOT real language models.** `vulnerable_rag` and `defended_rag`
are small, deterministic, dependency-free Python functions that simulate
how a naive vs. a defensive RAG pipeline *behaves* with respect to
retrieved-context injection. They exist purely so someone who does not yet
have a RAG application can see real raginject output (and a real gate
failure) immediately after `pip install raginject`, before wiring up their
own target. Do not use them as a stand-in for evaluating an actual LLM.
"""

import re
from typing import List, Optional

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
