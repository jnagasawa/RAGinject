"""Evaluate a RAG pipeline through corpus injection (mode A): raginject
writes each attack document into a real corpus and deletes it again,
instead of handing it to the target directly through `context`.

This is the payoff of mode A: `my_rag` below takes **only** `question` - no
`context` parameter at all - which mode B could not test (FunctionTarget
would raise ConfigurationError the moment a pattern needed a non-empty
context). Swap `InMemoryCorpus`'s `inject`/`remove` for calls into your own
vector store / search index / filesystem and the rest of this file is
unchanged.
"""

from typing import Dict, List, Tuple

from raginject import CorpusInjector, FunctionTarget, Runner


class InMemoryCorpus(CorpusInjector):
    """A stand-in for a real retrieval corpus. `inject`/`remove` are called
    in pairs, once per attack pattern; `retrieve` is what `my_rag` below
    calls to simulate "what my retriever would surface for this query"."""

    def __init__(self):
        self._documents: Dict[str, str] = {}

    def inject(self, document_id: str, content: str) -> None:
        self._documents[document_id] = content

    def remove(self, document_id: str) -> None:
        # Idempotent, as CorpusInjector.remove must be: removing an id
        # that was never inserted (or already removed) must not raise.
        self._documents.pop(document_id, None)

    def retrieve(self) -> List[Tuple[str, str]]:
        return list(self._documents.items())


corpus = InMemoryCorpus()


def my_rag(question: str) -> dict:
    # Your existing RAG logic - no `context` parameter, because mode A
    # queries your target the same way a real caller would: with just the
    # question. Retrieval happens here, against your real corpus.
    retrieved = corpus.retrieve()
    document_ids = [document_id for document_id, _ in retrieved]
    answer = f"Answer to: {question} (retrieved {len(retrieved)} document(s))"
    return {"answer": answer, "sources": document_ids}


target = FunctionTarget(my_rag)
runner = Runner(target=target, corpus_injector=corpus)
runner.load_patterns()
result = runner.run()

print(result.score)
print(result.summary)
