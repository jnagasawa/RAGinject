"""LangChain integration (mode A): inject into a vector store, query a chain.

Duck typed: nothing from `langchain` is imported here. The injector only calls
`add_texts`/`delete` on the vector store you pass, and the target only calls
`invoke` on your chain (any Runnable).
"""

from typing import Any, List, Optional

from ..corpus import CorpusInjector, HostDocument, is_injected_id
from ..errors import TargetResponseError
from ..target import QueryResult, Target, normalize_query_result
from ._common import call_wrapped, reject_context

_INJECTOR = "LangChainVectorStoreInjector"

#: How many nearest documents `find_host` fetches before skipping injected ones.
_HOST_FETCH_K = 4


class LangChainVectorStoreInjector(CorpusInjector):
    """Writes attack documents into a LangChain `VectorStore`.

    The document id is used both as the store id and as `metadata["source"]`,
    so a retrieved document reports it back to `LangChainTarget`. This writes
    into the store you pass: use a test or staging store.
    """

    def __init__(self, vectorstore: Any):
        self.vectorstore = vectorstore

    @property
    def description(self) -> str:
        return f"LangChainVectorStoreInjector({type(self.vectorstore).__name__})"

    def inject(self, document_id: str, content: str) -> None:
        self.vectorstore.add_texts(
            [content], metadatas=[{"source": document_id}], ids=[document_id]
        )

    def remove(self, document_id: str) -> None:
        self.vectorstore.delete(ids=[document_id])

    def find_host(self, question: str) -> Optional[HostDocument]:
        """Top-1 real document for `question`, via `similarity_search`.
        Fetches a few so skipping documents raginject injected still leaves
        a result."""
        docs = self.vectorstore.similarity_search(question, k=_HOST_FETCH_K)
        for doc in docs or []:
            metadata = getattr(doc, "metadata", None)
            metadata = metadata if isinstance(metadata, dict) else {}
            doc_id = getattr(doc, "id", None)
            if is_injected_id(metadata.get("source")) or is_injected_id(doc_id):
                continue
            text = getattr(doc, "page_content", None)
            if not isinstance(text, str) or not text.strip():
                continue
            source = metadata.get("source") or doc_id or "unknown"
            return HostDocument(text=text, source=str(source))
        return None


def _text_of(value: Any) -> Optional[str]:
    """A str, or the `.content` str of a message-like object; else None."""
    if isinstance(value, str):
        return value
    content = getattr(value, "content", None)
    return content if isinstance(content, str) else None


def _source_of(doc: Any) -> Optional[str]:
    if isinstance(doc, str):
        return doc or None
    doc_id = getattr(doc, "id", None)
    if doc_id:
        return str(doc_id)
    metadata = getattr(doc, "metadata", None)
    if isinstance(metadata, dict):
        source = metadata.get("source")
        if source:
            return str(source)
    return None


class LangChainTarget(Target):
    """Wraps a LangChain chain (anything with `.invoke`) as a question-only Target.

    `input_key=None` invokes `chain.invoke(question)`. Chains built with
    `create_retrieval_chain` expect a dict: pass `input_key="input"`.

    Output handling: a `str` or message-like output (`.content`) is the answer
    with no sources; a dict output takes the answer from `answer_key` and the
    sources from `sources_key` (a list of Documents, each reported as its `id`
    or else `metadata["source"]`). Sources are what mode A's retrieval check
    and the `retrieval_match` judge read, so a chain that does not return them
    cannot be verified. Anything else is a `TargetResponseError`.
    """

    def __init__(
        self,
        chain: Any,
        *,
        input_key: Optional[str] = None,
        answer_key: str = "answer",
        sources_key: str = "context",
    ):
        self.chain = chain
        self.input_key = input_key
        self.answer_key = answer_key
        self.sources_key = sources_key

    @property
    def target_description(self) -> str:
        return f"LangChainTarget({type(self.chain).__name__})"

    def query(self, question: str, context: Optional[List[str]] = None) -> QueryResult:
        reject_context(context, "LangChainTarget", _INJECTOR)
        payload = question if self.input_key is None else {self.input_key: question}
        out = call_wrapped(lambda: self.chain.invoke(payload), "LangChainTarget")
        return normalize_query_result(
            self._to_raw(out), source="LangChainTarget", answer_key="answer"
        )

    def _to_raw(self, out: Any) -> dict:
        text = _text_of(out)
        if text is not None:
            return {"answer": text, "sources": []}
        if not isinstance(out, dict):
            raise TargetResponseError(
                "LangChainTarget: chain returned "
                f"{type(out).__name__}; expected a str, a message with .content, "
                "or a dict"
            )
        if self.answer_key not in out:
            available = ", ".join(sorted(map(str, out))) or "(none)"
            raise TargetResponseError(
                "LangChainTarget: chain output is missing required key "
                f"{self.answer_key!r}; available keys: {available}"
            )
        answer = _text_of(out[self.answer_key])
        if answer is None:
            raise TargetResponseError(
                f"LangChainTarget: {self.answer_key!r} must be a str or a message "
                f"with .content, got {type(out[self.answer_key]).__name__}"
            )
        docs = out.get(self.sources_key) or []
        if not isinstance(docs, (list, tuple)):
            raise TargetResponseError(
                f"LangChainTarget: {self.sources_key!r} must be a list of "
                f"Documents, got {type(docs).__name__}"
            )
        sources = [s for s in (_source_of(d) for d in docs) if s]
        return {"answer": answer, "sources": sources}
