"""LlamaIndex integration (mode A): inject into an index, query an engine.

Duck typed except for `Document`, which is imported lazily inside `inject()`
so that importing this module never requires `llama-index-core`.
"""

import warnings
from typing import Any, List, Optional

from ..corpus import CorpusInjector, HostDocument, is_injected_id
from ..errors import ConfigurationError
from ..target import QueryResult, Target, normalize_query_result
from ._common import call_wrapped, reject_context

_INJECTOR = "LlamaIndexInjector"

#: How many nearest nodes `find_host` fetches before skipping injected ones.
_HOST_FETCH_K = 4


class LlamaIndexInjector(CorpusInjector):
    """Writes attack documents into a LlamaIndex index (`index.insert`).

    The document id becomes the `doc_id` (the nodes' `ref_doc_id`) and
    `metadata["source"]`, so `LlamaIndexTarget` can report it back. This
    writes into the index you pass: use a test or staging index.
    """

    def __init__(self, index: Any):
        self.index = index

    @property
    def description(self) -> str:
        return f"LlamaIndexInjector({type(self.index).__name__})"

    def inject(self, document_id: str, content: str) -> None:
        try:
            from llama_index.core import Document
        except ImportError as exc:
            raise ConfigurationError(
                "LlamaIndexInjector needs llama-index-core to build a Document; "
                "install it with `pip install llama-index-core`."
            ) from exc
        self.index.insert(
            Document(text=content, doc_id=document_id, metadata={"source": document_id})
        )

    def remove(self, document_id: str) -> None:
        self.index.delete_ref_doc(document_id, delete_from_docstore=True)

    def find_host(self, question: str) -> Optional[HostDocument]:
        """Top-1 real node for `question`, via the index's retriever. Fetches
        a few so skipping nodes raginject injected still leaves a result."""
        retriever = self.index.as_retriever(similarity_top_k=_HOST_FETCH_K)
        for item in retriever.retrieve(question) or []:
            node = getattr(item, "node", item)
            metadata = getattr(node, "metadata", None) or {}
            ref_doc_id = getattr(node, "ref_doc_id", None)
            node_id = getattr(node, "node_id", None)
            if (
                is_injected_id(ref_doc_id)
                or is_injected_id(node_id)
                or is_injected_id(metadata.get("source"))
            ):
                continue
            text = node.get_content()
            if not isinstance(text, str) or not text.strip():
                continue
            source = (
                metadata.get("file_name")
                or metadata.get("source")
                or ref_doc_id
                or node_id
                or "unknown"
            )
            return HostDocument(text=text, source=str(source))
        return None


def _warn_if_node_ids_pinned(engine: Any) -> None:
    """Best-effort, never raises: warn when a pre-built engine's retriever holds a
    non-empty fixed node-id list. `VectorStoreIndex.as_retriever` pins the index's
    node ids at build time and the retriever restricts every query to them, so
    documents injected later are never retrieved. An index over an external
    vector store that keeps text has an empty list and is not affected."""
    try:
        node_ids = getattr(getattr(engine, "_retriever", None), "_node_ids", None)
        pinned = isinstance(node_ids, (list, tuple, set)) and len(node_ids) > 0
    except Exception:
        return
    if pinned:
        warnings.warn(
            "LlamaIndexTarget: this query engine's retriever was built with a fixed "
            f"list of {len(node_ids)} node id(s), so documents injected afterwards "
            "will never be retrieved and every row will fail retrieval verification. "
            "Pass a function instead: LlamaIndexTarget(lambda: index.as_query_engine(...)).",
            stacklevel=3,
        )


class LlamaIndexTarget(Target):
    """Wraps a LlamaIndex query engine (anything with `.query`) as a
    question-only Target.

    **Pass a factory, not a built engine, when you can.** `index.as_query_engine()`
    snapshots the index's node ids when it is built, so an engine created
    *before* `LlamaIndexInjector.inject` never retrieves the injected document
    (every row would then be an excluded retrieval-verification error). Pass a
    zero-argument callable, e.g. `lambda: index.as_query_engine()`, and it is
    called once per query so the engine always sees the current index.

    The answer is `str(response.response)` (empty when `None`); sources are
    each `response.source_nodes` entry's `ref_doc_id`, falling back to
    `metadata["source"]`, with empty values dropped.
    """

    def __init__(self, query_engine: Any):  # engine, or a factory returning one
        self.query_engine = query_engine
        if hasattr(query_engine, "query"):
            _warn_if_node_ids_pinned(query_engine)

    @property
    def target_description(self) -> str:
        if not hasattr(self.query_engine, "query") and callable(self.query_engine):
            return "LlamaIndexTarget(factory)"
        return f"LlamaIndexTarget({type(self.query_engine).__name__})"

    def query(self, question: str, context: Optional[List[str]] = None) -> QueryResult:
        reject_context(context, "LlamaIndexTarget", _INJECTOR)

        def ask() -> Any:
            engine = self.query_engine
            if not hasattr(engine, "query") and callable(engine):
                engine = engine()
            return engine.query(question)

        resp = call_wrapped(ask, "LlamaIndexTarget")
        if hasattr(resp, "response"):
            text = resp.response
            answer = "" if text is None else str(text)
        else:
            answer = str(resp)
        sources = []
        for item in getattr(resp, "source_nodes", None) or []:
            node = getattr(item, "node", item)
            metadata = getattr(node, "metadata", None) or {}
            source = getattr(node, "ref_doc_id", None) or metadata.get("source")
            if source:
                sources.append(str(source))
        return normalize_query_result(
            {"answer": answer, "sources": sources}, source="LlamaIndexTarget"
        )
