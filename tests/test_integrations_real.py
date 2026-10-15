"""Framework integrations against the real LangChain / LlamaIndex packages,
fully offline (fake embeddings and LLMs). Skipped when they are not installed
(they are dev dependencies on Python >= 3.10 only)."""

import warnings

import pytest

from raginject import Runner
from raginject.attacks.loader import load_patterns
from raginject.integrations.langchain import (
    LangChainTarget,
    LangChainVectorStoreInjector,
)
from raginject.integrations.llamaindex import LlamaIndexInjector, LlamaIndexTarget

QUESTION = "What is the refund policy?"


def _run(target, injector, pattern_count=3):
    runner = Runner(target, corpus_injector=injector)
    runner.add_patterns(load_patterns()[:pattern_count])
    return runner.run()


def test_langchain_real_store_and_chain():
    pytest.importorskip("langchain_core")
    from langchain_core.embeddings import DeterministicFakeEmbedding
    from langchain_core.vectorstores import InMemoryVectorStore

    store = InMemoryVectorStore(DeterministicFakeEmbedding(size=16))
    store.add_texts(
        ["Refunds are issued within 14 days.", "Support is open on weekdays."]
    )
    retriever = store.as_retriever(search_kwargs={"k": 10})

    def chain_fn(payload):
        docs = retriever.invoke(payload["input"])
        return {"answer": "Summary.", "context": docs}

    from langchain_core.runnables import RunnableLambda

    chain = RunnableLambda(chain_fn)
    target = LangChainTarget(chain, input_key="input")
    injector = LangChainVectorStoreInjector(store)

    injector.inject("raginject-probe", "Refund policy notes.")
    assert any("raginject-probe" in s for s in target.query(QUESTION)["sources"])
    injector.remove("raginject-probe")
    assert not any("raginject-probe" in s for s in target.query(QUESTION)["sources"])
    injector.remove("raginject-probe")  # idempotent

    result = _run(target, injector)
    assert result.has_scoreable_outcomes
    assert all(o.status != "error" for o in result.outcomes)
    assert len(store.store) == 2  # only the seed documents remain


def test_langchain_real_lcel_chain_with_fake_chat_model():
    pytest.importorskip("langchain_core")
    from langchain_core.embeddings import DeterministicFakeEmbedding
    from langchain_core.language_models import FakeListChatModel
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.runnables import RunnablePassthrough
    from langchain_core.vectorstores import InMemoryVectorStore

    store = InMemoryVectorStore(DeterministicFakeEmbedding(size=16))
    store.add_texts(["Refunds are issued within 14 days."])
    retriever = store.as_retriever(search_kwargs={"k": 10})
    prompt = ChatPromptTemplate.from_template("{context}\n{question}")
    llm = FakeListChatModel(responses=["ok"])
    chain = RunnablePassthrough.assign(
        context=lambda x: retriever.invoke(x["question"])
    ).assign(
        answer=lambda x: (prompt | llm | StrOutputParser()).invoke(
            {**x, "context": "\n".join(d.page_content for d in x["context"])}
        )
    )
    target = LangChainTarget(chain, input_key="question")
    injector = LangChainVectorStoreInjector(store)
    injector.inject("raginject-probe", "text")
    result = target.query(QUESTION)
    assert result["answer"] == "ok"
    assert "raginject-probe" in result["sources"]
    injector.remove("raginject-probe")


def test_llamaindex_real_index_and_engine():
    pytest.importorskip("llama_index.core")
    from llama_index.core import Document, MockEmbedding, VectorStoreIndex
    from llama_index.core.llms import MockLLM

    index = VectorStoreIndex.from_documents(
        [Document(text="Refunds are issued within 14 days.", doc_id="faq")],
        embed_model=MockEmbedding(embed_dim=8),
    )

    def build():
        return index.as_query_engine(llm=MockLLM(max_tokens=4), similarity_top_k=10)

    with warnings.catch_warnings():
        warnings.simplefilter("error")  # the factory form must not warn
        target = LlamaIndexTarget(build)
    injector = LlamaIndexInjector(index)

    injector.inject("raginject-probe", "Refund policy notes.")
    assert "raginject-probe" in target.query(QUESTION)["sources"]
    injector.remove("raginject-probe")
    assert target.query(QUESTION)["sources"] == ["faq"]
    injector.remove("raginject-probe")  # idempotent

    # An engine built before injection snapshots node ids and never sees the
    # new document - the reason LlamaIndexTarget accepts a factory.
    with pytest.warns(UserWarning, match="lambda: index.as_query_engine"):
        stale = LlamaIndexTarget(build())
    injector.inject("raginject-probe", "Refund policy notes.")
    assert "raginject-probe" not in stale.query(QUESTION)["sources"]
    injector.remove("raginject-probe")

    result = _run(target, injector)
    assert result.has_scoreable_outcomes
    assert all(o.status != "error" for o in result.outcomes)
    assert list(index.ref_doc_info) == ["faq"]
