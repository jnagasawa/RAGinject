"""Framework integrations, tested against hand-written fakes (no langchain /
llama-index installed). The real-framework tests are in
test_integrations_real.py."""

import builtins
import re
from types import SimpleNamespace

import pytest

from raginject import Runner
from raginject.errors import ConfigurationError, TargetError, TargetResponseError
from raginject.integrations.langchain import (
    LangChainTarget,
    LangChainVectorStoreInjector,
)
from raginject.integrations.llamaindex import LlamaIndexInjector, LlamaIndexTarget

_QUOTED = re.compile(r'"([^"]{3,})"')


class FakeStore:
    def __init__(self):
        self.docs = {}
        self.calls = []

    def add_texts(self, texts, metadatas=None, *, ids=None):
        self.calls.append(("add_texts", list(texts), metadatas, ids))
        for text, meta, doc_id in zip(texts, metadatas, ids):
            self.docs[doc_id] = (text, meta)

    def delete(self, ids=None):
        self.calls.append(("delete", ids))
        for doc_id in ids:
            self.docs.pop(doc_id, None)


def fake_doc(doc_id=None, source=None, text=""):
    metadata = {"source": source} if source else {}
    return SimpleNamespace(id=doc_id, metadata=metadata, page_content=text)


def store_chain(store, obey):
    """A chain over FakeStore: returns {"answer", "context"} like an LCEL chain."""

    def invoke(payload):
        question = payload["input"] if isinstance(payload, dict) else payload
        assert isinstance(question, str)
        docs = [fake_doc(i, m.get("source"), t) for i, (t, m) in store.docs.items()]
        answer = "Summary."
        if obey:
            answer = " ".join(
                m for _, (t, _) in store.docs.items() for m in _QUOTED.findall(t)
            )
        return {"answer": answer, "context": docs}

    return SimpleNamespace(invoke=invoke)


def test_langchain_injector_call_shapes():
    store = FakeStore()
    injector = LangChainVectorStoreInjector(store)
    injector.inject("raginject-x", "hello")
    injector.remove("raginject-x")
    assert store.calls == [
        ("add_texts", ["hello"], [{"source": "raginject-x"}], ["raginject-x"]),
        ("delete", ["raginject-x"]),
    ]
    assert injector.description == "LangChainVectorStoreInjector(FakeStore)"


@pytest.mark.parametrize(
    "output, expected",
    [
        ("plain", {"answer": "plain", "sources": []}),
        (SimpleNamespace(content="msg"), {"answer": "msg", "sources": []}),
        (
            {
                "answer": SimpleNamespace(content="a"),
                "context": [
                    fake_doc("id1"),
                    fake_doc(None, "src2"),
                    fake_doc(),
                    "str-src",
                ],
            },
            {"answer": "a", "sources": ["id1", "src2", "str-src"]},
        ),
        ({"answer": "a"}, {"answer": "a", "sources": []}),
    ],
)
def test_langchain_output_normalization(output, expected):
    target = LangChainTarget(SimpleNamespace(invoke=lambda _: output))
    assert target.query("q") == expected


def test_langchain_keys_and_input_key():
    seen = []

    def invoke(payload):
        seen.append(payload)
        return {"reply": "r", "docs": [fake_doc("d")]}

    target = LangChainTarget(
        SimpleNamespace(invoke=invoke),
        input_key="input",
        answer_key="reply",
        sources_key="docs",
    )
    assert target.query("hi") == {"answer": "r", "sources": ["d"]}
    assert seen == [{"input": "hi"}]
    assert target.target_description == "LangChainTarget(SimpleNamespace)"


@pytest.mark.parametrize(
    "output",
    [42, {"nope": 1}, {"answer": 3}, {"answer": "a", "context": "notalist"}],
)
def test_langchain_bad_output_is_response_error(output):
    target = LangChainTarget(SimpleNamespace(invoke=lambda _: output))
    with pytest.raises(TargetResponseError):
        target.query("q")


def test_missing_key_message_lists_available_keys():
    target = LangChainTarget(SimpleNamespace(invoke=lambda _: {"zzz": 1}))
    with pytest.raises(TargetResponseError, match="zzz"):
        target.query("q")


def test_targets_reject_context_with_mode_a_hint():
    lc = LangChainTarget(SimpleNamespace(invoke=lambda _: "x"))
    li = LlamaIndexTarget(SimpleNamespace(query=lambda _: "x"))
    with pytest.raises(ConfigurationError, match="LangChainVectorStoreInjector"):
        lc.query("q", context=["doc"])
    with pytest.raises(ConfigurationError, match="LlamaIndexInjector"):
        li.query("q", context=["doc"])
    assert lc.query("q", context=[]) == {"answer": "x", "sources": []}


def test_chain_exception_becomes_target_error():
    def boom(_):
        raise RuntimeError("model down")

    with pytest.raises(TargetError, match="model down"):
        LangChainTarget(SimpleNamespace(invoke=boom)).query("q")
    with pytest.raises(TargetError, match="model down"):
        LlamaIndexTarget(SimpleNamespace(query=boom)).query("q")


def test_configuration_error_from_chain_propagates():
    def bad(_):
        raise ConfigurationError("fix me")

    with pytest.raises(ConfigurationError):
        LangChainTarget(SimpleNamespace(invoke=bad)).query("q")


def test_run_marks_failing_chain_as_error_rows():
    def boom(_):
        raise RuntimeError("down")

    runner = Runner(
        LangChainTarget(SimpleNamespace(invoke=boom)),
        corpus_injector=LangChainVectorStoreInjector(FakeStore()),
    )
    runner.load_patterns()
    result = runner.run()
    assert not result.has_scoreable_outcomes
    assert {o.status for o in result.outcomes} == {"error"}


@pytest.mark.parametrize("obey, expected_score", [(False, 1.0), (True, 0.0)])
def test_langchain_end_to_end_mode_a(obey, expected_score):
    store = FakeStore()
    target = LangChainTarget(store_chain(store, obey), input_key="input")
    runner = Runner(target, corpus_injector=LangChainVectorStoreInjector(store))
    runner.load_patterns()
    result = runner.run()
    assert result.has_scoreable_outcomes
    assert result.score == expected_score
    assert all(o.status != "error" for o in result.outcomes)
    assert store.docs == {}  # every injected document was removed


class FakeIndex:
    def __init__(self):
        self.docs = {}

    def insert(self, document):
        self.docs[document.doc_id] = document

    def delete_ref_doc(self, ref_doc_id, delete_from_docstore=False):
        assert delete_from_docstore is True
        self.docs.pop(ref_doc_id, None)


def fake_response(index, obey, text=None):
    nodes = [
        SimpleNamespace(
            node=SimpleNamespace(ref_doc_id=d.doc_id, metadata=d.metadata, text=d.text)
        )
        for d in index.docs.values()
    ]
    answer = "Summary."
    if obey:
        answer = " ".join(
            m for d in index.docs.values() for m in _QUOTED.findall(d.text)
        )
    return SimpleNamespace(
        response=answer if text is None else text, source_nodes=nodes
    )


def test_llamaindex_end_to_end_mode_a_with_factory():
    pytest.importorskip("llama_index.core")
    index = FakeIndex()
    builds = []

    def factory():
        builds.append(1)
        return SimpleNamespace(query=lambda q: fake_response(index, obey=False))

    runner = Runner(
        LlamaIndexTarget(factory), corpus_injector=LlamaIndexInjector(index)
    )
    runner.load_patterns()
    result = runner.run()
    assert result.score == 1.0
    assert all(o.status != "error" for o in result.outcomes)
    assert len(builds) == len(result.outcomes)
    assert index.docs == {}


def test_llamaindex_response_normalization():
    index = FakeIndex()
    resp = SimpleNamespace(
        response=None,
        source_nodes=[
            SimpleNamespace(node=SimpleNamespace(ref_doc_id="a", metadata={})),
            SimpleNamespace(
                node=SimpleNamespace(ref_doc_id=None, metadata={"source": "b"})
            ),
            SimpleNamespace(node=SimpleNamespace(ref_doc_id=None, metadata={})),
        ],
    )
    target = LlamaIndexTarget(SimpleNamespace(query=lambda _: resp))
    assert target.query("q") == {"answer": "", "sources": ["a", "b"]}
    assert target.target_description == "LlamaIndexTarget(SimpleNamespace)"
    assert (
        LlamaIndexTarget(lambda: None).target_description == "LlamaIndexTarget(factory)"
    )
    # a bare string response has no source_nodes
    assert LlamaIndexTarget(SimpleNamespace(query=lambda _: "txt")).query("q") == {
        "answer": "txt",
        "sources": [],
    }
    assert LlamaIndexInjector(index).description == "LlamaIndexInjector(FakeIndex)"


def test_llamaindex_injector_without_llama_index_raises_configuration_error(
    monkeypatch,
):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("llama_index"):
            raise ImportError("no llama_index")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ConfigurationError, match="llama-index-core"):
        LlamaIndexInjector(FakeIndex()).inject("raginject-x", "hello")


def test_llamaindex_injector_builds_document():
    pytest.importorskip("llama_index.core")
    index = FakeIndex()
    injector = LlamaIndexInjector(index)
    injector.inject("raginject-x", "hello")
    doc = index.docs["raginject-x"]
    assert doc.text == "hello"
    assert doc.metadata == {"source": "raginject-x"}
    injector.remove("raginject-x")
    injector.remove("raginject-x")  # idempotent
    assert index.docs == {}


def test_node_id_warning_is_best_effort_and_only_for_non_empty_lists():
    import warnings

    def engine(node_ids):
        return SimpleNamespace(
            query=lambda _: "x", _retriever=SimpleNamespace(_node_ids=node_ids)
        )

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        LlamaIndexTarget(engine([]))  # external-store index: nothing pinned
        LlamaIndexTarget(engine(None))
        LlamaIndexTarget(SimpleNamespace(query=lambda _: "x"))  # no retriever
    with pytest.warns(UserWarning, match="1 node id"):
        LlamaIndexTarget(engine(["n1"]))
