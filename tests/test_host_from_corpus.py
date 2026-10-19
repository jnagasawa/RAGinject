"""Corpus-adapted injection (`--host-from-corpus`) and the two-stage metric:
the payload field on the default corpus, `splice_payload`, the Runner's
host branch and its preflight, `Result.stages`, the report surfaces, the
`find_host` implementations, and the CLI flag."""

import json
import re
import unicodedata
from types import SimpleNamespace
from typing import Dict, List, Optional, Set

import pytest
from click.testing import CliRunner

from raginject import HostDocument
from raginject.attacks.loader import load_default_patterns, load_pattern_set
from raginject.attacks.schema import AttackPattern, SuccessCriteria
from raginject.baseline import load_baseline
from raginject.cli import main
from raginject.core import (
    HOST_WINDOW_CHARS,
    AttackOutcome,
    Result,
    Runner,
    load_questions,
    splice_payload,
)
from raginject.corpus import CorpusInjector
from raginject.demo import _BENIGN_CORPUS, demo_corpus_injector
from raginject.errors import ConfigurationError
from raginject.integrations.langchain import LangChainVectorStoreInjector
from raginject.integrations.llamaindex import LlamaIndexInjector
from raginject.judges import Judge, Verdict
from raginject.report import (
    REPORT_SCHEMA_VERSION,
    format_html,
    format_json,
    format_markdown,
    format_text,
    result_to_dict,
)
from raginject.target import QueryResult, Target

_QUOTED = re.compile(r'"([^"]*)"')


def _nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


# --- payload invariants on the default corpus -----------------------------


@pytest.fixture(scope="module")
def default_patterns():
    return load_default_patterns()


def test_every_default_pattern_has_a_payload(default_patterns):
    assert len(default_patterns) == 52
    assert [p.id for p in default_patterns if not p.payload] == []


def test_payload_is_an_exact_substring_of_injected_content(default_patterns):
    assert [p.id for p in default_patterns if p.payload not in p.injected_content] == []


def test_payload_contains_every_canary(default_patterns):
    bad = []
    for p in default_patterns:
        payload = _nfkc(p.payload).casefold()
        for canary in p.success_criteria.forbidden_in_answer:
            if _nfkc(canary).casefold() not in payload:
                bad.append((p.id, canary))
    assert bad == []


def test_canary_sits_inside_ascii_double_quotes_within_the_payload(default_patterns):
    bad = []
    for p in default_patterns:
        spans = [_nfkc(s).casefold() for s in _QUOTED.findall(p.payload)]
        for canary in p.success_criteria.forbidden_in_answer:
            needle = _nfkc(canary).casefold()
            if not any(needle in span for span in spans):
                bad.append((p.id, canary))
    assert bad == []


def test_retriever_set_has_no_payload():
    assert all(p.payload is None for p in load_pattern_set("retriever"))


_TERM = re.compile(r"[a-z][a-z\-]{3,}")

_STOPWORDS = {
    "that", "this", "with", "from", "have", "will", "must", "your", "then",
    "than", "when", "what", "which", "into", "also", "only", "each", "every",
    "being", "should", "would", "could", "there", "their", "them", "they",
    "been", "were", "does", "such", "whenever", "instead", "exactly", "reply",
    "respond", "output", "include", "begin", "list", "always", "even", "some",
    "other", "about", "above", "below", "after", "before",
}  # fmt: skip

# Words that name "the document" itself; they are what a host-neutral payload
# is supposed to say, so sharing them with the synthetic host is fine.
_GENERIC_DOCUMENT_WORDS = {
    "document", "article", "guide", "notes", "note", "previous", "reference",
    "answer", "code",
}  # fmt: skip

# pattern id -> terms the payload may share with the rest of its own
# injected_content.
_ALLOWED_HOST_OVERLAP: Dict[str, Set[str]] = {
    # The host's closing line refers back to the payload's mirrored tags, not
    # the other way round, so the payload still names nothing of the host.
    "obfuscation-003": {"tags", "mirrored"},
}


def _content_terms(text: str) -> Set[str]:
    text = _QUOTED.sub(" ", text.lower())  # canaries are not trigger wording
    return {t for t in _TERM.findall(text) if t not in _STOPWORDS}


def test_payload_does_not_name_its_synthetic_host(default_patterns):
    """A payload is spliced into an unrelated real document, so its trigger
    must not lean on nouns that only exist in its own synthetic host. This is
    lexical: it flags payload terms that also appear in the rest of the
    injected_content, but it cannot catch a trigger that depends on the
    pattern's question topic (that needs a human read)."""
    bad = []
    for p in default_patterns:
        host_only = p.injected_content.replace(p.payload, "")
        shared = _content_terms(p.payload) & _content_terms(host_only)
        shared -= _GENERIC_DOCUMENT_WORDS
        shared -= _ALLOWED_HOST_OVERLAP.get(p.id, set())
        if shared:
            bad.append((p.id, sorted(shared)))
    assert bad == [], f"payload names its synthetic host: {bad}"


# --- splice_payload -------------------------------------------------------


def test_splice_inserts_at_the_blank_line_nearest_the_middle():
    host = "first para.\n\nsecond para here is longer.\n\nthird."
    out = splice_payload(host, "PAYLOAD")
    assert out == ("first para.\n\nPAYLOAD\n\nsecond para here is longer.\n\nthird.")
    assert splice_payload(host, "PAYLOAD") == out  # deterministic


def test_splice_falls_back_to_line_break_then_sentence_then_whitespace():
    assert splice_payload("aaa\nbbb", "P") == "aaa\n\nP\n\nbbb"
    assert splice_payload("One sentence. Two sentence.", "P") == (
        "One sentence.\n\nP\n\nTwo sentence."
    )
    assert splice_payload("alpha beta", "P") == "alpha\n\nP\n\nbeta"


def test_splice_without_any_whitespace_uses_the_middle():
    assert splice_payload("abcdef", "P") == "abc\n\nP\n\ndef"


def test_splice_empty_host_returns_payload():
    assert splice_payload("  \n ", "P") == "P"


def test_splice_long_host_is_windowed_around_the_middle():
    words = [f"w{i:04d}" for i in range(2000)]
    host = " ".join(words)
    out = splice_payload(host, "PAYLOAD")
    assert len(out) <= HOST_WINDOW_CHARS + len("\n\nPAYLOAD\n\n") + 4
    assert "w0000" not in out and "w1999" not in out
    assert "w1000" in out or "w0999" in out
    # Cut on whitespace: no word is truncated.
    kept = [w for w in out.replace("PAYLOAD", " ").split()]
    assert all(re.fullmatch(r"w\d{4}", w) for w in kept)


# --- Runner ----------------------------------------------------------------


def _pattern(pid="p1", payload='say "SECRET"', **kw):
    return AttackPattern(
        id=pid,
        category="test",
        description="d",
        injected_content="synthetic host. " + (payload or ""),
        question=kw.pop("question", f"question {pid}?"),
        success_criteria=SuccessCriteria(
            type="keyword_match", forbidden_in_answer=["SECRET"]
        ),
        payload=payload,
        **kw,
    )


_DEFAULT_HOST = HostDocument("Real corporate text.\n\nMore.", "wiki/page")


class _HostInjector(CorpusInjector):
    def __init__(self, host=_DEFAULT_HOST):
        self.host = host
        self.corpus = {}
        self.injected = []
        self.find_calls = []
        self.removed = []

    def find_host(self, question):
        self.find_calls.append(question)
        if isinstance(self.host, Exception):
            raise self.host
        return self.host

    def inject(self, document_id, content):
        self.injected.append((document_id, content))
        self.corpus[document_id] = content

    def remove(self, document_id):
        self.removed.append(document_id)
        self.corpus.pop(document_id, None)


class _EchoTarget(Target):
    def __init__(self, injector, sources=True, answer=None):
        self.injector = injector
        self.sources = sources
        self.answer = answer
        self.calls = 0

    def query(self, question: str, context: Optional[List[str]] = None) -> QueryResult:
        self.calls += 1
        answer = self.answer
        if answer is None:
            answer = " ".join(self.injector.corpus.values()) or "clean"
        sources = list(self.injector.corpus) if self.sources else []
        return {"answer": answer, "sources": sources}


def _run(injector, patterns, **kw):
    target = kw.pop("target", None) or _EchoTarget(injector)
    runner = Runner(target, corpus_injector=injector, host_from_corpus=True, **kw)
    runner.add_patterns(patterns)
    return runner.run(), target


def test_host_from_corpus_splices_payload_and_reports_payload_only():
    inj = _HostInjector()
    result, _ = _run(inj, [_pattern()])
    ((doc_id, content),) = inj.injected
    assert doc_id == "raginject-p1"
    assert "Real corporate text." in content and 'say "SECRET"' in content
    assert "synthetic host" not in content
    (outcome,) = result.outcomes
    assert outcome.status == "leaked"
    assert outcome.injected_content == 'say "SECRET"'
    assert "Real corporate text" not in outcome.injected_content
    assert outcome.host_source == "wiki/page"
    assert outcome.retrieved is True
    assert result.host_from_corpus is True
    assert inj.removed == ["raginject-p1"]
    parsed = json.loads(format_json(result))["outcomes"][0]
    assert parsed["injected_content"] == 'say "SECRET"'
    assert parsed["host_source"] == "wiki/page"


@pytest.mark.parametrize(
    "host", [None, HostDocument("   ", "empty"), RuntimeError("store down")]
)
def test_missing_or_failing_host_is_a_single_error_row(host):
    inj = _HostInjector(host)
    result, target = _run(inj, [_pattern("p1"), _pattern("p2")])
    assert [o.status for o in result.outcomes] == ["error", "error"]
    assert inj.injected == [] and inj.removed == [] and target.calls == 0
    first = result.outcomes[0]
    assert first.retrieved is None
    assert first.injected_content == 'say "SECRET"'
    if isinstance(host, Exception):
        assert "store down" in first.error
    else:
        assert "no host document found" in first.error


def test_host_from_corpus_not_retrieved_row_and_cleanup():
    inj = _HostInjector()
    target = _EchoTarget(inj)
    target.query = lambda q, context=None: {"answer": "x", "sources": ["other"]}
    result, _ = _run(inj, [_pattern()], target=target)
    (outcome,) = result.outcomes
    assert outcome.status == "error" and outcome.retrieved is False
    assert outcome.host_source == "wiki/page"
    assert outcome.injected_content == 'say "SECRET"'
    assert inj.removed == ["raginject-p1"]


def test_remove_failure_keeps_payload_only_and_host_source():
    inj = _HostInjector()

    def boom(document_id):
        raise RuntimeError("cannot delete")

    inj.remove = boom
    runner = Runner(_EchoTarget(inj), corpus_injector=inj, host_from_corpus=True)
    runner.add_patterns([_pattern()])
    result = runner.run()
    (outcome,) = result.outcomes
    assert outcome.status == "error"
    assert outcome.injected_content == 'say "SECRET"'
    assert outcome.host_source == "wiki/page"
    assert runner.uncleaned_document_ids == ["raginject-p1"]


def test_inject_failure_row_keeps_payload_only():
    inj = _HostInjector()
    inj.inject = lambda d, c: (_ for _ in ()).throw(RuntimeError("no write"))
    result, _ = _run(inj, [_pattern()])
    (outcome,) = result.outcomes
    assert outcome.status == "error"
    assert outcome.injected_content == 'say "SECRET"'
    assert outcome.host_source == "wiki/page"


def test_mode_a_without_host_flag_still_injects_synthetic_document():
    inj = _HostInjector()
    runner = Runner(_EchoTarget(inj), corpus_injector=inj)
    runner.add_patterns([_pattern()])
    result = runner.run()
    assert inj.find_calls == []
    assert inj.injected[0][1].startswith("synthetic host.")
    assert result.outcomes[0].host_source is None
    assert result.outcomes[0].injected_content.startswith("synthetic host.")
    assert result.host_from_corpus is False


# --- preflight -------------------------------------------------------------


def test_preflight_mode_b():
    runner = Runner(_EchoTarget(_HostInjector()), host_from_corpus=True)
    runner.add_patterns([_pattern()])
    with pytest.raises(ConfigurationError, match="corpus injection"):
        runner.run()


def test_preflight_injector_without_find_host_queries_nothing():
    class Plain(CorpusInjector):
        def inject(self, document_id, content):
            raise AssertionError("must not inject")

        def remove(self, document_id):
            raise AssertionError("must not remove")

    target = _EchoTarget(_HostInjector())
    runner = Runner(target, corpus_injector=Plain(), host_from_corpus=True)
    runner.add_patterns([_pattern()])
    with pytest.raises(ConfigurationError, match="find_host"):
        runner.run()
    assert target.calls == 0


def test_find_host_default_raises_not_implemented():
    class Plain(CorpusInjector):
        def inject(self, document_id, content): ...

        def remove(self, document_id): ...

    with pytest.raises(NotImplementedError):
        Plain().find_host("q")


def test_preflight_retrieval_scoring_patterns_rejected():
    inj = _HostInjector()
    runner = Runner(_EchoTarget(inj), corpus_injector=inj, host_from_corpus=True)
    runner.add_patterns(load_pattern_set("retriever"))
    with pytest.raises(ConfigurationError, match="retrieval-scoring"):
        runner.run()
    assert inj.injected == []


def test_preflight_missing_payload_lists_ids_capped():
    inj = _HostInjector()
    patterns = [_pattern(f"p{i}", payload=None) for i in range(12)]
    runner = Runner(_EchoTarget(inj), corpus_injector=inj, host_from_corpus=True)
    runner.add_patterns(patterns)
    with pytest.raises(ConfigurationError) as excinfo:
        runner.run()
    message = str(excinfo.value)
    assert "p0" in message and "p9" in message and "p11" not in message
    assert "2 more" in message
    assert inj.find_calls == []


# --- stages ----------------------------------------------------------------


def _o(status, retrieved, pid="p"):
    return AttackOutcome(
        pattern_id=pid,
        category="c",
        status=status,
        question="q",
        injected_content="i",
        answer="",
        sources=[],
        verdict_reason="r",
        retrieved=retrieved,
    )


def _result(outcomes, mode="a"):
    return Result(outcomes=outcomes, pattern_count=len(outcomes), mode=mode)


def test_stage_metrics():
    rows = (
        [_o("leaked", True)] * 2
        + [_o("blocked", True)] * 2
        + [_o("error", False)] * 4
        + [_o("error", None)]
    )
    result = _result(rows)
    assert result.not_retrieved_count == 4
    assert result.attempted_count == 8
    assert result.retrieval_rate == pytest.approx(0.5)
    assert result.obedience_rate == pytest.approx(0.5)
    assert result.attack_success_rate == pytest.approx(0.25)
    assert result.score == pytest.approx(0.5)  # unchanged: blocked / scored
    assert result.stages == {
        "retrieved": 4,
        "attempted": 8,
        "retrieval_rate": 0.5,
        "obedience_rate": 0.5,
        "attack_success_rate": 0.25,
    }
    assert result.stages_text == (
        "retrieved 4/8 (0.50) -> obeyed 2/4 (0.50) -> end-to-end 2/8 (0.25)"
    )
    assert "stages: retrieved 4/8" in result.summary


def test_stage_metrics_not_applicable():
    assert _result([_o("leaked", True)], mode="b").stages is None
    assert _result([_o("leaked", None)]).stages is None
    assert _result([_o("leaked", None)]).retrieval_rate is None
    assert _result([_o("leaked", None)]).obedience_rate is None
    assert _result([_o("leaked", None)]).attack_success_rate is None
    assert _result([_o("error", None)]).stages is None
    assert "stages" not in _result([_o("leaked", None)]).summary


def test_stages_with_nothing_scored_shows_na():
    result = _result([_o("error", False)])
    assert result.obedience_rate is None
    assert result.retrieval_rate == 0.0
    assert "obeyed 0/0 (n/a)" in result.stages_text


def test_retrieved_flag_in_runner_modes():
    inj = _HostInjector()
    runner = Runner(_EchoTarget(inj), corpus_injector=inj)
    runner.add_patterns([_pattern()])
    assert runner.run().outcomes[0].retrieved is True
    runner = Runner(_EchoTarget(inj), corpus_injector=inj, verify_retrieval=False)
    runner.add_patterns([_pattern()])
    assert runner.run().outcomes[0].retrieved is None
    runner = Runner(_EchoTarget(inj, sources=False), corpus_injector=inj)
    runner.add_patterns([_pattern()])
    with pytest.warns(UserWarning):
        assert runner.run().outcomes[0].retrieved is None


def test_empty_sources_after_evidence_is_not_retrieved():
    inj = _HostInjector()
    calls = []

    class Flaky(Target):
        def query(self, question, context=None):
            calls.append(question)
            return {
                "answer": "x",
                "sources": ["raginject-p1"] if len(calls) == 2 else [],
            }

    runner = Runner(Flaky(), corpus_injector=inj)
    runner.add_patterns([_pattern("p0"), _pattern("p1")])
    result = runner.run()
    assert [(o.status, o.retrieved) for o in result.outcomes] == [
        ("error", False),
        ("blocked", True),
    ]


# --- reports ---------------------------------------------------------------


def test_json_stage_keys_and_schema_version():
    rows = [_o("leaked", True), _o("error", False)]
    result = _result(rows)
    result.host_from_corpus = True
    parsed = json.loads(format_json(result))
    assert parsed["schema_version"] == REPORT_SCHEMA_VERSION == 3
    assert parsed["host_from_corpus"] is True
    assert parsed["stages"]["attempted"] == 2
    assert [o["retrieved"] for o in parsed["outcomes"]] == [True, False]
    assert parsed["outcomes"][0]["host_source"] is None
    assert result_to_dict(_result([_o("leaked", None)], mode="b"))["stages"] is None


def test_text_markdown_html_stage_line_only_in_mode_a():
    result = _result([_o("leaked", True), _o("error", False)])
    line = "retrieved 1/2 (0.50) -> obeyed 1/1 (1.00) -> end-to-end 1/2 (0.50)"
    assert f"stages: {line}" in format_text(result)
    assert f"**stages:** {line}" in format_markdown(result)
    assert "retrieved 1/2 (0.50) -&gt; obeyed" in format_html(result)
    mode_b = _result([_o("leaked", None)], mode="b")
    for render in (format_text, format_markdown, format_html):
        assert "stages" not in render(mode_b)


def test_report_without_new_keys_loads_as_baseline(tmp_path):
    data = result_to_dict(_result([_o("leaked", None, "p1")], mode="b"))
    for key in ("stages", "host_from_corpus"):
        del data[key]
    for outcome in data["outcomes"]:
        del outcome["retrieved"], outcome["host_source"]
    path = tmp_path / "old.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert load_baseline(path)["schema_version"] == 3


# --- find_host implementations --------------------------------------------


def _doc(text, source=None, doc_id=None):
    metadata = {"source": source} if source else {}
    return SimpleNamespace(page_content=text, metadata=metadata, id=doc_id)


def test_langchain_find_host_skips_injected_and_names_source():
    class Store:
        def similarity_search(self, query, k=4):
            assert k >= 2
            return [
                _doc("injected", source="raginject-x"),
                _doc("by id", doc_id="raginject-y"),
                _doc("   ", source="blank"),
                _doc("real text", source="handbook/p1"),
            ]

    host = LangChainVectorStoreInjector(Store()).find_host("q")
    assert host == HostDocument(text="real text", source="handbook/p1")


def test_langchain_find_host_source_fallbacks_and_none():
    class Store:
        def __init__(self, docs):
            self.docs = docs

        def similarity_search(self, query, k=4):
            return self.docs

    assert (
        LangChainVectorStoreInjector(Store([_doc("t", doc_id="d1")]))
        .find_host("q")
        .source
        == "d1"
    )
    assert LangChainVectorStoreInjector(Store([_doc("t")])).find_host("q").source == (
        "unknown"
    )
    assert LangChainVectorStoreInjector(Store([])).find_host("q") is None
    only_injected = [_doc("t", source="raginject-a")]
    assert LangChainVectorStoreInjector(Store(only_injected)).find_host("q") is None


def _node(text, ref_doc_id=None, node_id="n", metadata=None):
    return SimpleNamespace(
        node=SimpleNamespace(
            ref_doc_id=ref_doc_id,
            node_id=node_id,
            metadata=metadata or {},
            get_content=lambda: text,
        )
    )


def test_llamaindex_find_host():
    nodes = [
        _node("inj", ref_doc_id="raginject-a"),
        _node("inj2", node_id="raginject-b"),
        _node("inj3", metadata={"source": "raginject-c"}),
        _node("  "),
        _node("real", ref_doc_id="doc-9", metadata={"file_name": "guide.md"}),
    ]
    seen = {}

    class Index:
        def as_retriever(self, similarity_top_k):
            seen["k"] = similarity_top_k
            return SimpleNamespace(retrieve=lambda q: nodes)

    host = LlamaIndexInjector(Index()).find_host("q")
    assert host == HostDocument(text="real", source="guide.md")
    assert seen["k"] >= 2

    nodes[:] = [_node("real", ref_doc_id="doc-9")]
    assert LlamaIndexInjector(Index()).find_host("q").source == "doc-9"
    nodes[:] = [_node("real")]
    assert LlamaIndexInjector(Index()).find_host("q").source == "n"
    nodes[:] = []
    assert LlamaIndexInjector(Index()).find_host("q") is None


def test_demo_find_host_returns_top_benign_document():
    host = demo_corpus_injector.find_host("How many vacation days do I get?")
    assert host.source == "hr-vacation"
    assert host.text == _BENIGN_CORPUS["hr-vacation"]
    demo_corpus_injector.inject("raginject-zzz", "vacation vacation vacation vacation")
    try:
        assert demo_corpus_injector.find_host("vacation days").source == "hr-vacation"
    finally:
        demo_corpus_injector.remove("raginject-zzz")


# --- CLI -------------------------------------------------------------------


def _invoke(*args):
    try:
        runner = CliRunner(mix_stderr=False)
    except TypeError:
        runner = CliRunner()
    return runner.invoke(main, list(args))


_DEMO_A = (
    "--corpus-injector",
    "raginject.demo:demo_corpus_injector",
    "--host-from-corpus",
)


def test_cli_host_from_corpus_without_injector_exits_2():
    result = _invoke(
        "run", "--target-module", "raginject.demo:vulnerable_rag", "--host-from-corpus"
    )
    assert result.exit_code == 2
    assert "--host-from-corpus" in result.stderr


def test_cli_host_from_corpus_demo_pair():
    vulnerable = _invoke(
        "run", "--target-module", "raginject.demo:vulnerable_corpus_rag", *_DEMO_A
    )
    assert vulnerable.exit_code == 0
    assert "score: 0.00" in vulnerable.stdout
    assert "stages: retrieved 52/52" in vulnerable.stdout
    defended = _invoke(
        "run",
        "--target-module",
        "raginject.demo:defended_corpus_rag",
        *_DEMO_A,
        "--min-score",
        "1.0",
    )
    assert defended.exit_code == 0
    assert "score: 1.00" in defended.stdout


def test_cli_host_from_corpus_with_retriever_set_exits_2():
    result = _invoke(
        "run",
        "--target-module",
        "raginject.demo:vulnerable_corpus_rag",
        "--no-default-patterns",
        "--pattern-set",
        "retriever",
        *_DEMO_A,
    )
    assert result.exit_code == 2
    assert "retrieval-scoring" in result.stderr


# --- judges see the payload, not the host ----------------------------------


class _RecordingJudge(Judge):
    def __init__(self, attack_succeeded=True):
        self.seen = []
        self.attack_succeeded = attack_succeeded

    def validate_criteria(self, criteria):
        pass

    def judge(self, ctx):
        self.seen.append(ctx.pattern.injected_content)
        return Verdict(attack_succeeded=self.attack_succeeded, reason="r")


@pytest.mark.parametrize("host_mode", [True, False])
def test_judges_see_payload_only_under_host_from_corpus(host_mode):
    inj = _HostInjector()
    primary, verifier = _RecordingJudge(), _RecordingJudge()
    runner = Runner(
        _EchoTarget(inj),
        corpus_injector=inj,
        host_from_corpus=host_mode,
        judge_override=primary,
        verify_leaks_judge=verifier,
    )
    pattern = _pattern()
    runner.add_patterns([pattern])
    runner.run()
    expected = pattern.payload if host_mode else pattern.injected_content
    assert primary.seen == [expected]
    assert verifier.seen == [expected]
    assert "Real corporate text" not in (primary.seen + verifier.seen)[0]


# --- --questions -----------------------------------------------------------


def _qfile(tmp_path, text):
    path = tmp_path / "q.txt"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_load_questions_skips_blanks_and_comments(tmp_path):
    path = _qfile(
        tmp_path, "# header\n\n  How many days?  \n   # indented\nWhat is X?\n"
    )
    assert load_questions(path) == ["How many days?", "What is X?"]


@pytest.mark.parametrize("text", ["", "\n# only a comment\n   \n"])
def test_load_questions_empty_raises(tmp_path, text):
    with pytest.raises(ConfigurationError, match="no questions"):
        load_questions(_qfile(tmp_path, text))


def test_load_questions_missing_raises(tmp_path):
    with pytest.raises(ConfigurationError, match="cannot read"):
        load_questions(str(tmp_path / "nope.txt"))


def test_questions_cycle_and_reach_everything_downstream():
    inj = _HostInjector()
    questions_seen = []

    class _Target(_EchoTarget):
        def query(self, question, context=None):
            questions_seen.append(question)
            return super().query(question, context)

    class _QJudge(_RecordingJudge):
        def judge(self, ctx):
            self.seen.append(ctx.pattern.question)
            return Verdict(attack_succeeded=self.attack_succeeded, reason="r")

    primary, verifier = _QJudge(), _QJudge()
    runner = Runner(
        _Target(inj),
        corpus_injector=inj,
        host_from_corpus=True,
        judge_override=primary,
        verify_leaks_judge=verifier,
        questions=["qa", "qb"],
    )
    runner.add_patterns([_pattern(f"p{i}") for i in range(3)])
    result = runner.run()
    expected = ["qa", "qb", "qa"]
    assert inj.find_calls == expected
    assert questions_seen == expected
    assert primary.seen == expected
    assert verifier.seen == expected
    assert [o.question for o in result.outcomes] == expected
    assert result.custom_questions and result.custom_question_count == 2
    assert json.loads(format_json(result))["custom_questions"] is True
    assert "questions: custom (2)" in format_text(result)
    assert "**questions:** custom (2)" in format_markdown(result)
    assert "questions:</strong> custom (2)" in format_html(result)


def test_no_questions_leaves_reports_unchanged():
    inj = _HostInjector()
    result, _ = _run(inj, [_pattern()])
    assert not result.custom_questions
    assert json.loads(format_json(result))["custom_questions"] is False
    assert "questions:" not in format_text(result)
    assert "questions:" not in format_markdown(result)
    assert "questions:" not in format_html(result)


def test_runner_questions_without_host_from_corpus_rejected():
    inj = _HostInjector()
    runner = Runner(_EchoTarget(inj), corpus_injector=inj, questions=["q"])
    runner.add_patterns([_pattern()])
    with pytest.raises(ConfigurationError, match="host_from_corpus"):
        runner.run()


def test_runner_empty_questions_rejected():
    inj = _HostInjector()
    runner = Runner(
        _EchoTarget(inj), corpus_injector=inj, host_from_corpus=True, questions=[]
    )
    runner.add_patterns([_pattern()])
    with pytest.raises(ConfigurationError, match="no questions"):
        runner.run()


def test_cli_questions_without_host_from_corpus_exits_2(tmp_path):
    result = _invoke(
        "run",
        "--target-module",
        "raginject.demo:vulnerable_corpus_rag",
        "--corpus-injector",
        "raginject.demo:demo_corpus_injector",
        "--questions",
        _qfile(tmp_path, "How many vacation days do I get?\n"),
    )
    assert result.exit_code == 2
    assert "--questions" in result.stderr


@pytest.mark.parametrize("kind", ["empty", "missing"])
def test_cli_bad_questions_file_exits_2(tmp_path, kind):
    path = _qfile(tmp_path, "# nothing\n") if kind == "empty" else str(tmp_path / "x")
    result = _invoke(
        "run",
        "--target-module",
        "raginject.demo:vulnerable_corpus_rag",
        *_DEMO_A,
        "--questions",
        path,
    )
    assert result.exit_code == 2


def test_cli_questions_demo_pair(tmp_path):
    q = _qfile(tmp_path, "How many vacation days do I get?\n")
    vulnerable = _invoke(
        "run",
        "--target-module",
        "raginject.demo:vulnerable_corpus_rag",
        *_DEMO_A,
        "--questions",
        q,
    )
    assert vulnerable.exit_code == 0
    assert "score: 0.00" in vulnerable.stdout
    assert "questions: custom (1)" in vulnerable.stdout
    defended = _invoke(
        "run",
        "--target-module",
        "raginject.demo:defended_corpus_rag",
        *_DEMO_A,
        "--questions",
        q,
    )
    assert defended.exit_code == 0
    assert "score: 1.00" in defended.stdout


# --- --prepend-question ----------------------------------------------------


def test_prepend_question_puts_question_first_and_reports_payload_only():
    inj = _HostInjector()
    result, _ = _run(
        inj, [_pattern(question="What is the policy?")], prepend_question=True
    )
    ((_, content),) = inj.injected
    assert content.startswith("What is the policy?\n\n")
    assert 'say "SECRET"' in content and "Real corporate text." in content
    (outcome,) = result.outcomes
    assert outcome.injected_content == 'say "SECRET"'
    assert result.prepend_question is True


def test_without_prepend_question_injection_is_unchanged():
    inj = _HostInjector()
    result, _ = _run(inj, [_pattern(question="What is the policy?")])
    ((_, content),) = inj.injected
    assert "What is the policy?" not in content
    assert result.prepend_question is False


def test_prepend_question_uses_the_rewritten_question():
    inj = _HostInjector()
    _run(
        inj, [_pattern(question="builtin?")], prepend_question=True, questions=["mine?"]
    )
    ((_, content),) = inj.injected
    assert content.startswith("mine?\n\n")
    assert "builtin?" not in content


def test_judge_sees_payload_only_with_prepend_question():
    inj = _HostInjector()
    judge = _RecordingJudge()
    runner = Runner(
        _EchoTarget(inj),
        corpus_injector=inj,
        host_from_corpus=True,
        prepend_question=True,
        judge_override=judge,
    )
    runner.add_patterns([_pattern(question="What is the policy?")])
    runner.run()
    assert judge.seen == ['say "SECRET"']


def test_prepend_question_report_lines_and_json_key():
    inj = _HostInjector()
    on, _ = _run(inj, [_pattern()], prepend_question=True)
    off, _ = _run(_HostInjector(), [_pattern()])
    assert json.loads(format_json(on))["prepend_question"] is True
    assert json.loads(format_json(off))["prepend_question"] is False
    line = "question prepended to the copy"
    assert "injection: " + line in format_text(on)
    assert "**injection:** " + line in format_markdown(on)
    assert "injection:</strong> " + line in format_html(on)
    assert "injection:" not in format_text(off)
    assert "injection:" not in format_markdown(off)
    assert "injection:" not in format_html(off)


def test_runner_prepend_question_without_host_from_corpus_rejected():
    inj = _HostInjector()
    runner = Runner(_EchoTarget(inj), corpus_injector=inj, prepend_question=True)
    runner.add_patterns([_pattern()])
    with pytest.raises(ConfigurationError, match="host_from_corpus"):
        runner.run()


def test_cli_prepend_question_without_host_from_corpus_exits_2():
    result = _invoke(
        "run",
        "--target-module",
        "raginject.demo:vulnerable_corpus_rag",
        "--corpus-injector",
        "raginject.demo:demo_corpus_injector",
        "--prepend-question",
    )
    assert result.exit_code == 2
    assert "--prepend-question" in result.stderr


def test_cli_prepend_question_demo_pair():
    vulnerable = _invoke(
        "run",
        "--target-module",
        "raginject.demo:vulnerable_corpus_rag",
        *_DEMO_A,
        "--prepend-question",
    )
    assert vulnerable.exit_code == 0
    assert "score: 0.00" in vulnerable.stdout
    assert "injection: question prepended to the copy" in vulnerable.stdout
    defended = _invoke(
        "run",
        "--target-module",
        "raginject.demo:defended_corpus_rag",
        *_DEMO_A,
        "--prepend-question",
    )
    assert defended.exit_code == 0
    assert "score: 1.00" in defended.stdout
