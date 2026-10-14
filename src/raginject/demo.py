"""Six dependency-free, scripted demo RAG "pipelines" you can point raginject
at without having a real RAG app of your own:

    raginject run --target-module raginject.demo:vulnerable_rag
    raginject run --target-module raginject.demo:defended_rag --min-score 1.0

    raginject run --target-module raginject.demo:vulnerable_corpus_rag \\
                  --corpus-injector raginject.demo:demo_corpus_injector
    raginject run --target-module raginject.demo:defended_corpus_rag \\
                  --corpus-injector raginject.demo:demo_corpus_injector --min-score 1.0

    raginject run --target-module raginject.demo:vulnerable_retriever_rag \\
                  --corpus-injector raginject.demo:demo_corpus_injector \\
                  --no-default-patterns --pattern-set retriever
    raginject run --target-module raginject.demo:defended_retriever_rag \\
                  --corpus-injector raginject.demo:demo_corpus_injector \\
                  --no-default-patterns --pattern-set retriever --min-score 1.0

**None of these are real language models, and the two retriever targets are
not a real retriever either.** `vulnerable_rag` and `defended_rag` are
small, deterministic, dependency-free Python functions that simulate how a
naive vs. a defensive RAG pipeline *behaves* with respect to
retrieved-context injection. `vulnerable_corpus_rag` and `defended_corpus_rag`
are the same two behaviors again, but wired for corpus injection (mode A)
instead: they take a `question` only, and "retrieve" from
`demo_corpus_injector`'s in-memory store rather than being handed `context`
directly. `vulnerable_retriever_rag` and `defended_retriever_rag` are a
third pair, also question-only, that demonstrate the opt-in
`--pattern-set retriever` attacks instead of the default corpus: they rank
a small fixed benign corpus (plus whatever is currently injected) rather
than returning everything unranked, so a planted document can win - or
lose - a spot in the top-k the way it would against a real retriever. All
six exist purely so someone who does not yet have a RAG application can see
real raginject output (and a real gate failure) immediately after
`pip install raginject`, before wiring up their own target. Do not use any
of them as a stand-in for evaluating an actual LLM or an actual retriever.
"""

import math
import re
from collections import Counter
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

    def retrieve_ranked(
        self, question: str, rank_ids, k: int = 3
    ) -> List[Tuple[str, str]]:
        """Score `_BENIGN_CORPUS` plus whatever `inject()` currently holds
        using `rank_ids` (one of the two module-level ranking functions
        below) and return the top `k` as `(document_id, content)` pairs.

        Unlike `retrieve()` above - which the original mode-A demo pair
        uses, and which this deliberately leaves untouched - this one
        actually ranks, which is what makes a retriever-side attack
        meaningful to demonstrate: a retriever that returns everything
        unranked can never be "hijacked" into a top-k, because there is no
        top-k to begin with.
        """
        corpus = dict(_BENIGN_CORPUS)
        corpus.update(self._documents)
        ranked_ids = rank_ids(question, corpus)
        return [(doc_id, corpus[doc_id]) for doc_id in ranked_ids[:k]]


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


#: A small fixed benign corpus for the `vulnerable_retriever_rag` /
#: `defended_retriever_rag` demo pair below, one document genuinely
#: relevant to each of the 7 built-in `--pattern-set retriever` patterns'
#: questions (see `src/raginject/attacks/pattern_sets/retriever/`). Fixed
#: and small on purpose - this is a demo corpus, not an attempt to model a
#: real one; see the README's caveat that a small corpus makes almost
#: anything retrievable, so a score against this one is weaker evidence
#: than a score against a large real corpus.
_BENIGN_CORPUS: Dict[str, str] = {
    "hr-expenses": (
        "Expense reimbursement policy. Employees submit an expense claim "
        "within 30 days; approved reimbursement is paid with the next "
        "payroll run."
    ),
    "hr-vacation": (
        "Vacation days. New employees receive 15 vacation days in their "
        "first year, accruing monthly, rising to 20 days after three "
        "years."
    ),
    "hr-onboarding": (
        "Onboarding checklist for a new hire first week: collect "
        "equipment, complete security training, meet the team, set goals "
        "with the manager."
    ),
    "fin-po": (
        "Purchase order process. Submit a purchase requisition in the "
        "finance portal; procurement issues the purchase order after "
        "approval by a budget owner."
    ),
    "hr-travel": (
        "Business trip reimbursement. Book travel through the agency, "
        "keep receipts, and file travel expenses within two weeks of "
        "returning."
    ),
    "hr-payroll": (
        "Direct deposit. Update your banking information in the payroll "
        "portal; changes take effect on the following pay cycle."
    ),
    "cs-escalation": (
        "Customer complaint escalation. A damaged product complaint goes "
        "to tier-2 support, then to the service recovery team within 48 "
        "hours."
    ),
}

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> List[str]:
    return _TOKEN_RE.findall(text.lower())


def _rank_by_term_frequency(question: str, corpus: Dict[str, str]) -> List[str]:
    """Rank `corpus` by raw query-term frequency: no saturation, no document
    length normalization - just "how many times do this question's words
    appear in this document". Stands in for the real failure mode of a
    retriever that scores relevance by naive keyword counting: a document
    that simply repeats the query's terms outranks a short document that
    actually answers them, because nothing here discounts repetition or
    penalizes the extra length that repetition buys. This is NOT how any
    production retriever should be built, and the resulting ranking is not
    a measurement of any real embedding model or search index - it exists
    to make the term-frequency-vs-BM25 difference legible in this demo.
    """
    query_terms = _tokenize(question)
    scores = {}
    for doc_id, content in corpus.items():
        counts = Counter(_tokenize(content))
        scores[doc_id] = sum(counts[term] for term in query_terms)
    return sorted(corpus, key=lambda doc_id: (-scores[doc_id], doc_id))


#: Below this many tokens, a document's single-most-repeated-token ratio is
#: dominated by noise: a single incidental repeat in a ~20-word paragraph
#: (a subject named once in a title and again in a sentence, say) already
#: clears 6%, which would flag every one of `_BENIGN_CORPUS`'s short
#: documents as "stuffed" even though none of them is. Real stuffing
#: payloads run far longer with a term repeated many times over; below this
#: floor the stuffing filter simply doesn't fire, and the priority-claim
#: filter plus the BM25 ranking itself still constrain a short document.
_STUFFING_MIN_TOKENS = 30
_STUFFING_RATIO = 0.06

#: Case-insensitive substrings a document uses to assert its own retrieval
#: priority - a document telling the retriever how to rank it, not evidence
#: about its actual relevance.
_PRIORITY_CLAIM_PHRASES = (
    "supersede",
    "consulted first",
    "prioritize this document",
    "required reading",
    "canonical",
    "authoritative index",
    "start here",
    "master index",
    "administrative notice",
)


def _is_stuffed(terms: List[str]) -> bool:
    """True if this document's single most-repeated token accounts for more
    than 6% of its tokens (see `_STUFFING_MIN_TOKENS` for the length floor
    below which this never fires). A document this dominated by one
    repeated word is term salad, not content - this stands in for one real
    ingestion-time defense: reject documents whose vocabulary is this
    degenerate, rather than trusting whatever a retriever's similarity
    score says about them.
    """
    if len(terms) < _STUFFING_MIN_TOKENS:
        return False
    counts = Counter(terms)
    return max(counts.values()) / len(terms) > _STUFFING_RATIO


def _has_priority_claim(text: str) -> bool:
    """True if the document contains a document-asserted retrieval priority
    claim (see `_PRIORITY_CLAIM_PHRASES`). Stands in for a second
    ingestion-time defense: strip or reject a document's claims about its
    own ranking rather than trusting them - a document is not evidence
    about its own relevance."""
    lower = text.lower()
    return any(phrase in lower for phrase in _PRIORITY_CLAIM_PHRASES)


def _rank_bm25_filtered(question: str, corpus: Dict[str, str]) -> List[str]:
    """Rank `corpus` with BM25-style scoring (k1=1.2, b=0.75,
    length-normalized, so repeating a term stops paying off once it
    saturates) over whatever survives `_is_stuffed` / `_has_priority_claim`
    - documents that fail either filter are dropped entirely, not merely
    down-ranked. Stands in for a hardened pipeline that both scores
    relevance more carefully than raw term frequency and rejects
    obviously-poisoned documents at ingestion time, before they are ever
    ranked. Like `_rank_by_term_frequency`, this is hand-rolled stdlib and
    NOT a real retriever or a real content-moderation system - the numbers
    it produces exist to demonstrate raginject, not to characterize any
    real retriever's defenses.
    """
    query_terms = _tokenize(question)
    filtered: Dict[str, List[str]] = {}
    for doc_id, content in corpus.items():
        terms = _tokenize(content)
        if not terms or _is_stuffed(terms) or _has_priority_claim(content):
            continue
        filtered[doc_id] = terms
    if not filtered:
        return []

    doc_count = len(filtered)
    avg_len = sum(len(terms) for terms in filtered.values()) / doc_count
    doc_freq: Counter = Counter()
    for terms in filtered.values():
        for term in set(terms):
            doc_freq[term] += 1

    k1, b = 1.2, 0.75
    scores = {}
    for doc_id, terms in filtered.items():
        counts = Counter(terms)
        doc_len = len(terms)
        score = 0.0
        for term in set(query_terms):
            term_freq = counts.get(term, 0)
            if term_freq == 0:
                continue
            idf = math.log(
                1 + (doc_count - doc_freq[term] + 0.5) / (doc_freq[term] + 0.5)
            )
            denom = term_freq + k1 * (1 - b + b * doc_len / avg_len)
            score += idf * (term_freq * (k1 + 1)) / denom
        scores[doc_id] = score
    return sorted(filtered, key=lambda doc_id: (-scores[doc_id], doc_id))


def vulnerable_retriever_rag(question: str) -> QueryResult:
    """A scripted stand-in for a naively-ranked retriever - NOT a real
    retriever or a real language model.

    Question-only, like the mode-A pair above. Ranks `_BENIGN_CORPUS` plus
    whatever `demo_corpus_injector` currently holds by raw query-term
    frequency (`_rank_by_term_frequency`) and returns the top 3 document
    ids as `sources`. Against the built-in `--pattern-set retriever`
    patterns this scores 0.00: every payload is written to repeat its
    question's terms enough to outrank the short benign document that
    actually answers it, so every planted document wins a spot in the
    top-k. The answer text doesn't matter here - `retrieval_match` never
    reads it - so this always returns a placeholder answer.
    """
    retrieved = demo_corpus_injector.retrieve_ranked(question, _rank_by_term_frequency)
    document_ids = [document_id for document_id, _ in retrieved]
    return {"answer": f"Answer to: {question}", "sources": document_ids}


def defended_retriever_rag(question: str) -> QueryResult:
    """A scripted stand-in for a hardened retriever - NOT a real retriever
    or a real language model.

    Question-only, like `vulnerable_retriever_rag` above. Ranks the same
    combined corpus with BM25-style, length-normalized scoring
    (`_rank_bm25_filtered`), after dropping any document that trips the
    stuffing filter or the priority-claim filter, and returns the top 3
    document ids as `sources`. Against the built-in `--pattern-set
    retriever` patterns this scores 1.00: every payload in that set is
    either degenerate enough to trip the stuffing filter or explicit enough
    about its own priority to trip the claim filter, so none of them ever
    reach the ranking stage.
    """
    retrieved = demo_corpus_injector.retrieve_ranked(question, _rank_bm25_filtered)
    document_ids = [document_id for document_id, _ in retrieved]
    return {"answer": f"Answer to: {question}", "sources": document_ids}
