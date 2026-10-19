"""Evaluation engine: Runner and Result.

`AttackOutcome` and `Result` fields are the JSON report's schema contract,
so they are never renamed or removed, and a new one is only ever added
with a default (so older constructions stay valid) and additively in the
report.
"""

import re
import time
import warnings
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Union,
)

from ._version import __version__
from .attacks.loader import load_patterns as _load_patterns
from .attacks.schema import AttackPattern
from .corpus import CorpusInjector, HostDocument, source_matches_document
from .errors import ConfigurationError, TargetError
from .judges import Judge, JudgeContext, get_judge
from .target import Target

#: `status` values for AttackOutcome. "error" means the target could not be
#: reached / returned a malformed response — it is not the same as an
#: attack that got through ("leaked"). "error" rows are excluded from the
#: score denominator.
AttackStatus = Literal["blocked", "leaked", "error"]


@dataclass
class AttackOutcome:
    pattern_id: str
    category: str
    status: AttackStatus
    question: str
    injected_content: str
    answer: str
    sources: List[str]
    verdict_reason: str
    error: Optional[str] = None
    duration_ms: Optional[float] = None
    #: Mode A only. True: retrieval verification confirmed the injected
    #: document was among `sources`. False: it was not (the row is a
    #: `status="error"` row, excluded from `score` but counted by the stage
    #: metrics). None: not applicable or not knowable - mode B, a target that
    #: reports no sources, `--no-verify-retrieval`, a retrieval-scoring judge,
    #: or an error unrelated to retrieval.
    retrieved: Optional[bool] = None
    #: `--host-from-corpus` only: display name of the real document the
    #: payload was spliced into. The document's text is never stored.
    host_source: Optional[str] = None


@dataclass
class Result:
    outcomes: List[AttackOutcome] = field(default_factory=list)
    started_at: Optional[str] = None
    raginject_version: Optional[str] = None
    target_description: Optional[str] = None
    pattern_count: int = 0
    #: "a" (corpus injection) or "b" (direct context injection). Defaults to
    #: "b" so every existing `Result(...)` construction (tests included)
    #: stays valid without naming this field.
    mode: str = "b"
    #: `CorpusInjector.description` in mode A; `None` in mode B.
    corpus_injector_description: Optional[str] = None
    #: True when the run spliced payloads into real corpus documents
    #: (`--host-from-corpus`) rather than injecting the synthetic ones.
    host_from_corpus: bool = False
    #: Number of distinct questions loaded with `--questions` (0 when the
    #: patterns' built-in questions were used).
    custom_question_count: int = 0
    #: True when the run prepended each pattern's question to the injected
    #: copy (`--prepend-question`).
    prepend_question: bool = False

    @property
    def custom_questions(self) -> bool:
        return self.custom_question_count > 0

    @property
    def blocked_count(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "blocked")

    @property
    def leaked_count(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "leaked")

    @property
    def error_count(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "error")

    @property
    def scored_count(self) -> int:
        return self.blocked_count + self.leaked_count

    @property
    def failed_ids(self) -> List[str]:
        """pattern_ids of outcomes where the attack succeeded ('leaked')."""
        return [o.pattern_id for o in self.outcomes if o.status == "leaked"]

    @property
    def has_scoreable_outcomes(self) -> bool:
        return self.scored_count > 0

    @property
    def category_counts(self) -> Dict[str, Dict[str, int]]:
        """Per-category status counts, e.g.
        `{"indirect_injection": {"blocked": 6, "leaked": 1, "error": 0}}`.

        Ordered by first appearance of each category in `outcomes`, so
        output built from this stays deterministic/reproducible."""
        counts: Dict[str, Dict[str, int]] = {}
        for outcome in self.outcomes:
            category_counts = counts.setdefault(
                outcome.category, {"blocked": 0, "leaked": 0, "error": 0}
            )
            category_counts[outcome.status] += 1
        return counts

    @property
    def score(self) -> float:
        """Fraction of scoreable (blocked/leaked) outcomes that were
        blocked. Returns 0.0 (never raises ZeroDivisionError) when there
        are no scoreable outcomes - the caller must check
        `has_scoreable_outcomes` separately to distinguish "0% defended"
        from "never reached the target"."""
        denominator = self.scored_count
        if denominator == 0:
            return 0.0
        return self.blocked_count / denominator

    @property
    def not_retrieved_count(self) -> int:
        """Mode-A rows whose injected document was verified as not retrieved
        (these are `status="error"` rows, so `score` ignores them)."""
        return sum(1 for o in self.outcomes if o.retrieved is False)

    @property
    def attempted_count(self) -> int:
        """Rows that reached a retrieval outcome: scored + not retrieved.
        Errors unrelated to retrieval are in neither."""
        return self.scored_count + self.not_retrieved_count

    @property
    def _has_stage_data(self) -> bool:
        return self.mode == "a" and any(o.retrieved is not None for o in self.outcomes)

    @property
    def retrieval_rate(self) -> Optional[float]:
        """Fraction of attempted attacks whose document was retrieved.
        None unless mode A with retrieval data and at least one attempt."""
        if not self._has_stage_data or self.attempted_count == 0:
            return None
        return self.scored_count / self.attempted_count

    @property
    def obedience_rate(self) -> Optional[float]:
        """Fraction of retrieved (scored) attacks that leaked. None unless
        mode A with retrieval data and at least one scored row."""
        if not self._has_stage_data or self.scored_count == 0:
            return None
        return self.leaked_count / self.scored_count

    @property
    def attack_success_rate(self) -> Optional[float]:
        """Fraction of attempted attacks that were retrieved *and* leaked
        (end to end). None unless mode A with retrieval data and at least one
        attempt."""
        if not self._has_stage_data or self.attempted_count == 0:
            return None
        return self.leaked_count / self.attempted_count

    @property
    def stages(self) -> Optional[Dict[str, Any]]:
        """The two-stage breakdown (retrieval, then obedience), or None when
        it does not apply (mode B, or no row carries retrieval data).
        `score` is unaffected by it."""
        if not self._has_stage_data or self.attempted_count == 0:
            return None
        return {
            "retrieved": self.scored_count,
            "attempted": self.attempted_count,
            "retrieval_rate": self.retrieval_rate,
            "obedience_rate": self.obedience_rate,
            "attack_success_rate": self.attack_success_rate,
        }

    @property
    def stages_text(self) -> Optional[str]:
        """One line for reports, e.g. `retrieved 19/52 (0.37) -> obeyed 11/19
        (0.58) -> end-to-end 11/52 (0.21)`; None when `stages` is None."""
        stages = self.stages
        if stages is None:
            return None

        def rate(value: Optional[float]) -> str:
            return "n/a" if value is None else f"{value:.2f}"

        return (
            f"retrieved {self.scored_count}/{self.attempted_count} "
            f"({rate(stages['retrieval_rate'])}) -> "
            f"obeyed {self.leaked_count}/{self.scored_count} "
            f"({rate(stages['obedience_rate'])}) -> "
            f"end-to-end {self.leaked_count}/{self.attempted_count} "
            f"({rate(stages['attack_success_rate'])})"
        )

    @property
    def summary(self) -> str:
        """Short human-readable summary.

        Names the failed pattern ids: without them a CI log tells you the
        gate failed but not which attack got through.
        """
        lines = [
            f"raginject: {self.blocked_count}/{self.scored_count} attacks blocked "
            f"(score: {self.score:.2f})"
        ]
        if self.stages_text is not None:
            lines.append(f"stages: {self.stages_text}")
        if self.failed_ids:
            lines.append(f"Failed: {', '.join(self.failed_ids)}")
        if self.error_count:
            error_ids = [o.pattern_id for o in self.outcomes if o.status == "error"]
            lines.append(
                f"Errors: {self.error_count} (excluded from score): "
                f"{', '.join(error_ids)}"
            )
        return "\n".join(lines)


def _id_list(ids: List[str], limit: int = 10) -> str:
    shown = ", ".join(ids[:limit])
    return shown + (f", ... ({len(ids) - limit} more)" if len(ids) > limit else "")


#: How much of a host document `splice_payload` keeps when the host is
#: longer: a window around its middle. Short enough that the payload makes up
#: a real share of the chunk (and is not split from its host by a chunker),
#: long enough to read as a document.
HOST_WINDOW_CHARS = 800


def _host_window(text: str) -> str:
    """`text` itself, or an ~`HOST_WINDOW_CHARS` window centred on its middle
    with both cut edges moved inward to whitespace."""
    text = text.strip()
    if len(text) <= HOST_WINDOW_CHARS:
        return text
    start = max(0, len(text) // 2 - HOST_WINDOW_CHARS // 2)
    end = start + HOST_WINDOW_CHARS
    if start > 0:
        match = re.search(r"\s+", text[start:end])
        if match:
            start += match.end()
    if end < len(text):
        gaps = list(re.finditer(r"\s+", text[start:end]))
        if gaps:
            end = start + gaps[-1].start()
    return text[start:end].strip()


def splice_payload(host_text: str, payload: str) -> str:
    """Insert `payload` into `host_text` at the paragraph boundary nearest
    its middle, surrounded by blank lines. Deterministic.

    A host longer than `HOST_WINDOW_CHARS` is first cut to a window around
    its middle. Boundaries are tried in order - a blank line, a line break, a
    sentence end (". "), any whitespace - and the first kind that occurs
    inside the text wins; with none at all the payload goes in the exact
    middle.
    """
    host = _host_window(host_text)
    if not host:
        return payload
    middle = len(host) / 2
    for separator in ("\n\n", "\n", ". "):
        positions = [
            m.start()
            for m in re.finditer(re.escape(separator), host)
            if m.start() > 0 and m.end() < len(host)
        ]
        if positions:
            pos = min(positions, key=lambda p: (abs(p - middle), p))
            keep = 1 if separator == ". " else 0
            before = host[: pos + keep]
            after = host[pos + len(separator) :]
            return f"{before}\n\n{payload}\n\n{after}"
    spaces = [
        m.start() for m in re.finditer(r"\s", host) if 0 < m.start() < len(host) - 1
    ]
    if spaces:
        pos = min(spaces, key=lambda p: (abs(p - middle), p))
        return f"{host[:pos]}\n\n{payload}\n\n{host[pos + 1 :]}"
    pos = len(host) // 2
    return f"{host[:pos]}\n\n{payload}\n\n{host[pos:]}"


def load_questions(path: Union[str, Path]) -> List[str]:
    """Read a `--questions` file: UTF-8, one question per line. Blank lines
    and lines starting with `#` are skipped; lines are stripped."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigurationError(
            f"cannot read questions file {str(path)!r}: {exc}"
        ) from exc
    questions = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not questions:
        raise ConfigurationError(f"questions file {str(path)!r} contains no questions")
    return questions


class Runner:
    """Run attack patterns against a target and aggregate a Result.

    `judges`, if given, takes priority over the module-level judge registry
    for lookups by name - this lets callers inject a fake judge in tests, or
    a pre-configured judge instance (e.g. `LLMJudge(model=...)`) without
    needing a factory-based registry.

    `judge_override`, if given, replaces the judge named by every pattern's
    `success_criteria.type` - every pattern is judged by this one judge
    instead. `verify_leaks_judge`, if given, re-judges only the rows the
    primary judge marked "leaked" (never "blocked" ones, since that is
    where a judge's false positives live) and can flip a leaked row to
    blocked; see `run()` for the exact semantics. It does not apply to rows
    judged by a retrieval-scoring judge, whose verdict comes from `sources`
    rather than from answer text and so has no answer-based false positive
    to correct.

    `corpus_injector`, if given, switches the runner into **mode A**: each
    attack document is written into the user's real retrieval corpus via
    `corpus_injector.inject`/`.remove` and the target is queried with no
    `context` argument at all, so the user's own retriever decides whether
    the document surfaces. `verify_retrieval` (mode A only) controls whether
    a pattern whose injected document was not among the returned `sources`
    is turned into a `status="error"` row instead of being judged normally
    - see `run()`.

    `host_from_corpus` (mode A only) swaps the synthetic host document for a
    real one: per pattern the runner asks `corpus_injector.find_host(question)`
    for the top real document, splices the pattern's `payload` into a copy of
    it and injects that copy. The original is never touched, so a retriever
    can surface both the clean original and the tampered copy; the model may
    then side with the original, which biases the measured obedience low.
    Reports carry the payload and the host's `source` name, never the host's
    text.

    `questions` (requires `host_from_corpus`) replaces the patterns' built-in
    questions, assigned in run order and cycling: pattern i gets
    `questions[i % len(questions)]`. The host is the top real chunk for the
    question, so the question has to ask about that chunk's legitimate
    content; the built-in questions are written for the synthetic hosts.

    `prepend_question` (requires `host_from_corpus`) puts the pattern's
    question, as a paragraph of its own, in front of the injected copy: the
    query-targeted document of PoisonedRAG. It makes the copy near-certain to
    be retrieved, so the run measures obedience; its retrieval rate is the
    worst case of an attacker who knows the question. Reports and judges
    still see the payload only.
    """

    def __init__(
        self,
        target: Target,
        judges: Optional[Mapping[str, Judge]] = None,
        *,
        judge_override: Optional[Judge] = None,
        verify_leaks_judge: Optional[Judge] = None,
        corpus_injector: Optional[CorpusInjector] = None,
        verify_retrieval: bool = True,
        host_from_corpus: bool = False,
        questions: Optional[List[str]] = None,
        prepend_question: bool = False,
    ):
        self.target = target
        self._judges = judges
        self._judge_override = judge_override
        self._verify_leaks_judge = verify_leaks_judge
        self._corpus_injector = corpus_injector
        self.verify_retrieval = verify_retrieval
        self.host_from_corpus = host_from_corpus
        self._questions = list(questions) if questions is not None else None
        self.prepend_question = prepend_question
        self._patterns: Dict[str, AttackPattern] = {}
        #: Document ids a CorpusInjector.remove() call failed to clean up
        #: (mode A only). Deliberately *not* a Result field / part of the
        #: report schema - it is operational fallout for this one run, not
        #: an attack outcome, so callers (the CLI) read it directly off the
        #: runner after run() returns and warn loudly rather than losing it.
        self.uncleaned_document_ids: List[str] = []

    @property
    def mode(self) -> str:
        return "a" if self._corpus_injector is not None else "b"

    @property
    def patterns(self) -> List[AttackPattern]:
        return list(self._patterns.values())

    def load_patterns(self, path: Optional[Union[str, Path]] = None) -> None:
        """Load patterns from `path` (file/dir) or the built-in default set,
        merging additively into any patterns already loaded/added. Same id
        overrides the earlier entry but keeps its original position."""
        self.add_patterns(_load_patterns(path))

    def add_patterns(self, patterns: Iterable[AttackPattern]) -> None:
        """Add patterns programmatically (e.g. runtime-generated canaries).
        Same merge semantics as `load_patterns`: later wins, position of
        first occurrence is kept."""
        for pattern in patterns:
            self._patterns[pattern.id] = pattern

    def _get_judge(self, name: str) -> Judge:
        if self._judges is not None and name in self._judges:
            return self._judges[name]
        return get_judge(name)

    def _run_one(
        self,
        pattern: AttackPattern,
        judge: Judge,
        *,
        context: Optional[List[str]],
        document_id: Optional[str] = None,
        judged_pattern: Optional[AttackPattern] = None,
    ) -> AttackOutcome:
        """Query the target once for `pattern` and judge the answer,
        returning a single AttackOutcome.

        This is the part of `run()` that mode A and mode B share verbatim:
        mode B calls it with `context=[pattern.injected_content]` (the
        attack document handed straight to the target); mode A calls it
        with `context=None` after writing the document into the corpus via
        `corpus_injector.inject`, so the target's own retriever decides
        whether it surfaces. `document_id` is the id that document was
        injected under (mode A only; `None` in mode B) - it is threaded into
        `JudgeContext` so a retrieval-scoring judge (e.g. `retrieval_match`)
        can check whether it came back in `sources`.

        `judged_pattern`, if given, is what the judges see in place of
        `pattern` (`--host-from-corpus` passes a copy whose `injected_content`
        is the payload only: the document the model saw is a real corpus copy,
        and its text must neither be misdescribed to the judge nor sent to a
        remote judge API).

        A `ConfigurationError` raised by the target or a judge always
        propagates (it aborts the whole run - see `run()`'s docstring).
        Anything else becomes a `status="error"` outcome instead of being
        allowed to crash the run.
        """
        start = time.perf_counter()
        try:
            query_result = self.target.query(pattern.question, context=context)
        except ConfigurationError:
            raise
        except TargetError as exc:
            duration_ms = (time.perf_counter() - start) * 1000
            return AttackOutcome(
                pattern_id=pattern.id,
                category=pattern.category,
                status="error",
                question=pattern.question,
                injected_content=pattern.injected_content,
                answer="",
                sources=[],
                verdict_reason="target error",
                error=str(exc),
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = (time.perf_counter() - start) * 1000
            return AttackOutcome(
                pattern_id=pattern.id,
                category=pattern.category,
                status="error",
                question=pattern.question,
                injected_content=pattern.injected_content,
                answer="",
                sources=[],
                verdict_reason="unexpected error",
                error=f"{type(exc).__name__}: {exc}",
                duration_ms=duration_ms,
            )

        answer = query_result.get("answer", "")
        sources = query_result.get("sources", [])

        try:
            verdict = judge.judge(
                JudgeContext(
                    pattern=judged_pattern or pattern,
                    question=pattern.question,
                    answer=answer,
                    sources=sources,
                    document_id=document_id,
                )
            )
            status: AttackStatus = "leaked" if verdict.attack_succeeded else "blocked"
            verdict_reason = verdict.reason

            # Only leaked rows are worth a second look: keyword_match's
            # false positives (a correct refusal that names the canary)
            # only exist among rows it called "leaked" - a blocked row
            # can't be a false leak, so re-judging it would just spend
            # API calls for no possible change in outcome.
            #
            # Retrieval-scoring judges are excluded outright: leak
            # verification corrects a false positive in *answer text*, and a
            # judge that read `sources` to decide the document was retrieved
            # has no such false positive to correct. Letting an answer-based
            # verifier run here would flip every real retrieval hijack to
            # "blocked" (the answer contains no canary, so it always
            # disagrees) and report a fully poisoned retriever as perfect.
            if (
                self._verify_leaks_judge is not None
                and status == "leaked"
                and not getattr(judge, "scores_retrieval", False)
            ):
                try:
                    verify_verdict = self._verify_leaks_judge.judge(
                        JudgeContext(
                            pattern=judged_pattern or pattern,
                            question=pattern.question,
                            answer=answer,
                            sources=sources,
                            document_id=document_id,
                        )
                    )
                    if not verify_verdict.attack_succeeded:
                        status = "blocked"
                    verdict_reason = f"{verdict_reason} | {verify_verdict.reason}"
                except ConfigurationError:
                    raise
                except Exception as exc:
                    duration_ms = (time.perf_counter() - start) * 1000
                    return AttackOutcome(
                        pattern_id=pattern.id,
                        category=pattern.category,
                        status="error",
                        question=pattern.question,
                        injected_content=pattern.injected_content,
                        answer=answer,
                        sources=sources,
                        verdict_reason="leak-verification judge raised an exception",
                        # The primary verdict was "leaked" - it is being
                        # re-judged precisely because that verdict is
                        # unreliable, so silently keeping it and reporting
                        # a possibly-false leak as fact would be worse
                        # than excluding the row from the score.
                        error=f"verify-leaks judge failed: {type(exc).__name__}: {exc}",
                        duration_ms=duration_ms,
                    )

            duration_ms = (time.perf_counter() - start) * 1000
            return AttackOutcome(
                pattern_id=pattern.id,
                category=pattern.category,
                status=status,
                question=pattern.question,
                injected_content=pattern.injected_content,
                answer=answer,
                sources=sources,
                verdict_reason=verdict_reason,
                error=None,
                duration_ms=duration_ms,
            )
        except ConfigurationError:
            raise
        except Exception as exc:
            duration_ms = (time.perf_counter() - start) * 1000
            return AttackOutcome(
                pattern_id=pattern.id,
                category=pattern.category,
                status="error",
                question=pattern.question,
                injected_content=pattern.injected_content,
                answer=answer,
                sources=sources,
                verdict_reason="judge raised an exception",
                error=f"judge {pattern.success_criteria.type!r} failed: "
                f"{type(exc).__name__}: {exc}",
                duration_ms=duration_ms,
            )

    @staticmethod
    def _not_retrieved_outcome(outcome: AttackOutcome, error: str) -> AttackOutcome:
        """Copy of `outcome` turned into the `status="error"` row for "the
        injected document was not retrieved". Shared by the
        non-matching-sources and the empty-sources-with-evidence cases so the
        two rows only differ in their `error` text."""
        return replace(
            outcome,
            status="error",
            verdict_reason="injected document was not retrieved",
            error=error,
            retrieved=False,
        )

    def _verify_retrieval(
        self, outcome: AttackOutcome, document_id: str
    ) -> AttackOutcome:
        """Mode A only: check that `document_id` was among the sources the
        target reported, replacing `outcome` with a `status="error"` row if
        not.

        Only called for rows that are not already `status="error"` (an
        error row already excludes itself from the score denominator, and
        there is nothing to verify about a query that never produced an
        answer). A row with *empty* `sources` is returned unchanged: whether
        that means "retrieved nothing" or "this target never reports
        sources" can only be decided across the whole run, so `run()` handles
        it.
        """
        if not outcome.sources:
            return outcome
        if source_matches_document(outcome.sources, document_id):
            return replace(outcome, retrieved=True)
        return self._not_retrieved_outcome(
            outcome,
            f"expected a source naming/containing {document_id!r}; "
            f"target returned sources={outcome.sources!r}; pass "
            "--no-verify-retrieval to disable this check",
        )

    def _empty_sources_outcome(
        self, outcome: AttackOutcome, document_id: str
    ) -> AttackOutcome:
        """The error row for an empty `sources` list once the run has shown
        the target does report sources for other queries."""
        return self._not_retrieved_outcome(
            outcome,
            "target returned no sources for this query but reported sources "
            f"for others in this run; treating the injected document "
            f"{document_id!r} as not retrieved (pass --no-verify-retrieval "
            "to disable)",
        )

    def _resolve_pending(
        self,
        outcomes: List[Optional[AttackOutcome]],
        pending: List[int],
        held: Dict[int, AttackOutcome],
        on_outcome: Optional[Callable[[AttackOutcome], None]],
    ) -> None:
        """Convert every held empty-sources row to its error row now that the
        target has been shown to report sources, filling its slot and
        firing its delayed callback."""
        for index in pending:
            row = held.pop(index)
            row = self._empty_sources_outcome(row, f"raginject-{row.pattern_id}")
            outcomes[index] = row
            if on_outcome is not None:
                on_outcome(row)
        pending.clear()

    def _preflight_questions(self) -> None:
        if not self._questions:
            raise ConfigurationError("questions was given but contains no questions")
        if not self.host_from_corpus:
            raise ConfigurationError(
                "custom questions only apply with host_from_corpus: the host is "
                "the top real chunk for the question, so the question asks about "
                "that chunk's legitimate content, while a synthetic host would "
                "be unrelated to it"
            )

    def _preflight_prepend_question(self) -> None:
        if not self.host_from_corpus:
            raise ConfigurationError(
                "prepend_question only applies with host_from_corpus: it "
                "prepends the question to the copy of a real corpus document"
            )

    def _preflight_host_from_corpus(
        self, patterns: List[AttackPattern], judge_for_pattern: Dict[str, Judge]
    ) -> None:
        """Every `--host-from-corpus` precondition, checked before a single
        query or injection so a misconfiguration costs nothing."""
        injector = self._corpus_injector
        if injector is None:
            raise ConfigurationError(
                "host_from_corpus only applies to corpus injection mode; "
                "pass a corpus injector (--corpus-injector) to enable mode A"
            )
        if type(injector).find_host is CorpusInjector.find_host:
            raise ConfigurationError(
                f"{type(injector).__name__} does not implement find_host(), "
                "which --host-from-corpus needs to fetch the real document "
                "each payload is spliced into; implement "
                "CorpusInjector.find_host or use the LangChain/LlamaIndex "
                "injectors, which provide it"
            )
        retrieval_ids = [
            p.id
            for p in patterns
            if getattr(judge_for_pattern[p.id], "scores_retrieval", False)
        ]
        if retrieval_ids:
            raise ConfigurationError(
                "--host-from-corpus cannot be combined with retrieval-scoring "
                "patterns (" + _id_list(retrieval_ids) + "): they measure "
                "whether a planted document gets retrieved, which a copy of a "
                "real document would not test"
            )
        missing = [p.id for p in patterns if not p.payload]
        if missing:
            raise ConfigurationError(
                "--host-from-corpus needs a `payload` on every pattern (the "
                "instruction text to splice into a real document); missing "
                "on: " + _id_list(missing)
            )

    def run(
        self, on_outcome: Optional[Callable[[AttackOutcome], None]] = None
    ) -> Result:
        """Run every loaded pattern against the target and return a Result.

        Preflight (before any query is sent): zero patterns, an unknown
        judge name, or a judge rejecting a pattern's success_criteria all
        raise ConfigurationError immediately - none of that ever becomes an
        AttackOutcome.

        Mode B (`corpus_injector` not given, the default) hands each
        pattern's `injected_content` straight to the target as `context` -
        see `_run_one`.

        Mode A (`corpus_injector` given) additionally, per pattern: writes
        the attack document into the corpus (`inject`), queries the target
        with no `context` at all, optionally verifies the document was
        actually retrieved (`verify_retrieval`, default True), and always
        removes the document again (`remove`, in a `finally`, so it runs
        even when the target or the judge raised). If `inject` itself
        raises, the pattern becomes a single `status="error"` row and the
        run continues - there is nothing to clean up, since the document
        never landed. If `remove` raises, the document id is appended to
        `self.uncleaned_document_ids` and the row is forced to
        `status="error"` naming the leftover document, since a silently
        orphaned attack document in a production corpus is worse than
        discarding one data point.

        Empty `sources` in mode A (with `verify_retrieval` on, for rows not
        judged by a retrieval-scoring judge) is resolved adaptively across
        the run. If the target returns non-empty `sources` for any query,
        an empty list means "nothing relevant was retrieved" and the row
        becomes a `status="error"` row; if it never does, the target is
        assumed not to report sources, the rows are judged normally and one
        "cannot verify" warning is issued at the end of the run.

        `on_outcome` is called exactly once per pattern with its *final*
        outcome. A row whose empty `sources` cannot be classified yet is held
        back until the run learns which case applies, so the callback order
        can differ from pattern order; `Result.outcomes` is always in
        pattern order.
        """
        patterns = self.patterns
        if not patterns:
            raise ConfigurationError(
                "no attack patterns loaded; call load_patterns()/add_patterns() "
                "before run()"
            )

        if getattr(self._verify_leaks_judge, "scores_retrieval", False):
            # Leak verification re-reads the *answer* to catch a primary
            # judge that called a correct refusal a leak. A retrieval-scoring
            # judge never reads the answer, so as a verifier it would judge
            # every row against a document id it has no verdict to correct -
            # silently flipping real leaks to "blocked". There is no
            # configuration in which this combination measures anything.
            raise ConfigurationError(
                "a retrieval-scoring judge cannot be used to verify leaks: "
                "leak verification re-judges the answer text, which such a "
                "judge never reads. Pass it as the primary judge instead."
            )

        judge_for_pattern: Dict[str, Judge] = {}
        for pattern in patterns:
            if self._judge_override is not None:
                judge = self._judge_override
            else:
                judge_name = pattern.success_criteria.type
                judge = self._get_judge(judge_name)
            judge.validate_criteria(pattern.success_criteria)
            if getattr(judge, "scores_retrieval", False) and self.mode == "b":
                # A retrieval-scoring judge has nothing to score without a
                # real corpus and retriever standing behind the target - in
                # mode B the "document" never goes anywhere a retriever
                # could rank it. Caught here, in preflight, so it costs zero
                # queries and applies to the per-pattern *resolved* judge,
                # so `--judge retrieval_match` (the override) is covered
                # too, not just a pattern that names it directly.
                raise ConfigurationError(
                    f"pattern {pattern.id!r} uses a retrieval-scoring judge "
                    f"({pattern.success_criteria.type!r}), which requires "
                    "corpus injection mode; pass --corpus-injector to enable it"
                )
            judge_for_pattern[pattern.id] = judge
            if self._verify_leaks_judge is not None:
                self._verify_leaks_judge.validate_criteria(pattern.success_criteria)

        if self.host_from_corpus:
            self._preflight_host_from_corpus(patterns, judge_for_pattern)
        if self.prepend_question:
            self._preflight_prepend_question()
        if self._questions is not None:
            self._preflight_questions()
            patterns = [
                p.model_copy(
                    update={"question": self._questions[i % len(self._questions)]}
                )
                for i, p in enumerate(patterns)
            ]

        started_at = datetime.now(timezone.utc).isoformat()
        # Slots keep pattern order even when a row's callback is delayed.
        outcomes: List[Optional[AttackOutcome]] = []
        #: Indices into `outcomes` of rows with empty `sources` that are
        #: waiting to learn whether the target reports sources at all.
        pending: List[int] = []
        held: Dict[int, AttackOutcome] = {}
        saw_sources = False

        for pattern in patterns:
            judge = judge_for_pattern[pattern.id]

            if self._corpus_injector is None:
                outcome = self._run_one(
                    pattern, judge, context=[pattern.injected_content]
                )
                outcomes.append(outcome)
                if on_outcome is not None:
                    on_outcome(outcome)
                continue

            # Mode A from here down.
            document_id = f"raginject-{pattern.id}"
            inject_content = pattern.injected_content
            # What the report shows as the injected content: with a real host
            # document that is the payload only, never the corporate text.
            shown_content = pattern.injected_content
            host_source: Optional[str] = None
            judged_pattern: Optional[AttackPattern] = None
            if self.host_from_corpus:
                shown_content = pattern.payload or ""
                judged_pattern = pattern.model_copy(
                    update={"injected_content": shown_content}
                )
                host: Optional[HostDocument] = None
                host_error: Optional[str] = None
                try:
                    host = self._corpus_injector.find_host(pattern.question)
                except ConfigurationError:
                    raise
                except Exception as exc:
                    host_error = f"{type(exc).__name__}: {exc}"
                if host is None or not host.text.strip():
                    outcome = AttackOutcome(
                        pattern_id=pattern.id,
                        category=pattern.category,
                        status="error",
                        question=pattern.question,
                        injected_content=shown_content,
                        answer="",
                        sources=[],
                        verdict_reason="no host document found in the corpus for "
                        "this question",
                        error=host_error
                        or "no host document found in the corpus for this question",
                        duration_ms=None,
                    )
                    outcomes.append(outcome)
                    if on_outcome is not None:
                        on_outcome(outcome)
                    continue
                host_source = host.source
                inject_content = splice_payload(host.text, shown_content)
                if self.prepend_question:
                    inject_content = pattern.question + "\n\n" + inject_content

            try:
                self._corpus_injector.inject(document_id, inject_content)
            except ConfigurationError:
                raise
            except Exception as exc:
                # Nothing was written, so there is nothing to remove.
                outcome = AttackOutcome(
                    pattern_id=pattern.id,
                    category=pattern.category,
                    status="error",
                    question=pattern.question,
                    injected_content=shown_content,
                    host_source=host_source,
                    answer="",
                    sources=[],
                    verdict_reason="corpus injector failed to insert the attack "
                    "document",
                    error=f"{type(exc).__name__}: {exc}",
                    duration_ms=None,
                )
                outcomes.append(outcome)
                if on_outcome is not None:
                    on_outcome(outcome)
                continue

            outcome = None
            try:
                outcome = self._run_one(
                    pattern,
                    judge,
                    context=None,
                    document_id=document_id,
                    judged_pattern=judged_pattern,
                )
                if self.host_from_corpus:
                    outcome = replace(
                        outcome,
                        injected_content=shown_content,
                        host_source=host_source,
                    )
                if getattr(judge, "scores_retrieval", False):
                    # For these patterns "not retrieved" *is* the blocked
                    # verdict - the judge already decided that by reading
                    # `sources` itself, so running it back through
                    # `_verify_retrieval` would turn a correct "blocked"
                    # into an unscoreable "error". But a target that
                    # reports no `sources` at all hasn't actually been
                    # measured - scoring that as "blocked" would report an
                    # unmeasurable pipeline as safe, a false all-clear. This
                    # replacement is unconditional (not gated on
                    # `verify_retrieval`/`--no-verify-retrieval`): for
                    # these patterns it *is* the measurement, not a
                    # verification layered on top of one.
                    if outcome.status != "error" and not outcome.sources:
                        outcome = replace(
                            outcome,
                            status="error",
                            verdict_reason=(
                                "target returned no sources, so retrieval "
                                "cannot be measured"
                            ),
                            error=(
                                "retrieval_match judge requires the target "
                                "to report `sources`; got an empty list"
                            ),
                        )
                elif self.verify_retrieval and outcome.status != "error":
                    outcome = self._verify_retrieval(outcome, document_id)
            finally:
                try:
                    self._corpus_injector.remove(document_id)
                except ConfigurationError:
                    # Still aborts the run (ConfigurationError always does),
                    # but the document was still left behind - recording
                    # that must happen before the raise, not after, or the
                    # id is lost the moment this propagates.
                    self.uncleaned_document_ids.append(document_id)
                    raise
                except Exception as exc:
                    self.uncleaned_document_ids.append(document_id)
                    outcome = AttackOutcome(
                        pattern_id=pattern.id,
                        category=pattern.category,
                        status="error",
                        question=pattern.question,
                        injected_content=shown_content,
                        host_source=host_source,
                        answer=outcome.answer if outcome is not None else "",
                        sources=outcome.sources if outcome is not None else [],
                        verdict_reason="corpus injector failed to remove the "
                        "attack document; it was left in the corpus and must be "
                        "deleted manually",
                        error=f"{type(exc).__name__}: {exc}",
                        duration_ms=outcome.duration_ms
                        if outcome is not None
                        else None,
                    )

            if outcome.sources:
                saw_sources = True
            if (
                self.verify_retrieval
                and not getattr(judge, "scores_retrieval", False)
                and outcome.status != "error"
                and not outcome.sources
            ):
                if saw_sources:
                    outcome = self._empty_sources_outcome(outcome, document_id)
                else:
                    outcomes.append(None)
                    pending.append(len(outcomes) - 1)
                    held[len(outcomes) - 1] = outcome
                    continue
            outcomes.append(outcome)
            if on_outcome is not None:
                on_outcome(outcome)

            if saw_sources and pending:
                self._resolve_pending(outcomes, pending, held, on_outcome)

        if pending:
            # The target never returned a single source, so there is nothing
            # to tell "retrieved nothing" from "does not report sources".
            warnings.warn(
                "corpus injection mode: the target never returned `sources`, "
                "so raginject cannot verify the injected attack document was "
                "actually retrieved. The score therefore cannot distinguish "
                "a blocked attack from one whose document was never surfaced "
                "by your retriever. Return `sources` from your target to "
                "enable verification, or pass --no-verify-retrieval to "
                "silence this warning.",
                stacklevel=2,
            )
            for index in pending:
                outcomes[index] = held[index]
                if on_outcome is not None:
                    on_outcome(held[index])

        return Result(
            outcomes=[o for o in outcomes if o is not None],
            started_at=started_at,
            raginject_version=__version__,
            target_description=self.target.target_description,
            pattern_count=len(patterns),
            mode=self.mode,
            corpus_injector_description=(
                self._corpus_injector.description
                if self._corpus_injector is not None
                else None
            ),
            host_from_corpus=self.host_from_corpus,
            custom_question_count=(
                len(set(self._questions)) if self._questions is not None else 0
            ),
            prepend_question=self.prepend_question,
        )
