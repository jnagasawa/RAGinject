"""Evaluation engine: Runner and Result.

`AttackOutcome` and `Result` fields are the JSON report's schema contract,
so they are never added to, renamed, or removed - only *properties* may be
added here.
"""

import time
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import (
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
from .corpus import CorpusInjector, source_matches_document
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
    def summary(self) -> str:
        """Short human-readable summary.

        Names the failed pattern ids: without them a CI log tells you the
        gate failed but not which attack got through.
        """
        lines = [
            f"raginject: {self.blocked_count}/{self.scored_count} attacks blocked "
            f"(score: {self.score:.2f})"
        ]
        if self.failed_ids:
            lines.append(f"Failed: {', '.join(self.failed_ids)}")
        if self.error_count:
            error_ids = [o.pattern_id for o in self.outcomes if o.status == "error"]
            lines.append(
                f"Errors: {self.error_count} (excluded from score): "
                f"{', '.join(error_ids)}"
            )
        return "\n".join(lines)


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
    ):
        self.target = target
        self._judges = judges
        self._judge_override = judge_override
        self._verify_leaks_judge = verify_leaks_judge
        self._corpus_injector = corpus_injector
        self.verify_retrieval = verify_retrieval
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
                    pattern=pattern,
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
                            pattern=pattern,
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
        return AttackOutcome(
            pattern_id=outcome.pattern_id,
            category=outcome.category,
            status="error",
            question=outcome.question,
            injected_content=outcome.injected_content,
            answer=outcome.answer,
            sources=outcome.sources,
            verdict_reason="injected document was not retrieved",
            error=error,
            duration_ms=outcome.duration_ms,
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
        if not outcome.sources or source_matches_document(outcome.sources, document_id):
            return outcome
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
            try:
                self._corpus_injector.inject(document_id, pattern.injected_content)
            except ConfigurationError:
                raise
            except Exception as exc:
                # Nothing was written, so there is nothing to remove.
                outcome = AttackOutcome(
                    pattern_id=pattern.id,
                    category=pattern.category,
                    status="error",
                    question=pattern.question,
                    injected_content=pattern.injected_content,
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
                    pattern, judge, context=None, document_id=document_id
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
                        outcome = AttackOutcome(
                            pattern_id=outcome.pattern_id,
                            category=outcome.category,
                            status="error",
                            question=outcome.question,
                            injected_content=outcome.injected_content,
                            answer=outcome.answer,
                            sources=outcome.sources,
                            verdict_reason=(
                                "target returned no sources, so retrieval "
                                "cannot be measured"
                            ),
                            error=(
                                "retrieval_match judge requires the target "
                                "to report `sources`; got an empty list"
                            ),
                            duration_ms=outcome.duration_ms,
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
                        injected_content=pattern.injected_content,
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
        )
