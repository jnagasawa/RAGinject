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
    Tuple,
    Union,
)

from ._version import __version__
from .attacks.loader import load_patterns as _load_patterns
from .attacks.schema import AttackPattern
from .corpus import CorpusInjector
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
    blocked; see `run()` for the exact semantics.

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
    ) -> AttackOutcome:
        """Query the target once for `pattern` and judge the answer,
        returning a single AttackOutcome.

        This is the part of `run()` that mode A and mode B share verbatim:
        mode B calls it with `context=[pattern.injected_content]` (the
        attack document handed straight to the target); mode A calls it
        with `context=None` after writing the document into the corpus via
        `corpus_injector.inject`, so the target's own retriever decides
        whether it surfaces.

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
                )
            )
            status: AttackStatus = "leaked" if verdict.attack_succeeded else "blocked"
            verdict_reason = verdict.reason

            # Only leaked rows are worth a second look: keyword_match's
            # false positives (a correct refusal that names the canary)
            # only exist among rows it called "leaked" - a blocked row
            # can't be a false leak, so re-judging it would just spend
            # API calls for no possible change in outcome.
            if self._verify_leaks_judge is not None and status == "leaked":
                try:
                    verify_verdict = self._verify_leaks_judge.judge(
                        JudgeContext(
                            pattern=pattern,
                            question=pattern.question,
                            answer=answer,
                            sources=sources,
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

    def _verify_retrieval(
        self, outcome: AttackOutcome, document_id: str, *, warned: bool
    ) -> Tuple[AttackOutcome, bool]:
        """Mode A only: check that `document_id` was among the sources the
        target reported, replacing `outcome` with a `status="error"` row if
        not. Returns `(outcome, warned)` - `warned` tracks whether the
        "retrieval is unverifiable" warning has already fired this run, so
        it fires at most once regardless of how many patterns hit it.

        Only called for rows that are not already `status="error"` (an
        error row already excludes itself from the score denominator, and
        there is nothing to verify about a query that never produced an
        answer).
        """
        if not outcome.sources:
            # Nothing to check the id against - the pipeline simply isn't
            # reporting sources. That is a real gap (the score can't tell
            # "blocked" from "never retrieved" apart), but it must not be
            # silently penalized, so this is a warning, not an error row.
            if not warned:
                warnings.warn(
                    "corpus injection mode: the target returned no `sources` for "
                    "at least one query, so raginject cannot verify the injected "
                    "attack document was actually retrieved. The score therefore "
                    "cannot distinguish a blocked attack from one whose document "
                    "was never surfaced by your retriever. Return `sources` from "
                    "your target to enable verification, or pass "
                    "--no-verify-retrieval to silence this warning.",
                    stacklevel=3,
                )
                warned = True
            return outcome, warned

        # Substring match, not equality: a pipeline may return
        # "raginject-<id>.txt" or a path/URL containing the id rather than
        # the bare id. The ids are unique and implausible, so this is not a
        # realistic source of false positives.
        if any(document_id in source for source in outcome.sources):
            return outcome, warned

        outcome = AttackOutcome(
            pattern_id=outcome.pattern_id,
            category=outcome.category,
            status="error",
            question=outcome.question,
            injected_content=outcome.injected_content,
            answer=outcome.answer,
            sources=outcome.sources,
            verdict_reason="injected document was not retrieved",
            error=(
                f"expected a source naming/containing {document_id!r}; "
                f"target returned sources={outcome.sources!r}"
            ),
            duration_ms=outcome.duration_ms,
        )
        return outcome, warned

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
        """
        patterns = self.patterns
        if not patterns:
            raise ConfigurationError(
                "no attack patterns loaded; call load_patterns()/add_patterns() "
                "before run()"
            )

        judge_for_pattern: Dict[str, Judge] = {}
        for pattern in patterns:
            if self._judge_override is not None:
                judge = self._judge_override
            else:
                judge_name = pattern.success_criteria.type
                judge = self._get_judge(judge_name)
            judge.validate_criteria(pattern.success_criteria)
            judge_for_pattern[pattern.id] = judge
            if self._verify_leaks_judge is not None:
                self._verify_leaks_judge.validate_criteria(pattern.success_criteria)

        started_at = datetime.now(timezone.utc).isoformat()
        outcomes: List[AttackOutcome] = []
        warned_unverifiable = False

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
                outcome = self._run_one(pattern, judge, context=None)
                if self.verify_retrieval and outcome.status != "error":
                    outcome, warned_unverifiable = self._verify_retrieval(
                        outcome, document_id, warned=warned_unverifiable
                    )
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

            outcomes.append(outcome)
            if on_outcome is not None:
                on_outcome(outcome)

        return Result(
            outcomes=outcomes,
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
