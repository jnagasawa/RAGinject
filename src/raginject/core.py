"""Evaluation engine: Runner and Result.

`AttackOutcome` and `Result` fields are the JSON report's schema contract,
so they are never added to, renamed, or removed - only *properties* may be
added here.
"""

import time
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
    """

    def __init__(
        self,
        target: Target,
        judges: Optional[Mapping[str, Judge]] = None,
        *,
        judge_override: Optional[Judge] = None,
        verify_leaks_judge: Optional[Judge] = None,
    ):
        self.target = target
        self._judges = judges
        self._judge_override = judge_override
        self._verify_leaks_judge = verify_leaks_judge
        self._patterns: Dict[str, AttackPattern] = {}

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

    def run(
        self, on_outcome: Optional[Callable[[AttackOutcome], None]] = None
    ) -> Result:
        """Run every loaded pattern against the target and return a Result.

        Preflight (before any query is sent): zero patterns, an unknown
        judge name, or a judge rejecting a pattern's success_criteria all
        raise ConfigurationError immediately - none of that ever becomes an
        AttackOutcome.
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

        for pattern in patterns:
            judge = judge_for_pattern[pattern.id]
            start = time.perf_counter()
            try:
                query_result = self.target.query(
                    pattern.question, context=[pattern.injected_content]
                )
            except ConfigurationError:
                raise
            except TargetError as exc:
                duration_ms = (time.perf_counter() - start) * 1000
                outcome = AttackOutcome(
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
                outcomes.append(outcome)
                if on_outcome is not None:
                    on_outcome(outcome)
                continue
            except Exception as exc:
                duration_ms = (time.perf_counter() - start) * 1000
                outcome = AttackOutcome(
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
                outcomes.append(outcome)
                if on_outcome is not None:
                    on_outcome(outcome)
                continue

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
                status: AttackStatus = (
                    "leaked" if verdict.attack_succeeded else "blocked"
                )
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
                        outcome = AttackOutcome(
                            pattern_id=pattern.id,
                            category=pattern.category,
                            status="error",
                            question=pattern.question,
                            injected_content=pattern.injected_content,
                            answer=answer,
                            sources=sources,
                            verdict_reason="leak-verification judge raised an "
                            "exception",
                            # The primary verdict was "leaked" - it is being
                            # re-judged precisely because that verdict is
                            # unreliable, so silently keeping it and reporting
                            # a possibly-false leak as fact would be worse
                            # than excluding the row from the score.
                            error=f"verify-leaks judge failed: "
                            f"{type(exc).__name__}: {exc}",
                            duration_ms=duration_ms,
                        )
                        outcomes.append(outcome)
                        if on_outcome is not None:
                            on_outcome(outcome)
                        continue

                duration_ms = (time.perf_counter() - start) * 1000
                outcome = AttackOutcome(
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
                outcome = AttackOutcome(
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

            outcomes.append(outcome)
            if on_outcome is not None:
                on_outcome(outcome)

        return Result(
            outcomes=outcomes,
            started_at=started_at,
            raginject_version=__version__,
            target_description=self.target.target_description,
            pattern_count=len(patterns),
        )
