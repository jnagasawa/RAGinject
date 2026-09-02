"""Evaluation engine: Runner and Result (see PLAN.md 7, 7.1a).

`AttackOutcome` and `Result` keep exactly the fields frozen by PLAN.md
§7.1a - only *properties* are added here, never new/renamed/removed fields
(see CLAUDE.md's "frozen contracts" rule).
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
#: attack that got through ("leaked"). See PLAN.md §7 for the scoring rule:
#: "error" rows are excluded from the score denominator.
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
        """Short human-readable summary, per PLAN.md §7.1.

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
    a pre-configured judge instance (e.g. a Milestone 2 `LLMJudge(model=...)`)
    without needing a factory-based registry.
    """

    def __init__(self, target: Target, judges: Optional[Mapping[str, Judge]] = None):
        self.target = target
        self._judges = judges
        self._patterns: Dict[str, AttackPattern] = {}

    @property
    def patterns(self) -> List[AttackPattern]:
        return list(self._patterns.values())

    def load_patterns(self, path: Optional[Union[str, Path]] = None) -> None:
        """Load patterns from `path` (file/dir) or the built-in default set,
        merging additively into any patterns already loaded/added. Same id
        overrides the earlier entry but keeps its original position (see
        PLAN.md §5.3 / decision C)."""
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
            judge_name = pattern.success_criteria.type
            judge = self._get_judge(judge_name)
            judge.validate_criteria(pattern.success_criteria)
            judge_for_pattern[pattern.id] = judge

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
                duration_ms = (time.perf_counter() - start) * 1000
                status: AttackStatus = (
                    "leaked" if verdict.attack_succeeded else "blocked"
                )
                outcome = AttackOutcome(
                    pattern_id=pattern.id,
                    category=pattern.category,
                    status=status,
                    question=pattern.question,
                    injected_content=pattern.injected_content,
                    answer=answer,
                    sources=sources,
                    verdict_reason=verdict.reason,
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
