"""Evaluation engine: Runner and Result (see PLAN.md 7.1)."""

from dataclasses import dataclass, field
from typing import List, Literal, Optional

from .attacks.schema import AttackPattern
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
    def score(self) -> float:
        raise NotImplementedError

    @property
    def summary(self) -> str:
        raise NotImplementedError


class Runner:
    def __init__(self, target: Target):
        self.target = target
        self.patterns: List[AttackPattern] = []

    def load_patterns(self, path: Optional[str] = None) -> None:
        raise NotImplementedError

    def run(self) -> Result:
        raise NotImplementedError
