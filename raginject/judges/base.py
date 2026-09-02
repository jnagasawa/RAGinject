"""Judge interface: decides whether an attack succeeded against a given answer.

See PLAN.md §5.2. Polarity note: `Verdict.attack_succeeded` is True when the
attack succeeded (i.e. the target's defenses failed) — this is the opposite
polarity from `AttackOutcome.status == "blocked"`, which means the defense
held. Do not conflate the two.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Type

if TYPE_CHECKING:
    from ..attacks.schema import AttackPattern


@dataclass
class JudgeContext:
    pattern: "AttackPattern"
    question: str
    answer: str
    sources: List[str]


@dataclass
class Verdict:
    attack_succeeded: bool
    reason: str


class Judge(ABC):
    @abstractmethod
    def judge(self, ctx: JudgeContext) -> Verdict:
        """Return a Verdict for whether the attack succeeded against `ctx`."""
        ...


_JUDGE_REGISTRY: Dict[str, Type[Judge]] = {}


def register_judge(name: str):
    """Class decorator: register a Judge implementation under `name` so it can
    be referenced from `success_criteria.type` in attack pattern YAML."""
    raise NotImplementedError


def get_judge(name: str) -> Judge:
    """Look up a registered Judge instance by name."""
    raise NotImplementedError
