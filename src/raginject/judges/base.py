"""Judge interface: decides whether an attack succeeded against a given answer.

Polarity note: `Verdict.attack_succeeded` is True when the
attack succeeded (i.e. the target's defenses failed) — this is the opposite
polarity from `AttackOutcome.status == "blocked"`, which means the defense
held. Do not conflate the two.
"""

import difflib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Type

from ..errors import ConfigurationError

if TYPE_CHECKING:
    from ..attacks.schema import AttackPattern, SuccessCriteria


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

    @classmethod
    def validate_criteria(cls, criteria: "SuccessCriteria") -> None:
        """Raise ConfigurationError if this judge cannot operate with
        `criteria` (e.g. `keyword_match` without `forbidden_in_answer`).

        Default implementation is a no-op, so existing/third-party judges
        remain valid without changes. Called during preflight (before any
        query is sent) so a misconfigured pattern fails loudly instead of
        silently reporting "blocked".
        """
        return None


_JUDGE_REGISTRY: Dict[str, Type[Judge]] = {}
_JUDGE_INSTANCES: Dict[str, Judge] = {}


def register_judge(name: str):
    """Class decorator: register a Judge implementation under `name` so it can
    be referenced from `success_criteria.type` in attack pattern YAML.

    Re-registering the same name overwrites the previous entry (and clears
    any cached instance), so users can deliberately replace a built-in
    judge (e.g. via `--plugin`).
    """

    def _decorator(judge_cls: Type[Judge]) -> Type[Judge]:
        _JUDGE_REGISTRY[name] = judge_cls
        _JUDGE_INSTANCES.pop(name, None)
        return judge_cls

    return _decorator


def get_judge(name: str) -> Judge:
    """Look up a registered Judge instance by name (cached per name)."""
    if name in _JUDGE_INSTANCES:
        return _JUDGE_INSTANCES[name]

    judge_cls = _JUDGE_REGISTRY.get(name)
    if judge_cls is None:
        known = available_judges()
        suggestions = difflib.get_close_matches(name, known)
        message = (
            f"unknown judge {name!r}; available judges: {', '.join(known) or '(none)'}"
        )
        if suggestions:
            message += f"; did you mean {', '.join(suggestions)}?"
        raise ConfigurationError(message)

    instance = judge_cls()
    _JUDGE_INSTANCES[name] = instance
    return instance


def available_judges() -> List[str]:
    """Names of all currently registered judges."""
    return sorted(_JUDGE_REGISTRY.keys())
