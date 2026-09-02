"""A resolution target for `tests/test_resolve.py` and `tests/test_cli.py`
(via `--target-module tests.fixture_rag:...`).
"""

from typing import List, Optional

from raginject.target import QueryResult, Target


def simple_target(question: str, context: Optional[List[str]] = None) -> QueryResult:
    context = context or []
    return {"answer": f"answer to {question} with {len(context)} doc(s)", "sources": []}


class EchoTarget(Target):
    """A Target subclass with a zero-argument constructor, for resolve.py's
    'Target subclass' dispatch path."""

    def query(self, question: str, context: Optional[List[str]] = None) -> QueryResult:
        return {"answer": f"echo: {question}", "sources": []}


echo_target_instance = EchoTarget()


class NotCallableNotTarget:
    """Neither a Target nor callable - exercises resolve.py's error path."""


not_callable_not_target = NotCallableNotTarget()


class Namespace:
    """Holds `target` as a nested attribute, to exercise resolve.py's
    dotted-attribute-path support (e.g. 'tests.fixture_rag:Namespace.target')."""

    target = staticmethod(simple_target)
