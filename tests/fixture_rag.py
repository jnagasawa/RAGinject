"""A resolution target for `tests/test_resolve.py` and `tests/test_cli.py`
(via `--target-module tests.fixture_rag:...`).
"""

from typing import List, Optional

from raginject.corpus import CorpusInjector
from raginject.errors import ConfigurationError
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


class InMemoryCorpusInjector(CorpusInjector):
    """A trivial CorpusInjector, for `tests/test_resolve.py`'s and
    `tests/test_cli.py`'s 'CorpusInjector subclass'/'CorpusInjector
    instance' resolution paths."""

    def __init__(self):
        self.documents = {}

    def inject(self, document_id: str, content: str) -> None:
        self.documents[document_id] = content

    def remove(self, document_id: str) -> None:
        self.documents.pop(document_id, None)


in_memory_corpus_injector = InMemoryCorpusInjector()


def not_a_corpus_injector(question: str) -> QueryResult:
    """A plain callable - exercises resolve_corpus_injector_spec's 'no
    bare-callable fallback' rule (unlike resolve_target_spec, this must
    raise, not get wrapped in anything)."""
    return {"answer": question, "sources": []}


class RemoveRaisesConfigurationError(CorpusInjector):
    """`inject` succeeds; `remove` always raises `ConfigurationError` - for
    `tests/test_cli.py`'s regression test proving the leftover-document
    warning still prints on an aborted (ConfigurationError-exit) run, not
    just on a successful one."""

    def inject(self, document_id: str, content: str) -> None:
        pass

    def remove(self, document_id: str) -> None:
        raise ConfigurationError("corpus backend not configured")


remove_raises_configuration_error = RemoveRaisesConfigurationError()
