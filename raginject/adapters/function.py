"""FunctionTarget: wrap a Python callable as a Target."""

from typing import Callable, List, Optional

from ..target import QueryResult, Target


class FunctionTarget(Target):
    def __init__(self, fn: Callable[[str], dict]):
        self.fn = fn

    def query(self, question: str, context: Optional[List[str]] = None) -> QueryResult:
        raise NotImplementedError
