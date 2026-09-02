"""Target abstraction: the common interface all evaluation targets normalize to."""

from abc import ABC, abstractmethod
from typing import List, Optional, TypedDict


class _QueryResultOptional(TypedDict, total=False):
    sources: List[str]


class QueryResult(_QueryResultOptional):
    answer: str


class Target(ABC):
    @abstractmethod
    def query(self, question: str, context: Optional[List[str]] = None) -> QueryResult:
        """Send `question` (and optional `context` documents) to the target and
        return a QueryResult.

        `context` is the list of documents that should be treated as if they
        were retrieved for this query (see PLAN.md §4.1). `None` or an empty
        list means a normal, uninjected query.
        """
        ...
