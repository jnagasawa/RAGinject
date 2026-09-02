"""HTTPTarget: wrap an HTTP endpoint as a Target, per the raginject HTTP contract (see PLAN.md 4.3)."""

from typing import List, Optional

from ..target import QueryResult, Target


class HTTPTarget(Target):
    def __init__(
        self,
        url: str,
        method: str = "POST",
        request_key: str = "question",
        request_context_key: str = "context",
        response_answer_key: str = "answer",
        response_sources_key: str = "sources",
        headers: Optional[dict] = None,
        timeout: float = 30,
    ):
        self.url = url
        self.method = method
        self.request_key = request_key
        self.request_context_key = request_context_key
        self.response_answer_key = response_answer_key
        self.response_sources_key = response_sources_key
        self.headers = headers
        self.timeout = timeout

    def query(self, question: str, context: Optional[List[str]] = None) -> QueryResult:
        raise NotImplementedError
