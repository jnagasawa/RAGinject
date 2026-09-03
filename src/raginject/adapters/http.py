"""HTTPTarget: wrap an HTTP endpoint as a Target, per the raginject HTTP contract."""

from typing import List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

import httpx

from ..errors import (
    ConfigurationError,
    TargetConnectionError,
    TargetError,
    TargetResponseError,
    TargetTimeoutError,
)
from ..target import QueryResult, Target, normalize_query_result

_SUPPORTED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH"})


class HTTPTarget(Target):
    """Wrap an HTTP endpoint as a Target.

    Default wire contract: POST a JSON body
    ``{"question": ..., "context": [...]}`` and expect back
    ``{"answer": ..., "sources": [...]}``. Key names are configurable via
    `request_key`/`request_context_key`/`response_answer_key`/
    `response_sources_key` for services with a different schema. When
    `context` is empty (None or []), the context key is omitted from the
    request entirely (backward compatibility with endpoints that don't
    know about it).

    `headers` (e.g. an Authorization token) is never exposed by
    `target_description`, and this class defines no `__repr__` that would
    surface it - only pass it to the outgoing request.

    A `client` may be injected (mainly for tests); an injected client is
    never closed by this Target - only a client this Target created itself
    (from `url`/`timeout`) is closed by `close()`/`__exit__`.
    """

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
        client: Optional[httpx.Client] = None,
    ):
        self.url = url
        self.method = method.upper()
        if self.method not in _SUPPORTED_METHODS:
            raise ConfigurationError(
                f"HTTPTarget: unsupported method {method!r}; "
                f"expected one of {', '.join(sorted(_SUPPORTED_METHODS))}"
            )
        self.request_key = request_key
        self.request_context_key = request_context_key
        self.response_answer_key = response_answer_key
        self.response_sources_key = response_sources_key
        self.headers = headers
        self.timeout = timeout

        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.Client(timeout=timeout)
            self._owns_client = True

    @property
    def target_description(self) -> str:
        # Strip query string and fragment: they may carry API keys/tokens.
        parts = urlsplit(self.url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "HTTPTarget":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def query(self, question: str, context: Optional[List[str]] = None) -> QueryResult:
        context = context or []

        try:
            if self.method == "GET":
                params: List[Tuple[str, str]] = [(self.request_key, question)]
                if context:
                    params.extend((self.request_context_key, item) for item in context)
                response = self._client.get(
                    self.url, params=params, headers=self.headers, timeout=self.timeout
                )
            else:
                body = {self.request_key: question}
                if context:
                    body[self.request_context_key] = context
                response = self._client.request(
                    self.method,
                    self.url,
                    json=body,
                    headers=self.headers,
                    timeout=self.timeout,
                )
        except httpx.TimeoutException as exc:
            raise TargetTimeoutError(
                f"HTTPTarget: request to {self.target_description} timed out "
                f"after {self.timeout}s"
            ) from exc
        except httpx.ConnectError as exc:
            raise TargetConnectionError(
                f"HTTPTarget: could not connect to {self.target_description}: {exc}"
            ) from exc
        except httpx.HTTPError as exc:
            raise TargetError(
                f"HTTPTarget: request to {self.target_description} failed: {exc}"
            ) from exc

        if response.status_code < 200 or response.status_code >= 300:
            snippet = response.text[:200]
            raise TargetResponseError(
                f"HTTPTarget: {self.target_description} returned "
                f"HTTP {response.status_code}: {snippet!r}"
            )

        try:
            data = response.json()
        except ValueError as exc:
            content_type = response.headers.get("content-type", "unknown")
            raise TargetResponseError(
                f"HTTPTarget: {self.target_description} returned a non-JSON body "
                f"(Content-Type: {content_type})"
            ) from exc

        return normalize_query_result(
            data,
            source="HTTPTarget",
            answer_key=self.response_answer_key,
            sources_key=self.response_sources_key,
        )
