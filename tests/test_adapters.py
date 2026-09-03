"""FunctionTarget/HTTPTarget: QueryResult validation and error handling."""

import asyncio
import warnings

import httpx
import pytest

from raginject.adapters.function import FunctionTarget
from raginject.adapters.http import HTTPTarget
from raginject.errors import (
    ConfigurationError,
    TargetConnectionError,
    TargetResponseError,
    TargetTimeoutError,
)

# --------------------------------------------------------------------------
# FunctionTarget
# --------------------------------------------------------------------------


def test_function_target_question_only_with_empty_context_works():
    def rag(question):
        return {"answer": f"answered: {question}", "sources": []}

    target = FunctionTarget(rag)
    result = target.query("hi")
    assert result["answer"] == "answered: hi"


def test_function_target_question_only_with_nonempty_context_raises_configuration_error():
    def rag(question):
        return {"answer": question}

    target = FunctionTarget(rag)
    with pytest.raises(ConfigurationError):
        target.query("hi", context=["injected doc"])


def test_function_target_named_context_param_receives_injected_docs():
    def rag(question, context=None):
        return {"answer": "|".join(context or []), "sources": []}

    target = FunctionTarget(rag)
    result = target.query("hi", context=["doc-a", "doc-b"])
    assert result["answer"] == "doc-a|doc-b"


def test_function_target_kwargs_param_receives_context():
    def rag(question, **kwargs):
        return {"answer": "|".join(kwargs.get("context") or []), "sources": []}

    target = FunctionTarget(rag)
    result = target.query("hi", context=["doc-a"])
    assert result["answer"] == "doc-a"


def test_function_target_second_positional_param_binds_context_with_warning():
    def rag(question, ctx):
        return {"answer": "|".join(ctx), "sources": []}

    with pytest.warns(UserWarning):
        target = FunctionTarget(rag)

    # No warning on each call - only once, at construction.
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        result = target.query("hi", context=["doc-a"])
    assert result["answer"] == "doc-a"


def test_function_target_validates_result_shape_missing_answer():
    def rag(question):
        return {"sources": []}

    target = FunctionTarget(rag)
    with pytest.raises(TargetResponseError) as excinfo:
        target.query("hi")
    assert "answer" in str(excinfo.value)


def test_function_target_validates_result_shape_answer_not_a_string():
    def rag(question):
        return {"answer": 123}

    target = FunctionTarget(rag)
    with pytest.raises(TargetResponseError):
        target.query("hi")


def test_function_target_defaults_missing_sources_to_empty_list():
    def rag(question):
        return {"answer": "ok"}

    target = FunctionTarget(rag)
    result = target.query("hi")
    assert result["sources"] == []


def test_function_target_async_def_driven_from_inside_running_event_loop():
    # Proves an async target must work even when called from a thread that
    # already has a running event loop (e.g. an async test harness), not
    # just from plain sync code.
    async def rag(question, context=None):
        await asyncio.sleep(0)
        return {"answer": "|".join(context or []), "sources": []}

    target = FunctionTarget(rag)

    async def _drive():
        return target.query("hi", context=["doc-a"])

    result = asyncio.run(_drive())
    assert result["answer"] == "doc-a"


def test_function_target_async_reraises_original_exception():
    async def rag(question):
        raise ValueError("boom from inside coroutine")

    target = FunctionTarget(rag)
    with pytest.raises(ValueError, match="boom from inside coroutine"):
        target.query("hi")


# --------------------------------------------------------------------------
# HTTPTarget
# --------------------------------------------------------------------------


def test_http_target_default_contract_post_json_body(dummy_server):
    dummy_server.set_response({"answer": "the answer", "sources": ["doc1.txt"]})
    with HTTPTarget(url=dummy_server.url("/query")) as target:
        result = target.query("what is it?", context=["injected doc"])

    assert result == {"answer": "the answer", "sources": ["doc1.txt"]}
    method, path, _headers, _query, body = dummy_server.requests[-1]
    assert method == "POST"
    assert path == "/query"
    assert body == {"question": "what is it?", "context": ["injected doc"]}


def test_http_target_omits_context_key_when_empty(dummy_server):
    with HTTPTarget(url=dummy_server.url("/query")) as target:
        target.query("hello")

    _, _, _, _, body = dummy_server.requests[-1]
    assert "context" not in body


def test_http_target_get_repeats_context_as_query_params(dummy_server):
    with HTTPTarget(url=dummy_server.url("/query"), method="GET") as target:
        target.query("hello", context=["doc-a", "doc-b"])

    method, _path, _, query, _ = dummy_server.requests[-1]
    assert method == "GET"
    assert query["question"] == ["hello"]
    assert query["context"] == ["doc-a", "doc-b"]


def test_http_target_custom_key_mapping(dummy_server):
    dummy_server.set_response({"reply": "custom answer"})
    with HTTPTarget(
        url=dummy_server.url("/query"),
        request_key="q",
        request_context_key="docs",
        response_answer_key="reply",
    ) as target:
        result = target.query("hi", context=["d1"])

    assert result["answer"] == "custom answer"
    _, _, _, _, body = dummy_server.requests[-1]
    assert body == {"q": "hi", "docs": ["d1"]}


def test_http_target_validates_response_shape_missing_answer(dummy_server):
    with HTTPTarget(url=dummy_server.url("/no-answer")) as target:
        with pytest.raises(TargetResponseError):
            target.query("hi")


def test_http_target_non_json_response_raises_target_response_error(dummy_server):
    with HTTPTarget(url=dummy_server.url("/malformed")) as target:
        with pytest.raises(TargetResponseError):
            target.query("hi")


def test_http_target_non_2xx_status_raises_target_response_error(dummy_server):
    with HTTPTarget(url=dummy_server.url("/status500")) as target:
        with pytest.raises(TargetResponseError):
            target.query("hi")


def test_http_target_connection_error_raises_target_connection_error():
    with HTTPTarget(url="http://127.0.0.1:1/query", timeout=1) as target:
        with pytest.raises(TargetConnectionError):
            target.query("hi")


def test_http_target_timeout_raises_target_timeout_error(dummy_server):
    dummy_server.slow_delay = 0.5
    with HTTPTarget(url=dummy_server.url("/slow"), timeout=0.05) as target:
        with pytest.raises(TargetTimeoutError):
            target.query("hi")


def test_http_target_close_closes_owned_client(dummy_server):
    target = HTTPTarget(url=dummy_server.url("/query"))
    target.query("hi")
    target.close()
    assert target._client.is_closed


def test_http_target_does_not_close_injected_client(dummy_server):
    client = httpx.Client()
    target = HTTPTarget(url=dummy_server.url("/query"), client=client)
    target.query("hi")
    target.close()
    assert not client.is_closed
    client.close()


def test_http_target_header_value_never_appears_in_target_description(dummy_server):
    secret = "Bearer super-secret-token-value"
    target = HTTPTarget(
        url=dummy_server.url("/query") + "?api_key=leaked-in-query#frag",
        headers={"Authorization": secret},
    )
    description = target.target_description
    assert secret not in description
    assert "leaked-in-query" not in description
    assert "frag" not in description
    target.close()


def test_http_target_header_value_never_appears_in_repr(dummy_server):
    secret = "Bearer super-secret-token-value"
    target = HTTPTarget(
        url=dummy_server.url("/query"), headers={"Authorization": secret}
    )
    assert secret not in repr(target)
    target.close()


def test_http_target_header_is_sent_but_not_recorded_in_description(dummy_server):
    secret = "Bearer super-secret-token-value"
    with HTTPTarget(
        url=dummy_server.url("/query"), headers={"Authorization": secret}
    ) as target:
        target.query("hi")

    _, _, headers, _, _ = dummy_server.requests[-1]
    assert headers.get("Authorization") == secret


def test_empty_context_still_calls_a_required_context_parameter():
    # `def rag(question, context)` has no default, so calling fn(question)
    # alone would raise TypeError on an uninjected query.
    def rag(question, context):
        return {"answer": f"ctx={context!r}"}

    assert FunctionTarget(rag).query("hi")["answer"] == "ctx=None"


def test_empty_context_does_not_clobber_an_unrelated_positional_param():
    # `top_k` is bound positionally only when there is real context to inject;
    # an uninjected query must leave the function's own default alone.
    def rag(question, top_k=5):
        return {"answer": f"top_k={top_k!r}"}

    with pytest.warns(UserWarning, match="binding context positionally"):
        target = FunctionTarget(rag)
    assert target.query("hi")["answer"] == "top_k=5"
    assert target.query("hi", context=["doc"])["answer"] == "top_k=['doc']"


def test_http_target_rejects_an_unsupported_method():
    with pytest.raises(ConfigurationError, match="unsupported method"):
        HTTPTarget(url="http://example.invalid/query", method="DELETE")
