"""Tests for raginject.resolve.resolve_target_spec: the five dispatch
outcomes (Target instance / Target subclass / callable / dotted attribute /
error cases), plus the missing-colon message."""

import re

import pytest

from raginject.adapters.function import FunctionTarget
from raginject.errors import TargetResolutionError
from raginject.resolve import resolve_target_spec
from raginject.target import Target
from tests.fixture_rag import EchoTarget


def test_resolve_plain_function_wraps_in_function_target():
    target = resolve_target_spec("tests.fixture_rag:simple_target")
    assert isinstance(target, FunctionTarget)
    result = target.query("hi", context=["doc"])
    assert result["answer"] == "answer to hi with 1 doc(s)"


def test_resolve_target_instance_used_directly():
    target = resolve_target_spec("tests.fixture_rag:echo_target_instance")
    assert isinstance(target, EchoTarget)
    assert target.query("hi")["answer"] == "echo: hi"


def test_resolve_target_subclass_instantiated():
    target = resolve_target_spec("tests.fixture_rag:EchoTarget")
    assert isinstance(target, EchoTarget)
    assert target.query("hi")["answer"] == "echo: hi"


def test_resolve_dotted_attribute_path():
    target = resolve_target_spec("tests.fixture_rag:Namespace.target")
    assert isinstance(target, FunctionTarget)
    assert target.query("hi")["answer"].startswith("answer to hi")


def test_resolve_non_callable_non_target_errors():
    with pytest.raises(TargetResolutionError, match=re.escape("neither a Target")):
        resolve_target_spec("tests.fixture_rag:not_callable_not_target")


def test_resolve_missing_colon_gives_helpful_message():
    with pytest.raises(TargetResolutionError, match=re.escape("module:attribute")):
        resolve_target_spec("tests.fixture_rag.simple_target")


def test_resolve_bad_module_errors():
    with pytest.raises(TargetResolutionError):
        resolve_target_spec("no_such_module_xyz:fn")


def test_resolve_bad_attribute_errors():
    with pytest.raises(TargetResolutionError):
        resolve_target_spec("tests.fixture_rag:no_such_attr")


def test_isinstance_check_precedes_callable_check_for_target_with_call():
    """A Target instance (which may itself define __call__) must be
    returned as-is, not wrapped in FunctionTarget - isinstance must be
    checked before the generic `callable` branch."""
    target = resolve_target_spec("tests.fixture_rag:echo_target_instance")
    assert type(target) is EchoTarget
    assert not isinstance(target, FunctionTarget)


def test_resolve_target_spec_returns_target_instance():
    target = resolve_target_spec("tests.fixture_rag:simple_target")
    assert isinstance(target, Target)
