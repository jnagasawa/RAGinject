"""Error hierarchy for raginject.

This module imports nothing else from the package (to avoid import cycles:
other modules in the package need to raise these errors, so this module
must not import back from them).

Two branches, and the distinction matters a lot:

- ``ConfigurationError``: the *user's setup* is wrong (bad CLI flags, a
  function signature that can't accept ``context``, an unknown judge name,
  a malformed pattern file, ...). This never becomes an ``AttackOutcome`` —
  it aborts the run entirely (CLI exit code 2).
- ``TargetError``: the *target* failed at run time while answering a
  specific query (connection refused, timeout, non-2xx / non-JSON / a
  response that doesn't satisfy the ``QueryResult`` contract). This becomes
  a single ``AttackOutcome`` with ``status="error"`` and is excluded from
  the score denominator — it must never be silently conflated with
  "blocked" or "leaked".

    RagInjectError
    ├── ConfigurationError
    │   ├── PatternError            (has source/index/pattern_id)
    │   └── TargetResolutionError
    └── TargetError
        ├── TargetConnectionError
        ├── TargetTimeoutError
        └── TargetResponseError
"""

from typing import Optional


class RagInjectError(Exception):
    """Base class for all raginject errors."""


class ConfigurationError(RagInjectError):
    """The user's setup is wrong. Never becomes an AttackOutcome; aborts the run."""


class PatternError(ConfigurationError):
    """An attack pattern file/entry is invalid.

    Carries enough context to produce messages like:
    ``custom.yaml[2] (id=exfil-9): success_criteria.forbidden_in_answer: ...``
    """

    def __init__(
        self,
        message: str,
        *,
        source: Optional[str] = None,
        index: Optional[int] = None,
        pattern_id: Optional[str] = None,
    ):
        super().__init__(message)
        self.source = source
        self.index = index
        self.pattern_id = pattern_id


class TargetResolutionError(ConfigurationError):
    """A `--target-module`/`--target-url` spec could not be resolved to a Target."""


class TargetError(RagInjectError):
    """The target failed at run time while answering a specific query.

    Becomes a single AttackOutcome with status="error"; excluded from the
    score denominator.
    """


class TargetConnectionError(TargetError):
    """Could not connect to the target (e.g. connection refused/DNS failure)."""


class TargetTimeoutError(TargetError):
    """The target did not respond within the configured timeout."""


class TargetResponseError(TargetError):
    """The target responded, but with a non-2xx status, non-JSON body, or a
    body that doesn't satisfy the QueryResult contract."""
