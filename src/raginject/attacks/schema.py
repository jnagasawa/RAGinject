"""Attack pattern schema."""

from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class SuccessCriteria(BaseModel):
    model_config = ConfigDict(extra="allow")

    # Name of a judge registered in the judge registry (see judges/base.py),
    # e.g. "keyword_match" or "llm_judge". Not a fixed enum: new judges can
    # register their own name and criteria fields.
    type: str
    forbidden_in_answer: Optional[List[str]] = None
    rubric: Optional[str] = None


class AttackPattern(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    category: str
    description: str
    injected_content: str
    question: str
    success_criteria: SuccessCriteria
    # The instruction part of `injected_content`, as an exact substring of
    # it. Required for default-corpus patterns (enforced by the test suite,
    # not here, so user-written patterns without one stay valid); used by
    # `--host-from-corpus`, which splices only this into a real corpus
    # document instead of injecting the synthetic host document around it.
    payload: Optional[str] = None
