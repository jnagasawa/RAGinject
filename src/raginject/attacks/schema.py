"""Attack pattern schema (see PLAN.md 5.1)."""

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
