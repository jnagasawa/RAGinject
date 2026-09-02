"""llm_judge: LLM-as-judge, using a rubric. Requires the `llm-judge` extra (OpenAI/Anthropic SDK).

Milestone 2. Not implemented yet.
"""

from .base import Judge, JudgeContext, Verdict


class LLMJudge(Judge):
    def judge(self, ctx: JudgeContext) -> Verdict:
        raise NotImplementedError
