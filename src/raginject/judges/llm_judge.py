"""llm_judge: LLM-as-judge, using a rubric. Requires the `llm-judge` extra (OpenAI/Anthropic SDK).

Milestone 2. Not implemented yet.

Do NOT import this module from `judges/__init__.py`: it will depend on the
optional `llm-judge` extra (openai/anthropic), and importing it eagerly
would pull those SDKs into every `import raginject`. When it is
implemented, `get_judge` should lazy-import it on a registry miss.
"""

from .base import Judge, JudgeContext, Verdict


class LLMJudge(Judge):
    def judge(self, ctx: JudgeContext) -> Verdict:
        raise NotImplementedError
