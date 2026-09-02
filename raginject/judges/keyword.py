"""keyword_match judge: attack succeeds if any forbidden string appears in the answer."""

from .base import Judge, JudgeContext, Verdict


class KeywordMatchJudge(Judge):
    def judge(self, ctx: JudgeContext) -> Verdict:
        raise NotImplementedError
