"""Test-only plugin module: importing this registers the "always_blocks"
judge, exercising the CLI's `--plugin` flag (see tests/test_cli.py)."""

from raginject.judges import Judge, JudgeContext, Verdict, register_judge


@register_judge("always_blocks")
class _AlwaysBlocksJudge(Judge):
    def judge(self, ctx: JudgeContext) -> Verdict:
        return Verdict(attack_succeeded=False, reason="always blocks (test plugin)")
