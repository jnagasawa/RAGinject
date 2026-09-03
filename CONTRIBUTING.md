# Contributing

## Setup

```bash
uv sync --all-extras      # recommended
uv run pytest
```

Without `uv`: `dev` is a dependency-group, not an extra, so `pip install -e
".[dev,llm-judge]"` will not pull in pytest/ruff. Use:

```bash
pip install -e ".[llm-judge]" && pip install pytest ruff
```

Before opening a PR, run what CI runs:

```bash
uv run ruff check . && uv run ruff format --check .
uv run pytest --cov          # fails under 90% coverage (see pyproject.toml)
```

`--cov` is opt-in so a plain `uv run pytest` stays fast; CI always passes it.
Note that `ruff format` also formats the Python code blocks inside `README.md`,
so a snippet added there has to be formatted like real source.

## Regenerating the demo GIF

`docs/demo.gif` in the README is a recording of real CLI output, produced from
the committed script `demo.tape` with [VHS](https://github.com/charmbracelet/vhs):

```bash
brew install vhs      # or see the VHS README
vhs demo.tape         # rewrites docs/demo.gif
```

Re-record it whenever the CLI's output changes — a screenshot that no longer
matches what the tool prints is worse than no screenshot. Keep it under ~1 MB;
adjust `Set Width` / `Set Height` in the tape if a line starts wrapping.

The GIF opens on the wordmark in `docs/banner.txt`, which the tape `cat`s. That
file is the single source for the art: README's opening code block must hold the
same six lines. Note that raginject itself never prints the banner. `run` has to
keep stdout parseable for `--output json`, CI logs readable, and the box-drawing
characters would raise `UnicodeEncodeError` on a legacy Windows console — so the
wordmark stays in documentation, where none of that can bite.

## Guidelines

- Keep core dependencies minimal (`pyyaml`, `pydantic`, `httpx`, `click`). New
  hard dependencies need a discussion first. If one is approved, run
  `uv lock` and commit the updated `uv.lock` alongside your `pyproject.toml`
  change — CI runs `uv sync --all-extras --frozen`, which fails if the two
  files disagree.
- `llm_judge` and other optional integrations must stay behind extras
  (`pip install raginject[llm-judge]`) — `keyword_match` must always work
  with zero LLM API access.
- New attack patterns go in `src/raginject/attacks/patterns/`. New judges
  implement `src/raginject/judges/base.py`. New adapters implement
  `src/raginject/target.py`'s `Target`.
- Add/update tests under `tests/` for any new behavior.
- Ask as little of the user's pipeline as possible. Today the only thing
  raginject requires is that a target accept a `context` argument (mode B's
  injection channel). Don't add a second such requirement — no mandatory
  callbacks, config files, or wrappers around their retriever.
- `Target` implementations must be safe for concurrent `query()` calls. This
  isn't exercised in Milestone 1, but a future `--concurrency` option will
  call `query()` from multiple threads at once, and that must not require a
  breaking change to the `Target` contract — see `src/raginject/target.py`'s
  docstring.

## Adding a judge

Subclass `raginject.judges.base.Judge` and register it with
`@register_judge("your_name")`:

```python
# src/raginject/judges/your_judge.py
from .base import Judge, JudgeContext, Verdict, register_judge


@register_judge("your_name")
class YourJudge(Judge):
    def judge(self, ctx: JudgeContext) -> Verdict:
        # ctx.pattern.success_criteria carries whatever fields your pattern
        # YAML sets under `success_criteria:` (extra fields are allowed there)
        ...
        return Verdict(attack_succeeded=..., reason="...")

    @classmethod
    def validate_criteria(cls, criteria) -> None:
        # Optional: raise ConfigurationError if `criteria` can't be used with
        # this judge (e.g. a required field is missing). Called during
        # preflight, before any query is sent, so a misconfigured pattern
        # fails loudly instead of silently reporting "blocked". The base
        # class default is a no-op.
        ...
```

Import it from `src/raginject/judges/__init__.py` if it's a built-in judge (so the
`@register_judge` decorator runs on `import raginject`); a third-party judge
instead gets loaded on demand via `raginject run --plugin your_package.your_judge`.

## Adding an adapter

Subclass `raginject.target.Target` and implement `query`:

```python
from typing import List, Optional
from raginject.target import QueryResult, Target, normalize_query_result


class YourTarget(Target):
    def query(self, question: str, context: Optional[List[str]] = None) -> QueryResult:
        raw = ...  # however your adapter talks to the target
        return normalize_query_result(raw, source="YourTarget")

    @property
    def target_description(self) -> str:
        return "a short, secret-free description shown in reports"
```

Reuse `normalize_query_result()` (from `src/raginject/target.py`) rather than
hand-rolling response validation — it's what gives `FunctionTarget` and
`HTTPTarget` their consistent, informative error messages for a malformed
response, and new adapters should match that behavior.

## Adding a report formatter

`register_formatter` is a decorator shaped exactly like `register_judge`:

```python
# src/raginject/report.py, or your own plugin module
from raginject.report import register_formatter


@register_formatter("your_format")
def format_your_format(result, options=None) -> str:
    ...
    return rendered_text
```

A built-in formatter is registered by importing its module from
`src/raginject/report.py`; a third-party one is loaded the same way as a
third-party judge, via `raginject run --output your_format --plugin your_package.your_formatter`.

## Issues / PRs

Open an issue before large changes. Keep PRs small and focused.

Contributions are licensed under Apache-2.0, the same as the rest of the
project.
