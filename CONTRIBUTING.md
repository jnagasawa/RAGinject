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

## Guidelines

- Keep core dependencies minimal (`pyyaml`, `pydantic`, `httpx`, `click`). New
  hard dependencies need a discussion first.
- `llm_judge` and other optional integrations must stay behind extras
  (`pip install raginject[llm-judge]`) — `keyword_match` must always work
  with zero LLM API access.
- New attack patterns go in `raginject/attacks/patterns/`. New judges
  implement `raginject/judges/base.py`. New adapters implement
  `raginject/target.py`'s `Target`.
- Add/update tests under `tests/` for any new behavior.
- Non-invasive by design: don't add anything that requires users to modify
  their own RAG pipeline code.

## Issues / PRs

Open an issue before large changes. Keep PRs small and focused.

Contributions are licensed under Apache-2.0, the same as the rest of the
project.
