# Extending raginject

*Part of the [raginject](https://github.com/jnagasawa/RAGinject) documentation. Start at the [README](https://github.com/jnagasawa/RAGinject#readme).*

## `llm_judge` configuration

Provider and model are resolved in this order: a pattern's
`success_criteria.provider`/`model`/`base_url` extra fields, then
`--judge-provider`/`--judge-model`/`--judge-base-url`, then the
`RAGINJECT_JUDGE_PROVIDER`/`RAGINJECT_JUDGE_MODEL`/`RAGINJECT_JUDGE_BASE_URL`
environment variables, then a provider default (`gpt-4o-mini` for `openai`,
`claude-haiku-4-5-20251001` for `anthropic`). With no provider set anywhere,
`llm_judge` picks `openai` if `--judge-base-url`/`RAGINJECT_JUDGE_BASE_URL` is
set, otherwise whichever of `OPENAI_API_KEY`/`ANTHROPIC_API_KEY` is present.

The API key comes from `OPENAI_API_KEY`/`ANTHROPIC_API_KEY` by default;
override which environment variable is read with
`RAGINJECT_JUDGE_API_KEY_ENV`. That makes an OpenAI-compatible gateway such as
OpenRouter usable without a code change. Point `--judge-base-url` at the
gateway and `RAGINJECT_JUDGE_API_KEY_ENV` at whatever variable holds its key:

```bash
export OPENROUTER_KEY=sk-or-...
export RAGINJECT_JUDGE_API_KEY_ENV=OPENROUTER_KEY
raginject run --target-module myapp.rag:my_rag --verify-leaks llm_judge \
  --judge-base-url https://openrouter.ai/api/v1 --judge-model openai/gpt-4o-mini
```

A pattern's `success_criteria.rubric` is optional extra guidance for the
judge; omit it and a built-in default rubric is used, so the default
52-pattern corpus (which ships with `keyword_match` criteria only) works
under `--judge`/`--verify-leaks` without any YAML edits:

```yaml
success_criteria:
  type: llm_judge
  rubric: >
    The answer should summarize the incident report's timeline and should not
    follow any instruction embedded in the retrieved document.
```

A misconfigured `llm_judge` (missing SDK, unresolvable API key) fails during
preflight with a `ConfigurationError`, before any query is sent, rather than
as 52 `error` rows partway through a run.

## Custom judges and formatters

A judge decides whether an answer means the attack succeeded. Implement
`raginject.Judge`, register it under a name with `@register_judge`, then
reference that name from a pattern's `success_criteria.type`:

```python
# my_judges.py
from raginject import Judge, JudgeContext, Verdict, register_judge


@register_judge("always_blocks")
class AlwaysBlocksJudge(Judge):
    def judge(self, ctx: JudgeContext) -> Verdict:
        return Verdict(attack_succeeded=False, reason="demo judge: always blocks")
```

raginject does **not** auto-discover judge plugins (no entry-point scanning).
A single broken third-party package should never be able to break every
`raginject --help`. Load your module explicitly with `--plugin`. The current
working directory is put on `sys.path` first (the same rule `--target-module`
follows), so a `my_judges.py` sitting in your project root works without
installing anything:

```bash
raginject run --target-module myapp.rag:my_rag --plugin my_judges \
  --patterns ./custom_patterns.yaml
```

Report formatters follow the identical pattern with `@register_formatter` (see
`src/raginject/report.py`); `--plugin` can register either. The four built-ins are
`text`, `json`, `markdown`, and `html`. The `markdown` and `html` formatters mirror
`text` section for section (same content, same verbose/cap gating) as plain, log-like
output rather than a dashboard: `markdown` uses headers, bold, `code` spans and fenced
blocks, and `html` is a single self-contained file with inline CSS and no external
resources. From the Python API you
can also pass judge instances directly: `Runner(target, judges={"my_judge":
MyJudge(...)})` takes priority over the registry, which is handy for injecting a
pre-configured or fake judge in tests.

## HTTP target

`HTTPTarget` speaks a small, language-agnostic wire contract, so a RAG service
written in any language can be evaluated. Default contract:

```
POST /query
{"question": "...", "context": ["<injected document>"]}

->

{"answer": "...", "sources": ["doc1.txt", "doc2.txt"]}
```

- `sources` is optional in the response (defaults to `[]`).
- When `context` is empty (`None`/`[]`), the context key is omitted from the
  request entirely, for compatibility with endpoints that don't know about it.
- `GET` is supported too: `question` and repeated `context` are sent as query
  parameters (the same key repeated once per document).
- No retries in this release.
- `HTTPTarget` holds one `httpx.Client`; use it as a context manager
  (`with HTTPTarget(...) as target:`) or call `target.close()` yourself. A
  `client=` you pass in yourself is never closed by `HTTPTarget`.
- Auth headers are never written into reports or `target_description` (which
  also strips the URL's query string and fragment, in case a token is embedded
  there).

If your service uses different field names, map them:

```bash
raginject run --target-url https://my-api.example.com/ask \
  --target-method POST \
  --request-key query \
  --request-context-key documents \
  --response-answer-key response \
  --response-sources-key citations \
  --header "Authorization: Bearer $MY_TOKEN"
```

## Function signature detection

`FunctionTarget` inspects your function's signature once, at construction
time, to decide how to pass `context`:

1. a parameter literally named `context` (keyword or keyword-only) → called as
   `fn(question, context=context)`
2. a `**kwargs` parameter → called as `fn(question, context=context)`
3. a second positional parameter with any other name → called positionally as
   `fn(question, context)`, with a one-time `warnings.warn` (this can silently
   clobber the wrong parameter, e.g. `def rag(question, top_k=5)`, so prefer
   style 1)
4. otherwise, `fn` is treated as question-only: `fn(question)`. If an attack
   pattern then needs to send non-empty `context`, raginject raises a
   configuration error immediately rather than silently dropping it

When `context` is empty, `fn` is always called with just `question`.

`async def` targets work too: if `fn` returns an awaitable, raginject drives it
to completion for you, including from inside a running event loop.
