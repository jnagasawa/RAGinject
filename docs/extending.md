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

## LangChain and LlamaIndex integrations

Both live in `raginject.integrations` and are duck typed: they import neither
framework at module load. They are mode A only (see "Corpus injection" in the
README) and write into the store you give them.

**`LangChainVectorStoreInjector(vectorstore)`**

- `inject(document_id, content)` calls
  `vectorstore.add_texts([content], metadatas=[{"source": document_id}], ids=[document_id])`.
- `remove(document_id)` calls `vectorstore.delete(ids=[document_id])`.
- `description` is `LangChainVectorStoreInjector(<class name>)`, never a
  connection string.

**`LangChainTarget(chain, *, input_key=None, answer_key="answer", sources_key="context")`**

- Calls `chain.invoke(question)`, or `chain.invoke({input_key: question})` when
  `input_key` is set (use `"input"` for `create_retrieval_chain`).
- A `str` output is the answer; so is an object with a `str` `.content` (a chat
  message). Both have no sources.
- A `dict` output takes the answer from `answer_key` (a `str` or a message) and
  the sources from `sources_key`: each Document becomes its `id`, else its
  `metadata["source"]`; entries with neither are dropped. A missing
  `sources_key` means no sources.
- Anything else, or a dict without `answer_key`, raises `TargetResponseError`.
- A non-empty `context` raises `ConfigurationError` (the target is
  question-only). An exception from the chain becomes a `TargetError`, so that
  one query is an `error` row and the run continues.

**`LlamaIndexInjector(index)`**

- `inject` calls `index.insert(Document(text=content, doc_id=document_id, metadata={"source": document_id}))`.
  `Document` is imported lazily; without `llama-index-core` it raises
  `ConfigurationError`.
- `remove` calls `index.delete_ref_doc(document_id, delete_from_docstore=True)`.

**`LlamaIndexTarget(query_engine)`**

- `query_engine` is an object with `.query`, or a zero-argument function
  returning one, called once per query. Prefer the function: an engine from
  `index.as_query_engine()` snapshots the index's node ids when built, so one
  built before `inject` never retrieves the injected document.
- The answer is `str(response.response)`, or `""` when it is `None`. Sources
  are each `response.source_nodes` entry's `node.ref_doc_id`, else
  `node.metadata["source"]`, with empty values dropped.
- `context` and exception handling match `LangChainTarget`.

Mode A's retrieval check and the `retrieval_match` judge look for the injected
document id in `sources`, which is why both injectors stamp it as the id and as
`metadata["source"]` and both targets read it back.

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
