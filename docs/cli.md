# CLI reference

*Part of the [raginject](https://github.com/jnagasawa/RAGinject) documentation. Start at the [README](https://github.com/jnagasawa/RAGinject#readme).*

| Command | Purpose |
|---|---|
| `raginject run` | Run attack patterns against a target and report/gate |
| `raginject validate PATH...` | Check pattern files (or directories) load and are well-formed |
| `raginject list-patterns` | List `id / category / judge / description` of what would run |

## `raginject run` options

| Flag | Default | Meaning |
|---|---|---|
| `--target-module` | none | `module:attribute` target spec |
| `--target-url` | none | HTTP endpoint URL |
| `--target-method` | `POST` | `GET`, `POST`, `PUT`, or `PATCH` |
| `--request-key` | `question` | Request field carrying the question |
| `--request-context-key` | `context` | Request field carrying the injected documents |
| `--response-answer-key` | `answer` | Response field holding the answer |
| `--response-sources-key` | `sources` | Response field holding the sources |
| `--header` | none | `'Name: value'`, repeatable |
| `--timeout` | `30.0` | Per-request timeout in seconds |
| `--patterns` | none | Pattern file or directory, repeatable |
| `--no-default-patterns` | off | Skip the built-in pattern set |
| `--plugin` | none | Module to import (registers judges/formatters), repeatable |
| `--output` | `text` | `text`, `json`, `markdown`, `html`, or a registered formatter |
| `--max-answer-chars` | `2000` | Truncate answers in reports (`0` disables) |
| `--min-score` | none | Fail (exit `1`) below this score. **No default: no gate unless set** |
| `--verbose` | off | Include answers in the text report |
| `--color` / `--no-color` | auto | Colorize `text`-report status labels. Default: on for a real terminal, off otherwise or when `NO_COLOR` is set |
| `--judge` | none | Judge name overriding every pattern's `success_criteria.type` |
| `--verify-leaks` | none | Judge name used to re-judge only the rows the primary judge marked `leaked` |
| `--judge-model` | none | Model name (`llm_judge` only) |
| `--judge-provider` | none | `openai` or `anthropic` (`llm_judge` only) |
| `--judge-base-url` | none | OpenAI-compatible endpoint, e.g. an OpenRouter URL (`llm_judge` only) |
| `--corpus-injector` | none | `module:attribute` `CorpusInjector` spec; enables corpus injection (mode A) |
| `--no-verify-retrieval` | off | Don't error rows whose injected document wasn't in the target's `sources` (mode A only) |
| `--baseline` | none | Path to a JSON report from an earlier run, to compare this run against (see [Catching regressions](https://github.com/jnagasawa/RAGinject#catching-regressions)) |
| `--max-drop` | none | Fail (exit `1`) if the score drops below `baseline score - this`. Requires `--baseline` |

`--target-module` and the HTTP-specific flags are mutually exclusive;
combining them is a configuration error (exit `2`) rather than a silently
ignored flag.

Options are also settable as environment variables named
`RAGINJECT_RUN_<OPTION>` (`RAGINJECT_RUN_TARGET_URL`,
`RAGINJECT_RUN_MIN_SCORE`, and so on), which keeps tokens out of committed
config files. One caveat: values of repeatable options (`--header`,
`--patterns`, `--plugin`) are split on whitespace when read from the
environment, so a header like `Authorization: Bearer <token>` has to be passed
on the command line.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Every gate that was requested (`--min-score` and/or `--max-drop`) passed, **or** neither was given at all (a warning goes to stderr in that case, since the run does not gate) |
| `1` | `--min-score` was given and the score is below it, **or** `--max-drop` was given and the baseline comparison regressed |
| `2` | Any configuration error (bad flags, unknown judge, zero patterns loaded, invalid pattern file, a `--baseline` that doesn't parse or doesn't match this run's pattern set/mode, ...); **or** every attack errored (zero scoreable outcomes, meaning the target was never successfully reached, so returning `1` would misreport a connectivity failure as a security failure); or an unexpected crash (set `RAGINJECT_DEBUG=1` for a traceback instead of the one-line message) |

`--min-score` has no default on purpose: a CI job that forgets to set it does
not silently gate on score `0.0`; it warns on stderr and exits `0`. The same
is true of `--max-drop`. A run given neither flag never gates.

With `--output json`, stdout is pure JSON (warnings and errors go to stderr),
so it pipes safely. The payload carries a `schema_version`, top-level `score`
and `counts`, and one entry per attack. That is stable enough to diff between
runs, which is exactly what [Catching
regressions](https://github.com/jnagasawa/RAGinject#catching-regressions) does
for you.

## Loading pattern files

Unknown top-level keys are rejected (a typo like `injected_contents:` fails
loudly instead of silently loading an empty attack). Validate before running:

```bash
raginject validate ./custom_patterns.yaml
# ./custom_patterns.yaml: ok (1 pattern(s))

raginject list-patterns
# indirect-injection-basic-001    indirect_injection    keyword_match    Instruction override embedded in a retrieved document
# indirect-injection-basic-002    indirect_injection    keyword_match    Role-play override attempt
# ...
```

Load them alongside (or instead of) the built-in set:

```bash
raginject run --target-module myapp.rag:my_rag --patterns ./custom_patterns.yaml
raginject run --target-module myapp.rag:my_rag --patterns ./custom_patterns.yaml --no-default-patterns
```

`--patterns` is repeatable and accepts a directory (all `*.yaml`/`*.yml` files
in it, sorted). Loading is additive: a pattern `id` loaded again later
overrides the earlier one, keeping its original position, rather than being
rejected as a duplicate, so you can override a single built-in pattern by
re-declaring its `id` in your own file.
