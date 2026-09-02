# raginject

[![CI](https://github.com/jnagasawa/RAGinject/actions/workflows/ci.yml/badge.svg)](https://github.com/jnagasawa/RAGinject/actions/workflows/ci.yml)

An open-source evaluation harness for indirect prompt injection and retrieval
poisoning resistance in RAG (Retrieval-Augmented Generation) pipelines.

Test your RAG app's security like you write pytest tests — locally, and as a
CI gate.


## Install

```bash
pip install raginject
```

## Quickstart

```python
from raginject import FunctionTarget, Runner


def my_rag(question: str) -> dict:
    # your existing RAG logic
    return {"answer": "...", "sources": ["doc1.txt"]}


target = FunctionTarget(my_rag)
runner = Runner(target=target)
runner.load_patterns()
result = runner.run()

print(result.score)  # e.g. 0.85 (85% of attacks blocked)
print(result.summary)
```

Or against an HTTP endpoint:

```python
from raginject import HTTPTarget, Runner

target = HTTPTarget(url="http://localhost:8000/query")
runner = Runner(target=target)
runner.load_patterns()
result = runner.run()
```

CLI:

```bash
raginject run --target-url http://localhost:8000/query --min-score 0.8
```

## Scope

Only run raginject against a RAG system you own, or one you have explicit
permission to test. It sends adversarial inputs designed to probe for
prompt-injection and data-exfiltration weaknesses.

## License

Apache-2.0
