"""Evaluate a RAG pipeline exposed as a Python function."""

from typing import List, Optional

from raginject import FunctionTarget, Runner


def my_rag(question: str, context: Optional[List[str]] = None) -> dict:
    # your existing RAG logic - `context` is the list of documents raginject
    # wants your pipeline to treat as retrieved for this query; make sure
    # your pipeline actually looks at it (see README.md's Quickstart)
    docs = context or []
    answer = f"Answer to: {question}"
    return {"answer": answer, "sources": [f"doc{i}" for i in range(len(docs))]}


target = FunctionTarget(my_rag)
runner = Runner(target=target)
runner.load_patterns()
result = runner.run()

print(result.score)
print(result.summary)
