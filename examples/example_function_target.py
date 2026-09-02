"""Evaluate a RAG pipeline exposed as a Python function."""

from raginject import FunctionTarget, Runner


def my_rag(question: str) -> dict:
    return {"answer": "...", "sources": ["doc1.txt"]}


target = FunctionTarget(my_rag)
runner = Runner(target=target)
runner.load_patterns()
result = runner.run()

print(result.score)
print(result.summary)
