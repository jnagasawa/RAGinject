"""Evaluate a RAG pipeline exposed over HTTP (see PLAN.md 4.3 for the default contract)."""

from raginject import HTTPTarget, Runner

target = HTTPTarget(url="http://localhost:8000/query")
runner = Runner(target=target)
runner.load_patterns()
result = runner.run()

print(result.score)
print(result.summary)
