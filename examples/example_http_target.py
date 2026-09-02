"""Evaluate a RAG pipeline exposed over HTTP (see PLAN.md 4.3 / README.md's
"HTTP target" section for the default wire contract)."""

from raginject import HTTPTarget, Runner

with HTTPTarget(url="http://localhost:8000/query") as target:
    runner = Runner(target=target)
    runner.load_patterns()
    result = runner.run()

print(result.score)
print(result.summary)

# Equivalent from the CLI, with a CI-style gate (nonzero exit if score < 0.8):
#   raginject run --target-url http://localhost:8000/query --min-score 0.8
