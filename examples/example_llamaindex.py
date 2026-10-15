"""Evaluate a LlamaIndex query engine through corpus injection (mode A).

Offline: `MockEmbedding` and `MockLLM`, so no API key is needed. `MockLLM()`
with no `max_tokens` echoes its prompt (a maximally vulnerable pipeline, score
0.00); `max_tokens=8` emits filler text and never leaks (score 1.00). Swap `index`
for your own; the last lines stay the same. raginject inserts each attack
document into `index` and deletes it again, so point it at a test or staging
index, not production.

Requires `llama-index-core` (`pip install llama-index-core`).
"""

from llama_index.core import Document, MockEmbedding, VectorStoreIndex
from llama_index.core.llms import MockLLM

from raginject import Runner
from raginject.integrations.llamaindex import LlamaIndexInjector, LlamaIndexTarget

index = VectorStoreIndex.from_documents(
    [
        Document(text="Refunds are issued within 14 days.", doc_id="faq-refunds"),
        Document(text="Support is open on weekdays.", doc_id="faq-support"),
    ],
    embed_model=MockEmbedding(embed_dim=8),
)


def build_query_engine():
    return index.as_query_engine(llm=MockLLM(max_tokens=8), similarity_top_k=10)


# Pass the factory, not a built engine: an engine snapshots the index's node ids
# when it is built, so one built before injection would never see the attack doc.
target = LlamaIndexTarget(build_query_engine)
injector = LlamaIndexInjector(index)

runner = Runner(target=target, corpus_injector=injector)
runner.load_patterns()
result = runner.run()

print(result.score)
print(result.summary)
