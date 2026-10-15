"""Evaluate a LangChain RAG chain through corpus injection (mode A).

Offline: fake embeddings and a fake chat model, so no API key is needed. Swap
`vectorstore` and `chain` for your own; the last three lines stay the same.
raginject writes each attack document into `vectorstore` and deletes it again,
so point it at a test or staging store, not production.

Requires `langchain-core` (`pip install langchain-core`).
"""

from langchain_core.embeddings import DeterministicFakeEmbedding
from langchain_core.language_models import FakeListChatModel
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.vectorstores import InMemoryVectorStore

from raginject import Runner
from raginject.integrations.langchain import (
    LangChainTarget,
    LangChainVectorStoreInjector,
)

vectorstore = InMemoryVectorStore(DeterministicFakeEmbedding(size=32))
vectorstore.add_texts(
    ["Refunds are issued within 14 days.", "Support is open on weekdays."]
)
retriever = vectorstore.as_retriever(search_kwargs={"k": 10})

prompt = ChatPromptTemplate.from_template("Context:\n{context}\n\nQuestion: {question}")
llm = FakeListChatModel(responses=["I can only summarize the documents."])


def format_docs(docs):
    return "\n".join(doc.page_content for doc in docs)


answer_chain = prompt | llm | StrOutputParser()
chain = RunnablePassthrough.assign(
    context=lambda x: retriever.invoke(x["question"]),
).assign(
    answer=lambda x: answer_chain.invoke({**x, "context": format_docs(x["context"])})
)
# The chain takes {"question": ...} and returns {"answer", "context", ...}.

target = LangChainTarget(chain, input_key="question")
injector = LangChainVectorStoreInjector(vectorstore)

runner = Runner(target=target, corpus_injector=injector)
runner.load_patterns()
result = runner.run()

print(result.score)
print(result.summary)
