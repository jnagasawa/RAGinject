"""Optional adapters for popular RAG frameworks.

Import from the submodules directly (`raginject.integrations.langchain`,
`raginject.integrations.llamaindex`). Nothing is imported here on purpose:
the adapters are duck typed and never import the framework at module load,
so raginject's own dependencies do not change.
"""
