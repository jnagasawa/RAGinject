from importlib.metadata import version

from .adapters import FunctionTarget, HTTPTarget
from .core import Result, Runner
from .target import QueryResult, Target

__all__ = [
    "FunctionTarget",
    "HTTPTarget",
    "QueryResult",
    "Result",
    "Runner",
    "Target",
]

__version__ = version("raginject")
