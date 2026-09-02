"""Package version, resolved from installed metadata.

Falls back to a dev placeholder when raginject is imported from a plain
checkout that hasn't been `pip install`-ed (this used to raise
`PackageNotFoundError` on import — see the Task 1 plan, Phase 0).
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("raginject")
except PackageNotFoundError:
    __version__ = "0.0.0.dev0"
