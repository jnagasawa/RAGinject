"""Load and merge attack patterns from YAML (see PLAN.md 5.3)."""

from pathlib import Path
from typing import List, Optional

from .schema import AttackPattern

DEFAULT_PATTERNS_PATH = Path(__file__).parent / "patterns" / "default.yaml"


def load_patterns(path: Optional[str] = None) -> List[AttackPattern]:
    """Load patterns from `path`, or the built-in default set if path is None."""
    raise NotImplementedError
