"""Load and merge attack patterns from YAML."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

import yaml
from pydantic import ValidationError

from ..errors import ConfigurationError, PatternError
from .schema import AttackPattern

DEFAULT_PATTERNS_PATH = Path(__file__).parent / "patterns"

#: Built-in pattern sets that are opt-in only - never merged into
#: `load_default_patterns()` - reachable from the CLI via `--pattern-set`.
#: Kept out of the default corpus deliberately: adding them there would
#: change every existing user's default pattern count/ids, which
#: `check_comparable` (see `raginject.baseline`) would then reject every
#: existing `--baseline` file over.
PATTERN_SETS_PATH = Path(__file__).parent / "pattern_sets"

BUILTIN_PATTERN_SETS: Dict[str, Path] = {
    "retriever": PATTERN_SETS_PATH / "retriever",
}


def _format_validation_error(
    exc: ValidationError, *, source: str, index: int, raw: Any
) -> str:
    pattern_id = raw.get("id", "?") if isinstance(raw, dict) else "?"
    first = exc.errors()[0]
    loc = ".".join(str(part) for part in first["loc"])
    return f"{source}[{index}] (id={pattern_id}): {loc}: {first['msg']}"


def parse_patterns(data: Any, source: str) -> List[AttackPattern]:
    """Parse already-YAML-loaded `data` (a list of pattern dicts) into
    AttackPattern objects.

    Raises `PatternError` (never a raw pydantic traceback) for:
    - `data` not being a list
    - any entry failing schema validation (unknown keys included, since
      AttackPattern has extra="forbid")
    - a duplicate `id` within this same source
    """
    if not isinstance(data, list):
        raise PatternError(
            f"{source}: expected a YAML list of patterns, got {type(data).__name__}",
            source=source,
        )

    patterns: List[AttackPattern] = []
    seen_ids: Dict[str, int] = {}

    for index, raw in enumerate(data):
        try:
            pattern = AttackPattern.model_validate(raw)
        except ValidationError as exc:
            message = _format_validation_error(exc, source=source, index=index, raw=raw)
            pattern_id = raw.get("id") if isinstance(raw, dict) else None
            raise PatternError(
                message, source=source, index=index, pattern_id=pattern_id
            ) from exc

        if pattern.id in seen_ids:
            raise PatternError(
                f"{source}[{index}] (id={pattern.id}): duplicate id "
                f"(first seen at index {seen_ids[pattern.id]})",
                source=source,
                index=index,
                pattern_id=pattern.id,
            )
        seen_ids[pattern.id] = index
        patterns.append(pattern)

    return patterns


def _load_file(path: Path) -> List[AttackPattern]:
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if data is None:
        data = []
    return parse_patterns(data, source=path.name)


def iter_pattern_files(path: Union[str, Path]) -> List[Path]:
    """Return the YAML files to load for `path`: itself if it's a file, or
    the sorted `*.yaml`/`*.yml` files directly inside it if it's a directory.

    Raises `PatternError` if `path` does not exist, or if it is a directory
    with no pattern files in it.
    """
    path = Path(path)
    if path.is_dir():
        files = sorted(p for p in path.iterdir() if p.suffix in (".yaml", ".yml"))
        if not files:
            # Silently yielding zero patterns would make a run "pass" without
            # having tested anything - the worst failure mode for a gate.
            raise PatternError(
                f"{path}: directory contains no .yaml/.yml pattern files",
                source=str(path),
            )
        return files
    if not path.exists():
        raise PatternError(f"{path}: no such file or directory", source=str(path))
    return [path]


def _merge(patterns: Sequence[AttackPattern]) -> List[AttackPattern]:
    """Later entries override earlier ones with the same id, but keep the
    position of the id's first occurrence."""
    merged: Dict[str, AttackPattern] = {}
    for pattern in patterns:
        merged[pattern.id] = pattern
    return list(merged.values())


def load_default_patterns() -> List[AttackPattern]:
    """Load the built-in default pattern set (all `*.yaml`/`*.yml` files
    directly inside `patterns/`, merged in sorted-filename order)."""
    files = iter_pattern_files(DEFAULT_PATTERNS_PATH)
    all_patterns: List[AttackPattern] = []
    for file_path in files:
        all_patterns.extend(_load_file(file_path))
    return _merge(all_patterns)


def load_patterns(path: Optional[Union[str, Path]] = None) -> List[AttackPattern]:
    """Load patterns from `path` (a file or directory), or the built-in
    default set if path is None.

    When `path` is a directory, files are read in sorted order and merged:
    a later file's pattern for a given id overrides an earlier file's, but
    the id keeps the position of its first occurrence overall.
    """
    if path is None:
        return load_default_patterns()

    files = iter_pattern_files(path)
    all_patterns: List[AttackPattern] = []
    for file_path in files:
        all_patterns.extend(_load_file(file_path))
    return _merge(all_patterns)


def available_pattern_sets() -> List[str]:
    """Names of the built-in opt-in pattern sets reachable via `--pattern-set`."""
    return sorted(BUILTIN_PATTERN_SETS.keys())


def load_pattern_set(name: str) -> List[AttackPattern]:
    """Load a built-in opt-in pattern set by name (e.g. "retriever").

    Reuses the same file-loading/merge path as `load_default_patterns()` -
    `iter_pattern_files()` + `_load_file()` + `_merge()` - so a set with
    multiple YAML files behaves identically to the default corpus.

    Raises `ConfigurationError` (not `PatternError`) for an unknown name:
    this is a user setup mistake caught before any query is sent, and the
    CLI maps `ConfigurationError` to exit code 2 for exactly that reason.
    """
    set_path = BUILTIN_PATTERN_SETS.get(name)
    if set_path is None:
        available = ", ".join(available_pattern_sets()) or "(none)"
        raise ConfigurationError(
            f"unknown pattern set {name!r}; available pattern sets: {available}"
        )
    files = iter_pattern_files(set_path)
    all_patterns: List[AttackPattern] = []
    for file_path in files:
        all_patterns.extend(_load_file(file_path))
    return _merge(all_patterns)


def filter_patterns(
    patterns: Sequence[AttackPattern],
    ids: Optional[Sequence[str]] = None,
    categories: Optional[Sequence[str]] = None,
) -> List[AttackPattern]:
    """Filter `patterns` by id and/or category (Python API only in M1).

    An empty/None `ids` or `categories` means "do not filter on that field".
    This matters for the CLI: click's `multiple=True` yields `()` when a flag
    is not given, and treating that as "match nothing" would silently reduce
    every run to zero patterns.
    """
    result = list(patterns)
    if ids:
        id_set = set(ids)
        result = [p for p in result if p.id in id_set]
    if categories:
        category_set = set(categories)
        result = [p for p in result if p.category in category_set]
    return result
