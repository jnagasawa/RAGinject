"""Regression guard: shipped files must never reference the internal design docs.

`PLAN.md`, `ROADMAP.md`, and `CLAUDE.md` are deliberately kept out of the
repo (see `.gitignore`) - the owner does not want the spec published. That
means anything a user can actually read - `src/` (shipped in the wheel, and
visible via `help()`) and `examples/` (public in the repo) - must be
self-contained: state the rule or the reason inline instead of pointing a
reader at a document they cannot open.
"""

import re
from pathlib import Path

import pytest

_FORBIDDEN_PATTERNS = [
    re.compile(r"PLAN\.md"),
    re.compile(r"ROADMAP\.md"),
    re.compile(r"Task \d+ plan"),
    re.compile(r"decision [A-Z]\b"),
]


#: Directories whose contents reach a user: the packaged source and the
#: public examples. `tests/` is excluded because this file necessarily
#: names the very strings it forbids.
_SCANNED_DIRS = ("src", "examples")


def test_shipped_files_have_no_internal_doc_references():
    repo_root = Path(__file__).resolve().parents[1]
    scanned = [
        repo_root / name for name in _SCANNED_DIRS if (repo_root / name).is_dir()
    ]
    if not scanned:
        pytest.skip("no source tree present (installed-package-only environment)")

    offenses = []
    for directory in scanned:
        for path in sorted(directory.rglob("*")):
            if path.suffix not in (".py", ".yaml", ".yml"):
                continue
            text = path.read_text(encoding="utf-8")
            for lineno, line in enumerate(text.splitlines(), start=1):
                for pattern in _FORBIDDEN_PATTERNS:
                    if pattern.search(line):
                        offenses.append(
                            f"{path.relative_to(repo_root)}:{lineno}: {line.strip()!r}"
                        )

    assert not offenses, (
        "Found reference(s) to internal design docs (PLAN.md / ROADMAP.md / "
        "CLAUDE.md) in a shipped file. These docs are deliberately kept out "
        "of the repo, so anything a user can read must be self-contained - "
        "state the rule or the reason inline instead of pointing at a "
        "document the reader cannot open:\n" + "\n".join(offenses)
    )
