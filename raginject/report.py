"""Result output formatting (text/json). See PLAN.md 7."""

from .core import Result

#: Schema version stamped into JSON reports, so future regression detection
#: (Milestone 3) can tell which report format it is comparing against.
REPORT_SCHEMA_VERSION = 1


def format_text(result: Result) -> str:
    raise NotImplementedError


def format_json(result: Result) -> str:
    raise NotImplementedError
