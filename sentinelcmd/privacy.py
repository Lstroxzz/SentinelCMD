"""Minimize retained command-line data and neutralize terminal control characters."""

import re

_SECRET = re.compile(
    r'''(?ix)(\b(?:password|passwd|pwd|token|secret|api[_-]?key|authorization)\b\s*[=:]\s*)
    (?:"[^"]*"|'[^']*'|[^\s]+)'''
)
_FLAG = re.compile(
    r'''(?ix)((?:--?|/)(?:password|passwd|pwd|token|secret|api[_-]?key)\s+)
    (?:"[^"]*"|'[^']*'|[^\s]+)'''
)


def command_line_for_storage(value: str | list[str] | tuple[str, ...] | None, enabled: bool) -> str | None:
    if isinstance(value, (list, tuple)):
        value = " ".join(str(argument) for argument in value)
    if not enabled or not value or not isinstance(value, str):
        return None
    # Best effort only: arbitrary positional secrets cannot be identified reliably.
    result = _SECRET.sub(r"\1[REDACTED]", value)
    result = _FLAG.sub(r"\1[REDACTED]", result)
    # Stored command lines must never carry terminal control characters.
    return "".join(ch if ch.isprintable() else " " for ch in result)[:8192]


def safe_text(value: object, limit: int = 1000) -> str:
    text = str(value) if value is not None else "-"
    return "".join(ch if ch.isprintable() else " " for ch in text)[:limit]


def csv_cell(value: object) -> str:
    text = safe_text(value, 32768)
    # Spreadsheet applications may execute formulas even in a quoted CSV cell.
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text
