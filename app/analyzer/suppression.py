"""Inline suppression comments.

    # analyzer-ignore: PY001, PY003        (Python)
    // analyzer-ignore: JV001              (Java, C#)
    /* analyzer-ignore: CS002 */

The comment suppresses the listed rules on its own line, or on the next line
when the comment stands alone on a line. Without rule ids
(``analyzer-ignore``) every rule is suppressed on that line.

Comments come from the language tokenizer/parser (``tokenize`` for Python,
tree-sitter comment nodes for Java/C#), so text that merely looks like the
marker inside a string literal has no effect.

IMPORTANT: suppression hides a warning; it does not make the code safe.
"""

from __future__ import annotations

import io
import re
import tokenize
from collections.abc import Iterable

ALL_RULES = "ALL"
_MARKER = re.compile(r"(?:#|//|/\*)\s*analyzer-ignore\b(?:\s*:\s*(?P<ids>[A-Za-z0-9_,\s]*))?", re.IGNORECASE)

Ignores = dict[int, frozenset[str]]


def ignores_from_comments(comments: Iterable[tuple[int, str, bool]]) -> Ignores:
    """Build the ignore map from ``(line, comment text, stands alone on its line)``."""
    ignores: dict[int, set[str]] = {}
    for line, text, standalone in comments:
        match = _MARKER.match(text.strip())
        if not match:
            continue
        ids = {part.strip().upper() for part in (match.group("ids") or "").split(",") if part.strip()}
        target = line + 1 if standalone else line
        ignores.setdefault(target, set()).update(ids or {ALL_RULES})
    return {line: frozenset(ids) for line, ids in ignores.items()}


def parse_inline_ignores(source: str) -> Ignores:
    """Ignore map of Python source (comments found with ``tokenize``)."""
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, SyntaxError):
        return {}
    return ignores_from_comments(
        (token.start[0], token.string, token.line.strip().startswith("#"))
        for token in tokens if token.type == tokenize.COMMENT
    )


def is_suppressed(rule_id: str, line: int, ignores: Ignores) -> bool:
    ids = ignores.get(line)
    return bool(ids) and (ALL_RULES in ids or rule_id.upper() in ids)
