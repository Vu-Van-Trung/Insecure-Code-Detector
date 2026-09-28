"""AST helper functions shared by the analyzer and the rules."""

from __future__ import annotations

import ast


def collect_imports(tree: ast.AST) -> dict[str, str]:
    """Map every locally bound import name to its fully qualified name.

    Examples::

        import os                      -> {"os": "os"}
        import subprocess as sp        -> {"sp": "subprocess"}
        import os.path                 -> {"os": "os"}
        from os import system          -> {"system": "os.system"}
        from os import system as run   -> {"run": "os.system"}

    This lets rules recognise ``sp.run(...)`` as ``subprocess.run(...)``, so an
    alias cannot be used to hide a dangerous call.
    """
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    imports[alias.asname] = alias.name
                else:
                    top_level = alias.name.split(".", 1)[0]
                    imports[top_level] = top_level
        elif isinstance(node, ast.ImportFrom):
            # Relative imports (from . import x) refer to project code, not stdlib.
            if node.level or not node.module:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                imports[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return imports


def get_dotted_name(node: ast.AST) -> str | None:
    """Return the raw dotted name of a Name/Attribute chain, e.g. ``os.path.join``.

    Returns None for anything that is not a pure name chain, such as
    ``get_module().system`` or ``obj[0].run``.
    """
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def resolve_name(node: ast.AST, imports: dict[str, str]) -> str | None:
    """Like :func:`get_dotted_name` but with import aliases resolved."""
    dotted = get_dotted_name(node)
    if dotted is None:
        return None
    head, _, rest = dotted.partition(".")
    qualified_head = imports.get(head, head)
    return f"{qualified_head}.{rest}" if rest else qualified_head


def get_keyword(call: ast.Call, name: str) -> ast.keyword | None:
    """Return the keyword argument ``name`` of a call, if present."""
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword
    return None


def is_constant(node: ast.AST | None, value: object) -> bool:
    """True if node is a literal constant equal (and same type) to ``value``."""
    return (
        isinstance(node, ast.Constant)
        and type(node.value) is type(value)
        and node.value == value
    )


def is_literal_string(node: ast.AST | None) -> bool:
    """True if node is a plain string literal (no interpolation)."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_static_value(node: ast.AST | None) -> bool:
    """True if the value is fully fixed in the source code.

    Static values cannot carry attacker-controlled data, e.g. ``"ls -l"``,
    ``"a" + "b"``, ``f"text"`` (no placeholders) or ``["ls", "-l"]``.
    Anything involving a variable, call or f-string placeholder is dynamic.
    """
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        # Literal parts of an f-string are Constant; placeholders are FormattedValue.
        return all(isinstance(value, ast.Constant) for value in node.values)
    if isinstance(node, ast.BinOp):
        return is_static_value(node.left) and is_static_value(node.right)
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(is_static_value(element) for element in node.elts)
    return False


def get_argument(call: ast.Call, position: int, keyword: str | None = None) -> ast.AST | None:
    """Return a call argument given either positionally or by keyword.

    Returns None if the argument is absent or hidden behind ``*args``.
    """
    positional = call.args[:position + 1]
    if any(isinstance(arg, ast.Starred) for arg in positional):
        return None
    if len(call.args) > position:
        return call.args[position]
    if keyword is not None:
        found = get_keyword(call, keyword)
        if found is not None:
            return found.value
    return None
