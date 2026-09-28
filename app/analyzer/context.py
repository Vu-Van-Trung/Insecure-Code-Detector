"""Per-file analysis context passed to every rule."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from app.analyzer.parser import ParsedSource
from app.analyzer.utils import collect_imports, resolve_name


@dataclass
class AnalysisContext:
    """Everything a rule may need to know about the file being analyzed.

    Built once per file by the engine; rules must treat it as read-only.
    """

    filename: str
    source_lines: list[str]
    tree: ast.Module
    imports: dict[str, str] = field(default_factory=dict)
    parents: dict[ast.AST, ast.AST] = field(default_factory=dict)
    # Names the file itself defines (functions, classes, assigned variables).
    local_names: set[str] = field(default_factory=set)

    @classmethod
    def from_parsed(cls, parsed: ParsedSource) -> AnalysisContext:
        parents: dict[ast.AST, ast.AST] = {}
        local_names: set[str] = set()
        for node in ast.walk(parsed.tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                local_names.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                local_names.add(node.id)
        return cls(
            filename=parsed.filename,
            source_lines=parsed.lines,
            tree=parsed.tree,
            imports=collect_imports(parsed.tree),
            parents=parents,
            local_names=local_names,
        )

    def get_line(self, lineno: int) -> str:
        """Return the stripped source line (1-based), or an empty string."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def resolve(self, node: ast.AST) -> str | None:
        """Qualified name of a Name/Attribute node with imports resolved."""
        return resolve_name(node, self.imports)

    def call_name(self, call: ast.Call) -> str | None:
        """Qualified name of the function being called, e.g. ``subprocess.run``."""
        return self.resolve(call.func)

    def parent(self, node: ast.AST) -> ast.AST | None:
        return self.parents.get(node)

    def is_shadowed_builtin(self, name: str) -> bool:
        """True if a builtin such as ``eval`` is redefined by the file itself.

        ``def eval(expr): ...`` followed by ``eval(x)`` calls the local function,
        not the builtin, so reporting it would be a false positive.
        """
        return "." not in name and name in self.local_names
