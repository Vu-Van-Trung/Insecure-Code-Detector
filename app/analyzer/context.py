"""Per-file analysis context passed to every rule."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from app.analyzer.parser import ParsedSource
from app.analyzer.taint import TaintConfig, TaintResult, analyze_taint
from app.analyzer.utils import SCOPE_NODES, collect_imports, resolve_name, walk_scope


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
    # Labels (tainted / static / unknown) of every expression; see taint.py.
    taint: TaintResult = field(default_factory=TaintResult)

    @classmethod
    def from_parsed(cls, parsed: ParsedSource, taint_config: TaintConfig | None = None) -> AnalysisContext:
        parents: dict[ast.AST, ast.AST] = {}
        local_names: set[str] = set()
        for node in ast.walk(parsed.tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                local_names.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                local_names.add(node.id)
        imports = collect_imports(parsed.tree)
        taint = analyze_taint(parsed.tree, imports, taint_config) if taint_config else TaintResult()
        return cls(
            filename=parsed.filename,
            source_lines=parsed.lines,
            tree=parsed.tree,
            imports=imports,
            parents=parents,
            local_names=local_names,
            taint=taint,
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

    def enclosing_scope(self, node: ast.AST) -> ast.AST:
        """Nearest enclosing function (or lambda); the module at top level."""
        current = self.parents.get(node)
        while current is not None:
            if isinstance(current, SCOPE_NODES):
                return current
            current = self.parents.get(current)
        return self.tree

    def enclosing_function_name(self, node: ast.AST) -> str | None:
        scope = self.enclosing_scope(node)
        return scope.name if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) else None

    def assignments_before(self, name: str, node: ast.AST) -> list[ast.stmt]:
        """Assignments to variable ``name`` in the same scope, before ``node``.

        Covers ``x = ...``, ``x: T = ...`` and ``x += ...``, sorted by line.
        This is a flow-insensitive approximation: branches (if/else) and loops
        are not distinguished, which is acceptable for a prototype.
        """
        line = getattr(node, "lineno", 0)
        found: list[ast.stmt] = []
        for stmt in walk_scope(self.enclosing_scope(node)):
            if getattr(stmt, "lineno", line) >= line:
                continue
            if isinstance(stmt, ast.Assign):
                if any(isinstance(t, ast.Name) and t.id == name for t in stmt.targets):
                    found.append(stmt)
            elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
                if isinstance(stmt.target, ast.Name) and stmt.target.id == name and stmt.value is not None:
                    found.append(stmt)
        return sorted(found, key=lambda stmt: stmt.lineno)

    def is_shadowed_builtin(self, name: str) -> bool:
        """True if a builtin such as ``eval`` is redefined by the file itself.

        ``def eval(expr): ...`` followed by ``eval(x)`` calls the local function,
        not the builtin, so reporting it would be a false positive.
        """
        return "." not in name and name in self.local_names
