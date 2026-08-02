"""Structural lint guard against the dead-code / duplicate-method class of bug
that the Sprint 9 extraction introduced (GAP-1-1, GAP-1-2, GAP-1-3).

The original orchestrator.py had:
  * two methods physically defined twice (Python silently keeps the last def,
    so the first becomes unreachable dead code), and
  * ~250 lines of statements after a `return` inside delegating methods.

A duplicate definition is also exactly how a half-applied edit corrupts a file.
These tests fail loudly if either pattern reappears, so a future refactor cannot
silently re-create an unreachable safety branch.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

# The extracted orchestrator package is the surface this guard protects.
ORCH_DIR = Path(__file__).resolve().parents[1] / "src" / "ai_osop" / "orchestrator"

PY_FILES = sorted(p for p in ORCH_DIR.glob("*.py") if p.name != "__init__.py")


def _classes(tree: ast.AST):
    return [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]


def _is_property_accessor(node: ast.AST) -> bool:
    """True for @property getters and @x.setter / @x.deleter accessors, which
    legitimately share a method name and must not count as duplicates."""
    for dec in getattr(node, "decorator_list", []):
        # @property
        if isinstance(dec, ast.Name) and dec.id == "property":
            return True
        # @<name>.setter / @<name>.deleter / @<name>.getter
        if isinstance(dec, ast.Attribute) and dec.attr in {"setter", "deleter", "getter"}:
            return True
    return False


@pytest.mark.parametrize("path", PY_FILES, ids=lambda p: p.name)
def test_no_duplicate_method_definitions(path: Path) -> None:
    """No class may define the same method name twice (the first def would be
    dead code that Python silently discards — GAP-1-1 / GAP-1-2)."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for cls in _classes(tree):
        names: dict[str, int] = {}
        dupes = []
        for node in cls.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # property getter/setter/deleter triples share a name by design.
                if _is_property_accessor(node):
                    continue
                if node.name in names:
                    dupes.append(node.name)
                names[node.name] = node.lineno
        assert not dupes, (
            f"{path.name}: class {cls.name} defines {dupes} more than once; "
            f"the earlier definition is unreachable dead code."
        )


@pytest.mark.parametrize("path", PY_FILES, ids=lambda p: p.name)
def test_no_statements_after_return(path: Path) -> None:
    """No function body may contain a statement after a top-level `return`
    (unreachable code left behind by a half-finished delegation — GAP-1-3)."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            for i, stmt in enumerate(body[:-1]):
                # A bare `return` at the top level of the body followed by more
                # statements in the same block is dead code.
                if isinstance(stmt, ast.Return):
                    nxt = body[i + 1]
                    offenders.append(
                        f"{path.name}:{nxt.lineno} in {node.name}() "
                        f"(statement after return on line {stmt.lineno})"
                    )
    assert not offenders, "Unreachable code after return:\n" + "\n".join(offenders)
