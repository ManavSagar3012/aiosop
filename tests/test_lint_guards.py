"""Repo-wide structural lint guards (OSOP-P1-08).

Enforces, without requiring ruff to be installed, that no bare `except:` re-enters the
codebase. A bare except swallows KeyboardInterrupt/SystemExit and every programming error,
which is how store outages and partial failures were silently hidden (the audit's
"browser-outage hang" / "ghost workflow" class of bug).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
PY_FILES = sorted(SRC.rglob("*.py"))


def test_repo_has_source():
    assert PY_FILES, "no source files discovered — guard would be vacuous"


@pytest.mark.parametrize("path", PY_FILES, ids=lambda p: str(p.relative_to(SRC)))
def test_no_bare_except(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    bare = [
        h.lineno
        for h in ast.walk(tree)
        if isinstance(h, ast.ExceptHandler) and h.type is None
    ]
    assert not bare, (
        f"{path.relative_to(SRC)} has bare `except:` at line(s) {bare}; "
        f"catch a specific exception (or `except Exception`) and log it."
    )
