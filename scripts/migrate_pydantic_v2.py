#!/usr/bin/env python3
"""Batch-migrate Pydantic V1 patterns to V2 across the ai_osop source tree.

Replaces:
  .dict()  → .model_dump()
  .parse_obj(...) → .model_validate(...)
  hasattr(..., "dict") → hasattr(..., "model_dump")

Run from repo root:
    python scripts/migrate_pydantic_v2.py
"""

import re
from pathlib import Path

SRC = Path("src/ai_osop")
REPLACEMENTS = [
    # Generic: any .dict() call → .model_dump()
    (re.compile(r'\b(\w+)\.dict\(\)'), r'\1.model_dump()'),
    # .parse_obj(...) → .model_validate(...)
    (re.compile(r'\.parse_obj\('), r'.model_validate('),
    # hasattr(..., "dict") → hasattr(..., "model_dump")
    (re.compile(r'hasattr\(([^,]+),\s*"dict"\s*\)'), r'hasattr(\1, "model_dump")'),
]

EXCLUDED_FILES = {"__pycache__", ".venv"}


def migrate_file(path: Path) -> int:
    """Return number of replacements made."""
    original = path.read_text(encoding="utf-8")
    updated = original
    count = 0
    for pattern, replacement in REPLACEMENTS:
        updated, n = pattern.subn(replacement, updated)
        count += n
    if updated != original:
        path.write_text(updated, encoding="utf-8")
    return count


def main() -> None:
    total = 0
    files = 0
    for py_file in SRC.rglob("*.py"):
        if any(part in EXCLUDED_FILES for part in py_file.parts):
            continue
        n = migrate_file(py_file)
        if n:
            print(f"  {py_file}: {n} replacements")
            files += 1
            total += n
    print(f"\nDone: {total} replacements across {files} files")


if __name__ == "__main__":
    main()
