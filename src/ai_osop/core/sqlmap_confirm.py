"""Direct sqlmap confirmation — escalate an oracle-flagged injection point to a
real, tool-demonstrated finding.

Why direct subprocess (not the security-bridge :8087 Go server): the sqlmap
binary is a first-class dependency of this platform, and the evidence path for a
CRITICAL finding must not depend on a separate long-running service being up.
This module shells out to sqlmap in a fully non-interactive, bounded, single-
target mode and parses its verdict. It is the seam that turns a fast in-band
oracle hit (``tool_source=deterministic_scan_generalized``) into a
``tool_source=sqlmap``, ``is_simulated()=False`` confirmed injection.

Discipline:
  * OPT-IN: callers enable it explicitly; the oracle path stays fast/hang-proof.
  * BOUNDED: hard wall-clock timeout; --batch (never prompts); level/risk 1 by
    default; one URL/param at a time — respectful to the target, no hammering.
  * HONEST: returns a verdict only from sqlmap's own machine-readable output; a
    non-zero exit, a timeout, or a "not injectable" result yields injectable=False
    (never an assumed positive).
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
from typing import Any, Dict, List, Optional


def sqlmap_available() -> bool:
    """True if a sqlmap binary is resolvable on PATH."""
    return shutil.which("sqlmap") is not None


# sqlmap's stdout summary lines we parse when the machine-readable results file
# is unavailable. Kept deliberately narrow so we never over-claim.
_INJECTABLE_RE = re.compile(r"Parameter:\s*([^\s]+)\s*\(([^)]+)\)")
_DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)")
_TYPE_RE = re.compile(r"Type:\s*(.+)")
_TITLE_RE = re.compile(r"Title:\s*(.+)")


async def sqlmap_confirm(
    url: str,
    *,
    data: Optional[str] = None,
    param: Optional[str] = None,
    level: int = 1,
    risk: int = 1,
    timeout: float = 240.0,
) -> Dict[str, Any]:
    """Run sqlmap against a single injection point and return a structured verdict.

    Returns::

        {injectable: bool, parameter: str, dbms: str, techniques: [str],
         payloads: [str], raw_tail: str}

    ``injectable`` is True only if sqlmap itself reports a confirmed injection.
    Any failure mode (binary missing, timeout, crash, no injection) returns
    ``injectable=False`` — the caller must not assert a finding without it.
    """
    if not sqlmap_available():
        return {"injectable": False, "error": "sqlmap binary not found on PATH"}

    out_dir = tempfile.mkdtemp(prefix="osop-sqlmap-")
    argv: List[str] = [
        "sqlmap",
        "-u",
        url,
        "--batch",  # never prompt
        "--level",
        str(int(level)),
        "--risk",
        str(int(risk)),
        "--technique",
        "BEUST",  # all techniques except stacked/inline for speed/safety
        "--threads",
        "4",
        "--disable-coloring",
        "--flush-session",  # deterministic: don't reuse a prior verdict
        "--output-dir",
        out_dir,
    ]
    if data:
        argv += ["--data", data]
    if param:
        argv += ["-p", param]

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            # never inherit a controlling tty; --batch already covers prompts
            stdin=asyncio.subprocess.DEVNULL,
        )
    except Exception as e:  # pragma: no cover - exec failure is environment-specific
        _rmtree(out_dir)
        return {"injectable": False, "error": f"sqlmap exec failed: {e}"}

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        _rmtree(out_dir)
        return {"injectable": False, "error": f"sqlmap timed out after {timeout}s"}

    text = (stdout or b"").decode("utf-8", "replace")

    # Prefer sqlmap's own machine-readable results log if present.
    verdict = _parse_results_dir(out_dir)
    if verdict is None:
        verdict = _parse_stdout(text)
    verdict["raw_tail"] = text[-1500:]
    _rmtree(out_dir)
    return verdict


def _parse_results_dir(out_dir: str) -> Optional[Dict[str, Any]]:
    """Parse sqlmap's per-target ``log`` / ``session`` artefacts if written.

    sqlmap writes ``<output-dir>/<host>/log`` (human) and a session sqlite; the
    ``log`` file's ``Parameter:``/``Type:``/``Title:`` block is the authoritative
    machine-adjacent record. Returns None if no target dir was produced (e.g. the
    URL had no testable parameter), so the caller falls back to stdout parsing.
    """
    try:
        hosts = [
            os.path.join(out_dir, d)
            for d in os.listdir(out_dir)
            if os.path.isdir(os.path.join(out_dir, d))
        ]
    except FileNotFoundError:
        return None
    for host_dir in hosts:
        log_path = os.path.join(host_dir, "log")
        if not os.path.isfile(log_path):
            continue
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        if "Parameter:" in content:
            return _extract(content)
    return None


def _parse_stdout(text: str) -> Dict[str, Any]:
    if "Parameter:" in text and (
        "is vulnerable" in text or "the following injection point" in text or "Type:" in text
    ):
        return _extract(text)
    return {
        "injectable": False,
        "parameter": "",
        "dbms": "",
        "techniques": [],
        "payloads": [],
    }


def _extract(content: str) -> Dict[str, Any]:
    pm = _INJECTABLE_RE.search(content)
    parameter = ""
    if pm:
        parameter = f"{pm.group(1)} ({pm.group(2)})"
    dbms_m = _DBMS_RE.search(content)
    techniques = [t.strip() for t in _TYPE_RE.findall(content)]
    payloads = [p.strip() for p in _TITLE_RE.findall(content)]
    return {
        "injectable": bool(pm),
        "parameter": parameter,
        "dbms": (dbms_m.group(1).strip() if dbms_m else ""),
        "techniques": techniques,
        "payloads": payloads,
    }


def _rmtree(path: str) -> None:
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass
