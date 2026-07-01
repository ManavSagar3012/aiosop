#!/usr/bin/env python3
"""AI-OSOP MCP supervisor + external-binary preflight (Sprint 0 / S0.4).

Why this exists
---------------
Two silent-failure modes made the platform "look healthy while under-delivering":

1. Only a subset of MCP tool servers were ever running, so scans dispatched fine
   but quietly covered a fraction of the intended surface.
2. Offensive scans depend on external binaries (nuclei, sqlmap, nmap, ...). When a
   binary is absent, the tool returns an empty result that is indistinguishable
   from "target is clean" — a dangerous false negative for a bug-bounty platform.

This script makes both visible and gives one command to bring the tool layer up:

    python scripts/ops/mcp_supervisor.py preflight   # what tools/templates exist
    python scripts/ops/mcp_supervisor.py status      # which MCP ports are live
    python scripts/ops/mcp_supervisor.py up           # start every down server
    python scripts/ops/mcp_supervisor.py up --only nuclei-mcp recon-mcp oast-mcp
    python scripts/ops/mcp_supervisor.py doctor       # preflight + status in one

It only starts servers that are DOWN (never restarts a live one) and logs each to
.runlogs/<name>.out. It refuses to touch ports known to belong to other services
(the API on 8090, Neo4j on 7687) — those collisions are real: session_memory_mcp.py
binds 8090 and attack_graph_mcp.py binds 7687, so both are intentionally excluded.
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
GO_DIR = REPO_ROOT / "mcp-servers" / "go"
PY_DIR = REPO_ROOT / "mcp-servers" / "python"
RUNLOGS = REPO_ROOT / ".runlogs"

# Ports owned by non-MCP services — never bind an MCP server here.
RESERVED_PORTS = {7687: "Neo4j (bolt)", 8090: "AI-OSOP API"}


@dataclass
class Server:
    name: str
    port: int
    kind: str  # "go-exe" | "python"
    entry: str  # exe filename (go) or script filename (python)
    required_bins: List[str] = field(default_factory=list)
    optional_bins: List[str] = field(default_factory=list)
    needs_nuclei_templates: bool = False

    def launch_cmd(self) -> Optional[List[str]]:
        if self.kind == "go-exe":
            exe = GO_DIR / self.entry
            return [str(exe)] if exe.exists() else None
        if self.kind == "python":
            script = PY_DIR / self.entry
            if not script.exists():
                return None
            return [sys.executable, str(script), "--port", str(self.port)]
        return None


# Curated registry: only REAL, runnable servers (no *_stub.py, no port collisions).
SERVERS: List[Server] = [
    Server("nuclei-mcp", 8084, "go-exe", "nuclei-mcp.exe",
           required_bins=["nuclei"], needs_nuclei_templates=True),
    Server("recon-mcp", 8082, "go-exe", "recon-mcp.exe",
           optional_bins=["amass", "subfinder"]),
    Server("security-bridge", 8087, "go-exe", "security-bridge.exe",
           optional_bins=["sqlmap", "nmap", "ffuf", "masscan", "gobuster", "nikto", "wpscan", "katana"]),
    Server("oast-mcp", 8099, "python", "oast_mcp.py"),
    Server("payload-mcp", 8083, "python", "payload_mcp.py"),
    Server("cloud-mcp", 8097, "python", "cloud_mcp.py", optional_bins=[]),
    Server("source-map-mcp", 8096, "python", "source_map_mcp.py"),
    Server("turbo-intruder-mcp", 8098, "python", "turbo_intruder_mcp.py"),
    Server("threat-intel-mcp", 8086, "python", "threat_intel_mcp.py"),
    Server("browser-mcp", 8089, "python", "browser_mcp.py"),
]


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def _nuclei_templates_present() -> bool:
    # nuclei stores templates under ~/nuclei-templates by default.
    tdir = Path.home() / "nuclei-templates"
    if not tdir.is_dir():
        return False
    # cheap non-recursive existence check for at least one template
    for _ in tdir.rglob("*.yaml"):
        return True
    return False


def preflight() -> int:
    """Report external-binary + template availability. Returns non-zero if a
    REQUIRED binary for any registered server is missing."""
    print("== External binary preflight ==")
    required = {b for s in SERVERS for b in s.required_bins}
    optional = {b for s in SERVERS for b in s.optional_bins} - required
    missing_required = []

    def row(bin_name: str, req: bool) -> None:
        path = shutil.which(bin_name)
        tag = "REQUIRED" if req else "optional"
        if path:
            print(f"  [ok]   {bin_name:<12} ({tag}) -> {path}")
        else:
            mark = "MISSING" if req else "absent"
            print(f"  [{'!!' if req else '--'}]   {bin_name:<12} ({tag}) -> {mark}")
            if req:
                missing_required.append(bin_name)

    for b in sorted(required):
        row(b, True)
    for b in sorted(optional):
        row(b, False)

    if any(s.needs_nuclei_templates for s in SERVERS):
        ok = _nuclei_templates_present()
        print(f"  [{'ok' if ok else '!!'}]   nuclei-templates -> "
              f"{'present (~/nuclei-templates)' if ok else 'MISSING — nuclei will scan 0 templates (silent empty!). Run: nuclei -update-templates'}")
        if not ok:
            missing_required.append("nuclei-templates")

    if missing_required:
        print(f"\n  -> {len(missing_required)} required capability(ies) missing: {', '.join(missing_required)}")
        print("     Scans needing these will produce EMPTY results (false negatives), not errors.")
        return 1
    print("\n  -> all required scan capabilities present.")
    return 0


def status() -> int:
    print("== MCP server status ==")
    down = 0
    for s in SERVERS:
        live = _port_open(s.port)
        runnable = s.launch_cmd() is not None
        state = "UP" if live else ("down" if runnable else "down (no binary/script)")
        print(f"  {s.name:<20} :{s.port:<5} {state}")
        if not live:
            down += 1
    for port, owner in RESERVED_PORTS.items():
        print(f"  (reserved) :{port:<5} {owner} {'UP' if _port_open(port) else 'down'}")
    return down


def up(only: Optional[List[str]] = None) -> int:
    RUNLOGS.mkdir(exist_ok=True)
    targets = [s for s in SERVERS if (only is None or s.name in only)]
    if only:
        unknown = set(only) - {s.name for s in SERVERS}
        for u in sorted(unknown):
            print(f"  [skip] unknown server: {u}")
    started = 0
    for s in targets:
        if s.port in RESERVED_PORTS:
            print(f"  [skip] {s.name}: port {s.port} reserved for {RESERVED_PORTS[s.port]}")
            continue
        if _port_open(s.port):
            print(f"  [live] {s.name} already up on :{s.port}")
            continue
        cmd = s.launch_cmd()
        if cmd is None:
            print(f"  [skip] {s.name}: no runnable entry ({s.entry} missing)")
            continue
        missing = [b for b in s.required_bins if shutil.which(b) is None]
        if missing:
            print(f"  [warn] {s.name}: starting but required bin(s) missing {missing} -> results will be empty")
        logf = RUNLOGS / f"{s.name}.out"
        with open(logf, "ab") as fh:
            subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT,
                             cwd=str(GO_DIR if s.kind == "go-exe" else REPO_ROOT),
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        print(f"  [up]   {s.name} -> :{s.port}  (log: {logf.relative_to(REPO_ROOT)})")
        started += 1
    print(f"\n  -> started {started} server(s).")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="AI-OSOP MCP supervisor + preflight")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("preflight", help="check external binaries + nuclei templates")
    sub.add_parser("status", help="show which MCP ports are live")
    up_p = sub.add_parser("up", help="start every down MCP server")
    up_p.add_argument("--only", nargs="+", help="only start these server names")
    sub.add_parser("doctor", help="preflight + status")
    args = ap.parse_args()

    if args.cmd == "preflight":
        return preflight()
    if args.cmd == "status":
        status()
        return 0
    if args.cmd == "up":
        return up(args.only)
    if args.cmd == "doctor":
        rc = preflight()
        print()
        status()
        return rc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
