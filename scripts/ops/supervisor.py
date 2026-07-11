#!/usr/bin/env python3
"""AI-OSOP process supervisor.

Keeps the MCP servers and the API alive, restarting any that die. Does NOT
touch shared infra (Redis/Neo4j/Postgres run in Docker and are managed there).

Usage:
    python scripts/ops/supervisor.py            # supervise stubs + API
    python scripts/ops/supervisor.py --once     # start anything down, then exit
    python scripts/ops/supervisor.py --no-api   # MCP stubs only

Design notes:
- Liveness is checked by TCP connect to each service port (authoritative), not
  by tracking child PIDs, so it also adopts processes started out-of-band.
- A service is (re)launched only when its port is closed, so running this is
  idempotent and safe to leave running.
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
if not os.path.exists(PY):  # non-Windows / non-venv fallback
    PY = sys.executable
STUB = os.path.join(ROOT, "mcp-servers", "python", "mcp_stub.py")
LOGDIR = os.path.join(ROOT, "logs", "supervisor")

# server_id -> port. Mirrors register_optional_mcp_servers() in api/main.py.
MCP_PORTS = {
    "burp-mcp": 8081,
    "recon-mcp": 8082,
    "payload-mcp": 8083,
    "nuclei-mcp": 8084,
    "shodan-mcp": 8085,
    "threat-intel-mcp": 8086,
    "security-bridge": 8087,
    "browser-mcp": 8091,
    "source-map-mcp": 8096,
    "cloud-mcp": 8097,
    "turbo-intruder-mcp": 8098,
}
API_PORT = 8200
CHECK_INTERVAL = 10  # seconds


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.4) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    finally:
        s.close()


def _logfile(name: str):
    os.makedirs(LOGDIR, exist_ok=True)
    return open(os.path.join(LOGDIR, f"{name}.log"), "a", encoding="utf-8")


def launch_stub(server_id: str, port: int) -> None:
    print(f"[supervisor] launching {server_id} on :{port}", flush=True)
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    subprocess.Popen(
        [PY, STUB, "--port", str(port)],
        stdout=_logfile(server_id), stderr=subprocess.STDOUT, cwd=ROOT,
        env=env,
    )


def launch_api() -> None:
    print(f"[supervisor] launching API on :{API_PORT}", flush=True)
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    subprocess.Popen(
        [PY, "-m", "uvicorn", "ai_osop.api.main:app", "--port", str(API_PORT)],
        stdout=_logfile("api"), stderr=subprocess.STDOUT, cwd=ROOT,
        env=env,
    )


def ensure_all(with_api: bool) -> None:
    for server_id, port in MCP_PORTS.items():
        if not port_open(port):
            launch_stub(server_id, port)
    if with_api and not port_open(API_PORT):
        # Give MCPs a moment so the API's startup self-test finds them.
        time.sleep(2)
        launch_api()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true", help="start anything down, then exit")
    ap.add_argument("--no-api", action="store_true", help="supervise MCP stubs only")
    args = ap.parse_args()
    with_api = not args.no_api

    ensure_all(with_api)
    if args.once:
        return 0

    print("[supervisor] entering supervise loop (Ctrl-C to stop)", flush=True)
    try:
        while True:
            time.sleep(CHECK_INTERVAL)
            ensure_all(with_api)
    except KeyboardInterrupt:
        print("[supervisor] stopped", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
