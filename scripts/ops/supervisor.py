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

from datetime import datetime

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
    "oast-mcp": 8099,
}
API_PORT = 8200
CHECK_INTERVAL = 10  # seconds

STALE_SESSION_TTL_HOURS = 1  # sessions older than this are flushed on preflight

# Single-instance guard: PID file so two supervisors can't run simultaneously.
# If the PID file exists AND the referenced process is alive, refuse to start.
PID_FILE = os.path.join(LOGDIR, "supervisor.pid")


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


GOROOT = os.path.join(ROOT, "mcp-servers", "go")
RECON_MCP_BIN = os.path.join(GOROOT, "recon-mcp.exe")
NUCLEI_MCP_BIN = os.path.join(GOROOT, "nuclei-mcp.exe")
SHODAN_MCP_BIN = os.path.join(GOROOT, "shodan-mcp.exe")
SECURITY_BRIDGE_BIN = os.path.join(GOROOT, "security-bridge.exe")


def _launch_python_stub(server_id: str, port: int) -> None:
    print(f"[supervisor] launching {server_id} on :{port}", flush=True)
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    subprocess.Popen(
        [PY, STUB, "--port", str(port), "--server-id", server_id],
        stdout=_logfile(server_id), stderr=subprocess.STDOUT, cwd=ROOT,
        env=env,
    )


def _launch_go_server(server_id: str, port: int, binary: str) -> None:
    """Launch a compiled Go MCP server binary."""
    print(f"[supervisor] launching {server_id} ({binary}) on :{port}", flush=True)
    env = dict(os.environ)
    subprocess.Popen(
        [binary],
        stdout=_logfile(server_id), stderr=subprocess.STDOUT, cwd=ROOT,
        env=env,
    )


# Map of server_id -> (launcher_func, arg). Servers with a Go binary use
# _launch_go_server; everything else uses the Python stub.
_MCP_LAUNCHERS: dict[str, tuple] = {
    server_id: (_launch_go_server, binary)
    for server_id, binary in {
        "recon-mcp": RECON_MCP_BIN,
        # Real Go MCP servers replacing the Python mock stubs. Only wired when a
        # compiled binary exists (os.path.exists guard below) — a missing binary
        # falls back to _launch_python_stub rather than crashing the supervisor.
        # payload-mcp is intentionally excluded: its Go source is still a mock
        # ("Mock payload generation tool"). threat-intel has real source but no
        # built binary yet, so it also falls through to the Python stub.
        "nuclei-mcp": NUCLEI_MCP_BIN,
        "shodan-mcp": SHODAN_MCP_BIN,
        "security-bridge": SECURITY_BRIDGE_BIN,
    }.items()
    if os.path.exists(binary)
}


def _redis_cli(args: list[str]) -> list[str]:
    """Run a redis-cli command and return stdout lines."""
    try:
        result = subprocess.run(
            ["docker", "exec", "ai-osop-redis", "redis-cli"] + args,
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip().split("\n") if result.stdout else []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _flush_stale_sessions(max_age_hours: int = STALE_SESSION_TTL_HOURS) -> int:
    """Remove engagement sessions from Redis that are older than max_age_hours.

    Old sessions accumulate across benchmark runs (24h default TTL in Redis).
    On API restart the RecoveryService restores every one, creating hundreds of
    stale tasks that flood the scheduler, saturate the 9 scanner agent slots,
    and produce an endless no_agent_found cascade. Flushing sessions older than
    a reasonable window (default 1h — plenty for a single engagement run) lets
    the API start cleanly without losing work-in-progress.

    Returns the number of sessions flushed.
    """
    import json as _json

    flushed = 0
    keys = _redis_cli(["KEYS", "session:*"])
    for key in keys:
        if not key.strip():
            continue
        raw = _redis_cli(["GET", key.strip()])
        if not raw or not raw[0].strip():
            continue
        try:
            data = _json.loads(raw[0].strip())
        except _json.JSONDecodeError:
            _redis_cli(["DEL", key.strip()])
            flushed += 1
            continue
        created = data.get("created_at") or data.get("updated_at")
        if not created:
            _redis_cli(["DEL", key.strip()])
            flushed += 1
            continue
        try:
            ts = datetime.fromisoformat(created)
        except (ValueError, TypeError):
            _redis_cli(["DEL", key.strip()])
            flushed += 1
            continue
        age = (datetime.utcnow() - ts).total_seconds() / 3600
        if age > max_age_hours:
            _redis_cli(["DEL", key.strip()])
            flushed += 1
    if flushed:
        print(f"[supervisor] flushed {flushed} stale session(s) >{max_age_hours}h old", flush=True)
    return flushed


def wait_for_mcps(timeout: float = 15.0) -> bool:
    """Wait until all MCP ports are open or timeout expires.

    Returns True if all MCPs are up, False if any timed out. Sleeps 0.5s
    between polls so the total wait is at most ``timeout`` seconds.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        all_up = all(port_open(p) for p in MCP_PORTS.values())
        if all_up:
            return True
        time.sleep(0.5)
    down = [sid for sid, p in MCP_PORTS.items() if not port_open(p)]
    print(f"[supervisor] WARNING: MCP ports still down after {timeout}s: {down}", flush=True)
    return False


def launch_api() -> None:
    # Preflight: wait for MCP servers before launching the API.
    # If the API starts before MCPs, its circuit breakers trip on failed
    # connection attempts, causing "no agent found" errors on every task.
    print(f"[supervisor] preflight: waiting for MCP servers ...", flush=True)
    wait_for_mcps(timeout=15.0)

    # Preflight: flush stale engagement sessions that would otherwise be
    # recovered on startup, flooding the scheduler with old tasks.
    _flush_stale_sessions(max_age_hours=STALE_SESSION_TTL_HOURS)

    print(f"[supervisor] launching API on :{API_PORT}", flush=True)
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    subprocess.Popen(
        [PY, "-m", "uvicorn", "ai_osop.api.main:app", "--port", str(API_PORT)],
        stdout=_logfile("api"), stderr=subprocess.STDOUT, cwd=ROOT,
        env=env,
    )


# Tracks the last time the API was launched to avoid spawning a second
# uvicorn before the first one has bound its port (Errno 10048).
_last_api_launch: float = 0.0
_API_COOLDOWN: float = 30.0  # seconds before we try relaunching again


def ensure_all(with_api: bool) -> None:
    global _last_api_launch

    for server_id, port in MCP_PORTS.items():
        if not port_open(port):
            launcher, arg = _MCP_LAUNCHERS.get(server_id, (_launch_python_stub, STUB))
            if launcher == _launch_go_server:
                launcher(server_id, port, arg)
            else:
                launcher(server_id, port)
    if with_api and not port_open(API_PORT):
        now = time.monotonic()
        if now - _last_api_launch < _API_COOLDOWN:
            return  # still within cooldown window, don't spawn duplicate
        _last_api_launch = now
        launch_api()


def _check_pidfile() -> None:
    """Exit with an error if another supervisor process is already running.

    Reads the PID file, checks if the referenced process exists, and refuses to
    start if it does. Stale PID files (no process) are cleaned up automatically.
    """
    if not os.path.exists(PID_FILE):
        return
    try:
        with open(PID_FILE) as f:
            pid_str = f.read().strip()
        if pid_str:
            pid = int(pid_str)
            # Sending signal 0 tests whether the process exists.
            os.kill(pid, 0)
            print(
                f"[supervisor] ERROR: supervisor already running (PID {pid}). "
                f"Delete {PID_FILE} to force.",
                flush=True,
            )
            raise SystemExit(1)
    except (OSError, ValueError):
        # Process not found or invalid PID -> stale file, clean up.
        try:
            os.remove(PID_FILE)
        except OSError:
            pass


def _write_pidfile() -> None:
    """Write current PID to the PID file."""
    os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))


def _remove_pidfile() -> None:
    """Remove the PID file on clean exit."""
    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    except OSError:
        pass


def main() -> int:
    _check_pidfile()
    _write_pidfile()

    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true", help="start anything down, then exit")
    ap.add_argument("--no-api", action="store_true", help="supervise MCP stubs only")
    args = ap.parse_args()
    with_api = not args.no_api

    ensure_all(with_api)
    if args.once:
        _remove_pidfile()
        return 0

    print("[supervisor] entering supervise loop (Ctrl-C to stop)", flush=True)
    try:
        while True:
            time.sleep(CHECK_INTERVAL)
            ensure_all(with_api)
    except KeyboardInterrupt:
        print("[supervisor] stopped", flush=True)
    finally:
        _remove_pidfile()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
