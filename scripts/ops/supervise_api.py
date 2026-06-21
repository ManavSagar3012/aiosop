#!/usr/bin/env python
"""
AI-OSOP API supervisor (AIOSOP-AUDIT-2026-06-16).

Eliminates two unattended-operation risks found in chaos testing:
  1. No auto-restart on API death  -> this process monitors the worker and
     restarts it with capped exponential backoff.
  2. Duplicate uvicorn instances    -> a single-instance guard refuses to start
     if :8200 is already bound, so you never get two workers fighting for state.

Usage:
    python supervise_api.py                 # host 127.0.0.1 port 8200
    OSOP_API_HOST=0.0.0.0 OSOP_API_PORT=8200 python supervise_api.py

Stop with Ctrl-C (the child is terminated cleanly).
"""
import os
import socket
import subprocess
import sys
import time
from datetime import datetime

HOST = os.environ.get("OSOP_API_HOST", "127.0.0.1")
PORT = int(os.environ.get("OSOP_API_PORT", "8200"))
MAX_BACKOFF = 30          # seconds
RESTART_WINDOW = 10       # a run shorter than this counts as a crash-loop
LOG = "api.supervisor.log"


def log(msg: str) -> None:
    line = f"[{datetime.utcnow().isoformat()}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex((host, port)) == 0


def main() -> int:
    # --- single-instance guard ---
    if port_in_use(HOST, PORT):
        log(f"REFUSING TO START: {HOST}:{PORT} already in use (API already running). "
            f"Stop the existing instance first.")
        return 3

    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(os.getcwd(), "src") + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [sys.executable, "-m", "uvicorn", "ai_osop.api.main:app",
           "--host", HOST, "--port", str(PORT)]

    backoff = 1
    log(f"Supervisor starting. cmd={' '.join(cmd)}")
    try:
        while True:
            started = time.time()
            log(f"Launching API worker...")
            proc = subprocess.Popen(cmd, env=env)
            rc = proc.wait()
            ran_for = time.time() - started
            log(f"API worker exited rc={rc} after {ran_for:.0f}s")

            if ran_for >= RESTART_WINDOW:
                backoff = 1  # healthy run -> reset backoff
            else:
                backoff = min(backoff * 2, MAX_BACKOFF)
                log(f"Crash-loop guard: backing off {backoff}s before restart")
            time.sleep(backoff)
    except KeyboardInterrupt:
        log("Supervisor received Ctrl-C; terminating worker.")
        try:
            proc.terminate()
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
