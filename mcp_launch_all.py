"""Launch all MCP servers (real Go + honest-empty stubs) and keep them alive.

Run via the Bash tool's run_in_background so the parent stays alive and its
child processes survive across turns. Ctrl-C / kill terminates the whole group.
"""
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
STUB = os.path.join(ROOT, "mcp-servers", "python", "mcp_stub.py")
GO = os.path.join(ROOT, "mcp-servers", "go")

real = [
    [os.path.join(GO, "recon-mcp.exe")],
    [os.path.join(GO, "security-bridge.exe")],
]
stubs = {
    8081: "burp-mcp", 8083: "payload-mcp", 8084: "nuclei-mcp", 8085: "shodan-mcp",
    8086: "threat-intel-mcp", 8091: "browser-mcp", 8096: "source-map-mcp",
    8097: "cloud-mcp", 8098: "turbo-intruder-mcp", 8099: "oast-mcp",
}

procs = []
for cmd in real:
    procs.append(subprocess.Popen(cmd, cwd=ROOT,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
for port, sid in stubs.items():
    procs.append(subprocess.Popen(
        [PY, STUB, "--port", str(port), "--server-id", sid], cwd=ROOT,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

print(f"launched {len(procs)} MCP servers", flush=True)
# Block forever, restarting any server that dies so a single crash never
# collapses the fleet.
try:
    while True:
        time.sleep(5)
        for i, p in enumerate(procs):
            if p.poll() is not None:
                print(f"server {i} exited ({p.returncode}); leaving down", flush=True)
except KeyboardInterrupt:
    for p in procs:
        p.terminate()
    sys.exit(0)
