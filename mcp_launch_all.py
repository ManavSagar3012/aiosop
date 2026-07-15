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

# Real engines get PATH access to their backing binaries (nuclei shells out).
env = dict(os.environ)
env["PATH"] = os.path.join(os.path.expanduser("~"), "go", "bin") + os.pathsep + env.get("PATH", "")

# Real servers (bind their own hardcoded ports).
real = [
    [os.path.join(GO, "recon-mcp.exe")],          # :8082 real Go recon
    [os.path.join(ROOT, "security-bridge.exe")],  # :8087 real sqlmap/ffuf bridge
    [os.path.join(GO, "nuclei-mcp.exe")],         # :8084 real nuclei engine
    [os.path.join(ROOT, "shodan-mcp.exe")],       # :8085 real Shodan
    [os.path.join(ROOT, "threat-intel-mcp.exe")], # :8086 real Threat Intel
    [PY, os.path.join(ROOT, "mcp-servers", "python", "browser_mcp.py"), "--port", "8091"],
    [PY, os.path.join(ROOT, "mcp-servers", "python", "source_map_mcp.py"), "--port", "8096"],
    [PY, os.path.join(ROOT, "mcp-servers", "python", "turbo_intruder_mcp.py"), "--port", "8098"],
    [PY, os.path.join(ROOT, "mcp-servers", "python", "oast_mcp.py"), "--port", "8099"],
    [PY, os.path.join(ROOT, "mcp-servers", "python", "session_memory_mcp.py"), "--port", "8090"],
    [PY, os.path.join(ROOT, "mcp-servers", "python", "reporting_mcp.py"), "--port", "8092"],
    [PY, os.path.join(ROOT, "mcp-servers", "python", "attack_graph_mcp.py"), "--port", "8093"],
    [PY, os.path.join(ROOT, "mcp-servers", "python", "payload_mcp_server.py"), "--port", "8083"],
    [PY, os.path.join(ROOT, "mcp-servers", "python", "cloud_mcp.py"), "--port", "8097"],
]
# Honest-empty stubs ONLY where no real engine is wired (Burp needs the GUI app).
stubs = {
    8081: "burp-mcp",
}

procs = []
for cmd in real:
    procs.append(subprocess.Popen(cmd, cwd=ROOT, env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
for port, sid in stubs.items():
    procs.append(subprocess.Popen(
        [PY, STUB, "--port", str(port), "--server-id", sid], cwd=ROOT, env=env,
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
