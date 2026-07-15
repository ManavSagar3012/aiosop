import subprocess
import sys
import os

sys.path.insert(0, os.path.join(r"C:\Users\HP\OneDrive\Desktop\burp_mcp\ai-osop", "src"))
from ai_osop.core.config import settings
import time
import urllib.request

ROOT = r"C:\Users\HP\OneDrive\Desktop\burp_mcp\ai-osop"
VENV_PY = os.path.join(ROOT, r".venv\Scripts\python.exe")
GO_DIR = os.path.join(ROOT, r"mcp-servers\go")

def start_detached(cmd):
    creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    try:
        p = subprocess.Popen(
            cmd,
            creationflags=creationflags,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            cwd=ROOT,
        )
        print(f"Started {os.path.basename(cmd[0])} (PID {p.pid})")
        return True
    except Exception as e:
        print(f"FAILED to start {cmd}: {e}")
        return False

def main():
    servers = [
        ([os.path.join(GO_DIR, "recon-mcp.exe")], "recon-mcp", 8082),
        ([os.path.join(GO_DIR, "nuclei-mcp.exe")], "nuclei-mcp", 8084),
        ([os.path.join(ROOT, "shodan-mcp.exe")], "shodan-mcp", 8085),
        ([os.path.join(ROOT, "threat-intel-mcp.exe")], "threat-intel-mcp", 8086),
        ([os.path.join(ROOT, "security-bridge.exe")], "security-bridge", 8087),
        ([VENV_PY, os.path.join("mcp-servers", "python", "browser_mcp.py"), "--port", "8091"], "browser-mcp", 8091),
        ([VENV_PY, os.path.join("mcp-servers", "python", "source_map_mcp.py"), "--port", "8096"], "source-map-mcp", 8096),
        ([VENV_PY, os.path.join("mcp-servers", "python", "turbo_intruder_mcp.py"), "--port", "8098"], "turbo-intruder-mcp", 8098),
        ([VENV_PY, os.path.join("mcp-servers", "python", "payload_mcp_server.py"), "--port", "8083"], "payload-mcp", 8083),
        ([VENV_PY, os.path.join("mcp-servers", "python", "session_memory_mcp.py"), "--port", "8090"], "session-memory-mcp", 8090),
        ([VENV_PY, os.path.join("mcp-servers", "python", "reporting_mcp.py"), "--port", "8092"], "reporting-mcp", 8092),
        ([VENV_PY, os.path.join("mcp-servers", "python", "attack_graph_mcp.py"), "--port", "8093"], "attack-graph-mcp", 8093),
        ([VENV_PY, os.path.join("mcp-servers", "python", "cloud_mcp.py"), "--port", "8097"], "cloud-mcp", 8097),
        ([VENV_PY, os.path.join("mcp-servers", "python", "oast_mcp.py"), "--port", "8099"], "oast-mcp", 8099),
    ]

    started = 0
    for cmd, name, port in servers:
        if start_detached(cmd):
            started += 1

    print(f"\nStarted {started}/{len(servers)} server processes.")
    print("Waiting 8 seconds for ports to bind...")
    time.sleep(8)

    results = {}
    for cmd, name, port in servers:
        try:
            req = urllib.request.Request(f'http://127.0.0.1:{port}/health')
            if settings.api_token:
                req.add_header("Authorization", f"Bearer {settings.api_token}")
            with urllib.request.urlopen(req, timeout=5) as r:
                data = r.read().decode()
                print(f"  {name} ({port}): {data[:80]}")
                results[name] = {"port": port, "status": "up", "health": data[:80]}
        except Exception as e:
            print(f"  {name} ({port}): DOWN ({e})")
            results[name] = {"port": port, "status": "down", "error": str(e)}

    return results

if __name__ == "__main__":
    main()
