import subprocess
import time
import sys

servers = [
    # Go Servers
    {"name": "nuclei-mcp", "cmd": ["go", "run", "./cmd/nuclei-mcp"], "cwd": "mcp-servers/go"},
    {"name": "recon-mcp", "cmd": ["go", "run", "./cmd/recon-mcp"], "cwd": "mcp-servers/go"},
    {"name": "shodan-mcp", "cmd": ["go", "run", "./cmd/shodan-mcp"], "cwd": "mcp-servers/go"},
    
    # Python Servers
    {"name": "browser-mcp", "cmd": [sys.executable, "browser_mcp.py"], "cwd": "mcp-servers/python"},
    {"name": "payload-mcp", "cmd": [sys.executable, "payload_mcp_server.py"], "cwd": "mcp-servers/python"}
]

processes = []
for s in servers:
    print(f"Starting {s['name']}...")
    p = subprocess.Popen(s['cmd'], cwd=s['cwd'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes.append(p)

print("Started essential MCP servers. Press Ctrl+C to stop.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Stopping servers...")
    for p in processes:
        p.terminate()
