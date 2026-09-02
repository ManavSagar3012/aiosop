"""Start the golden-path target on port 9199 (for the live autonomous E2E)."""
import socket
import threading
import time
import sys
import requests

sys.path.insert(0, ".")
from golden_path_target import run_golden_path_server  # noqa: E402

port = 9199

# Free the port if a stale server is holding it.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind(("0.0.0.0", port))
    s.close()
    bind_ok = True
except OSError:
    s.close()
    bind_ok = False

if not bind_ok:
    print(f"Port {port} already in use — will reuse it.")
else:
    print(f"Port {port} free.")

server = run_golden_path_server(port)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
time.sleep(0.5)

base = f"http://localhost:{port}"
health = requests.get(f"{base}/health", timeout=5)
login_page = requests.get(f"{base}/login", timeout=5)
sqli = requests.post(
    f"{base}/login", data={"username": "' OR 1=1 --", "password": "x"}, timeout=5
)
print(f"target={base}")
print(f"health={health.status_code}")
print(f"login_page={login_page.status_code}")
print(f"sqli_works={'Welcome' in sqli.text}")
