import os
import re
import json
from datetime import datetime

# Scan evidence_vault
print("\n--- EVIDENCE VAULT SCAN ---")
vault_files = []
for root, _, files in os.walk('evidence_vault'):
    for f in files:
        path = os.path.join(root, f)
        stats = os.stat(path)
        vault_files.append({
            "path": path,
            "size": stats.st_size,
            "created": stats.st_ctime
        })
print(json.dumps(vault_files, indent=2))

# Log Analysis
print("\n--- LOG ANALYSIS ---")
patterns = ['Page.goto', 'page.screenshot', 'browser.newContext', 'context.tracing.start', 'context.close']
try:
    with open('api.log', 'r') as f:
        content = f.read()
        for p in patterns:
            count = len(re.findall(p, content))
            print(f"Pattern '{p}' count: {count}")
except FileNotFoundError:
    print("api.log not found")
