"""Run inside Docker container to trace the exact 500 error on POST /engagements."""
import sys
import os
import traceback

# Force env vars for the test
os.environ["OSOP_ENV"] = "development"
os.environ["OSOP_API_TOKEN"] = "dev-token"

sys.path.insert(0, "/app/src")

from fastapi.testclient import TestClient
from ai_osop.api.main import app

client = TestClient(app)

payload = {
    "engagement_id": "eng-trace-001",
    "domains": ["example.com"],
    "roe": {"max_severity": "high"},
    "ips": [],
    "exclusions": [],
    "allowed_techniques": [],
    "restrictions": [],
    "approval_required_for": [],
}

try:
    resp = client.post(
        "/engagements",
        json=payload,
        headers={"Authorization": "Bearer dev-token"},
    )
    print(f"HTTP {resp.status_code}")
    print(f"Body: {resp.text[:2000]}")
except Exception:
    print("EXCEPTION in test client:")
    traceback.print_exc()

# Also check state
from ai_osop.api.deps import state
orch = state.get("orchestrator")
print(f"\nState keys: {list(state.keys())}")
print(f"Orchestrator: {orch is not None}")
