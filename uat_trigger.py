import httpx
import json
import time

API_BASE = "http://127.0.0.1:8088"
TOKEN = "dev-token"
TARGET_URL = "https://ginandjuice.shop/"
DOMAIN = "ginandjuice.shop"
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

def test_pipeline():
    print(f"--- Starting TC-01: Automated Dual-Agent Launch for {TARGET_URL} ---")
    
    # 1. Create Engagement
    eng_payload = {
        "engagement_id": f"uat-eng-{int(time.time())}",
        "domains": [DOMAIN],
        "approval_required_for": ["rce", "sqli"],
        "roe": {}
    }
    r = httpx.post(f"{API_BASE}/engagements", json=eng_payload, headers=HEADERS)
    if r.status_code != 200:
        print(f"FAILED: Engagement creation returned {r.status_code} - {r.text}")
        return
    session_id = r.json()["session_id"]
    print(f"SUCCESS: Engagement created with ID: {session_id}")

    # 2. Transition Phase
    r = httpx.post(f"{API_BASE}/engagements/{session_id}/transition?new_phase=reconnaissance", headers=HEADERS)
    if r.status_code != 200:
        print(f"FAILED: Phase transition returned {r.status_code} - {r.text}")
        return
    print(f"SUCCESS: Transitioned to reconnaissance phase.")

    # 3. Launch Burp Scan Task
    burp_payload = {
        "task_type": "burp_scan",
        "priority": 10,
        "agent_type": "vuln_analysis",
        "payload": {"url": TARGET_URL},
        "engagement_id": session_id
    }
    r = httpx.post(f"{API_BASE}/tasks", json=burp_payload, headers=HEADERS)
    if r.status_code != 200:
        print(f"FAILED: Burp scan task returned {r.status_code} - {r.text}")
        return
    print(f"SUCCESS: Burp scan task created.")

    # 4. Launch Recon Task
    recon_payload = {
        "task_type": "full_recon",
        "priority": 10,
        "agent_type": "recon",
        "payload": {"domain": DOMAIN},
        "engagement_id": session_id
    }
    r = httpx.post(f"{API_BASE}/tasks", json=recon_payload, headers=HEADERS)
    if r.status_code != 200:
        print(f"FAILED: Recon task returned {r.status_code} - {r.text}")
        return
    print(f"SUCCESS: Recon task created.")

    print("\n--- Pipeline Triggered Successfully ---")
    print("Wait for agents to process...")

if __name__ == "__main__":
    test_pipeline()
