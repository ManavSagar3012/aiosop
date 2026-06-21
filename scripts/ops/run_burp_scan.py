import httpx
import time

API_BASE = "http://localhost:8200"
HEADERS = {"Authorization": "Bearer dev-token"}

def run_burp_mission():
    domain = "ginandjuice.shop"
    # 1. Create Engagement
    eng_payload = {
        "engagement_id": f"burp-audit-{int(time.time())}",
        "domains": [domain],
        "approval_required_for": ["rce", "sqli"]
    }
    r = httpx.post(f"{API_BASE}/engagements", json=eng_payload, headers=HEADERS)
    if r.status_code != 200:
        print(f"Error creating engagement: {r.text}")
        return
    
    sid = r.json()["session_id"]
    print(f"Engagement Created: {sid}")

    # 2. Transition to Vuln Discovery
    r = httpx.post(f"{API_BASE}/engagements/{sid}/transition?new_phase=vulnerability_discovery", headers=HEADERS)
    print(f"Transitioned to VULN_DISCOVERY: {r.status_code}")

    # 3. Schedule Burp Scan Task
    task_payload = {
        "task_type": "burp_scan",
        "priority": 10,
        "agent_type": "vuln_analysis",
        "payload": {"url": f"https://{domain}"},
        "engagement_id": sid
    }
    r = httpx.post(f"{API_BASE}/tasks", json=task_payload, headers=HEADERS)
    if r.status_code == 200:
        print(f"Burp Scan Task Dispatched: {r.json()['id']}")
    else:
        print(f"Error dispatching task: {r.text}")

if __name__ == "__main__":
    run_burp_mission()
