import httpx
import time
import asyncio

API_BASE = "http://localhost:8088"
HEADERS = {"Authorization": "Bearer dev-token"}

async def test_full_flow():
    # 1. Wait for API to be ready
    print("Waiting for API to initialize...")
    for _ in range(10):
        try:
            r = httpx.get(f"{API_BASE}/health")
            if r.status_code == 200:
                print("API Online.")
                break
        except:
            pass
        await asyncio.sleep(2)

    # 2. Launch Engagement
    domain = "ginandjuice.shop"
    payload = {
        "engagement_id": f"full-test-{int(time.time())}",
        "domains": [domain],
        "approval_required_for": ["rce", "sqli"]
    }
    print(f"Launching engagement for {domain}...")
    r = httpx.post(f"{API_BASE}/engagements", json=payload, headers=HEADERS)
    if r.status_code != 200:
        print(f"Failed to launch: {r.text}")
        return
    
    session_id = r.json()["session_id"]
    print(f"Session Created: {session_id}")

    # 3. Trigger Recon
    print("Deploying Recon Agents...")
    r = httpx.post(f"{API_BASE}/tasks", json={
        "task_type": "full_recon",
        "priority": 10,
        "agent_type": "recon",
        "payload": {"domain": domain},
        "engagement_id": session_id
    }, headers=HEADERS)
    
    print("Mission in progress. Monitor the dashboard at http://localhost:5173")

if __name__ == "__main__":
    asyncio.run(test_full_flow())
