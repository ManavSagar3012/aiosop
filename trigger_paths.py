import httpx

API_BASE = "http://localhost:8088"
HEADERS = {"Authorization": "Bearer dev-token"}
SID = "eng-20260606052129-auto-mission-1780723287"

def trigger():
    payload = {
        "task_type": "discover_paths",
        "priority": 10,
        "agent_type": "attack_chain",
        "payload": {"engagement_id": SID},
        "engagement_id": SID
    }
    r = httpx.post(f"{API_BASE}/tasks", json=payload, headers=HEADERS)
    print(f"Status: {r.status_code}")
    print(r.text)

if __name__ == "__main__":
    trigger()
