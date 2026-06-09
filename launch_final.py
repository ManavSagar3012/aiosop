import httpx
import time

API_BASE = "http://localhost:8088"
HEADERS = {"Authorization": "Bearer dev-token"}

def launch():
    payload = {
        "engagement_id": f"auto-mission-{int(time.time())}",
        "domains": ["ginandjuice.shop"],
        "approval_required_for": ["rce", "sqli"]
    }
    r = httpx.post(f"{API_BASE}/engagements", json=payload, headers=HEADERS)
    if r.status_code == 200:
        print(f"Mission Launched: {r.json()['session_id']}")
    else:
        print(f"Error: {r.status_code} - {r.text}")

if __name__ == "__main__":
    launch()
