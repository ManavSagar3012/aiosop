import httpx
import json

API_BASE = "http://127.0.0.1:8088"
TOKEN = "dev-token"
ENGAGEMENT_ID = "eng-20260604170542-eng-ginandjuice-shop"

payload = {
    "task_type": "burp_scan",
    "priority": 5,
    "agent_type": "vuln_analysis",
    "payload": {"url": "https://ginandjuice.shop/"},
    "engagement_id": ENGAGEMENT_ID
}

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

response = httpx.post(f"{API_BASE}/tasks", json=payload, headers=headers)
print(f"Status: {response.status_code}")
print(f"Response: {response.text}")
