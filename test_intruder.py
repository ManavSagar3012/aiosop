import httpx
import json

def test_intruder():
    # Send an intruder_fuzz task to the orchestrator
    payload = {
        "task_type": "intruder_fuzz",
        "priority": 10,
        "agent_type": "vuln_analysis",
        "payload": {
            "url": "https://ginandjuice.shop/catalog",
            "method": "POST",
            "body": "search=test",
            "payload_set": ["' OR 1=1 --", "admin'--", "<script>alert(1)</script>"],
            "tab_name": "AI-INTRUDER-TEST"
        },
        "engagement_id": "eng-20260606080547-burp-audit-1780733145" # using the last session
    }
    
    r = httpx.post("http://localhost:8088/tasks", json=payload, headers={"Authorization": "Bearer dev-token"})
    print(r.status_code)
    print(r.text)

if __name__ == "__main__":
    test_intruder()
