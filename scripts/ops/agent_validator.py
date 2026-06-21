import asyncio
import httpx
import uuid

API_BASE = "http://127.0.0.1:8200"
TOKEN = "123"

async def validate_agents():
    print("PHASE 6 — AGENT VALIDATION\\n")
    async with httpx.AsyncClient(timeout=10.0) as client:
        # 1. Get all agents
        resp = await client.get(f"{API_BASE}/agents?token={TOKEN}")
        agents = resp.json()
        
        # 2. Create a test engagement
        eng_id = f"test-audit-{uuid.uuid4().hex[:6]}"
        eng_payload = {
            "engagement_id": eng_id,
            "domains": ["localhost"],
            "ips": ["127.0.0.1"]
        }
        await client.post(f"{API_BASE}/engagements?token={TOKEN}", json=eng_payload)
        print(f"Created test engagement: {eng_id}")

        for agent in agents:
            aid = agent["agent_id"]
            atype = agent["agent_type"]
            print(f"Testing agent: {aid} ({atype})...")
            
            # 3. Dispatch a dummy task
            # We'll use a task type that doesn't trigger heavy logic or just returns success
            # Each agent supports different tasks. Let's try 'ping' or a simple status check if implemented.
            # If not, we'll try a common one like 'full_recon' for recon-agent.
            
            task_type = "unknown"
            if atype == "recon": task_type = "full_recon"
            elif atype == "vuln_analysis": task_type = "analyze_vulnerability"
            elif atype == "reporting": task_type = "generate_report"
            elif atype == "workflow": task_type = "navigate"
            elif atype == "concurrency": task_type = "test_race_condition"
            
            if task_type == "unknown":
                print(f"  [?] Skipping task test for {aid}: No safe dummy task known.")
                continue
                
            task_payload = {
                "task_type": task_type,
                "agent_type": atype,
                "engagement_id": eng_id,
                "payload": {"url": "http://127.0.0.1:8200/health", "targets": ["127.0.0.1"], "domain": "localhost"}
            }
            
            t_resp = await client.post(f"{API_BASE}/tasks?token={TOKEN}", json=task_payload)
            if t_resp.status_code == 200:
                task_id = t_resp.json()["id"]
                print(f"  [+] Task {task_id} dispatched.")
                
                # 4. Wait for completion (poll for 10s)
                success = False
                for _ in range(10):
                    await asyncio.sleep(1)
                    s_resp = await client.get(f"{API_BASE}/tasks/{task_id}?token={TOKEN}")
                    status = s_resp.json()["status"]
                    if status == "completed":
                        print(f"  [+] Task completed successfully.")
                        success = True
                        break
                    if status == "failed":
                        print(f"  [-] Task failed: {s_resp.json().get('result', {}).get('error', 'unknown error')}")
                        break
                if not success:
                    print(f"  [!] Task timed out or still in {status}.")
            else:
                print(f"  [!] Failed to dispatch task: {t_resp.text}")
            print("")

if __name__ == "__main__":
    asyncio.run(validate_agents())
