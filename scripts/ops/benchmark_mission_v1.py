import asyncio
import httpx
import time
import logging
from typing import Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("BenchmarkMission")

API_BASE = "http://localhost:8200"
HEADERS = {"Authorization": "Bearer dev-token"}

async def run_benchmark():
    # 1. Start Engagement
    # Target: PortSwigger Lab - IDOR with data leakage
    # URL will be provided by user or set to a placeholder
    domain = "0a4c000c034b2f88819f727c001c009b.web-security-academy.net"
    target_url = f"https://{domain}/" 
    
    engagement_id = f"benchmark-idor-{int(time.time())}"
    logger.info(f"Initializing Benchmark Mission: {engagement_id}")
    
    payload = {
        "engagement_id": engagement_id,
        "domains": [domain],
        "approval_required_for": ["exploit"]
    }
    
    async with httpx.AsyncClient() as client:
        r = await client.post(f"{API_BASE}/engagements", json=payload, headers=HEADERS)
        if r.status_code != 200:
            logger.error(f"Failed to start engagement: {r.text}")
            return
            
        session_id = r.json()["session_id"]
        logger.info(f"Session started: {session_id}")

        # 2. Autonomous Discovery phase
        # The orchestrator will automatically trigger Recon and Workflow mapping.
        # For the benchmark, we'll wait for the workflow to be mapped.
        logger.info("Awaiting autonomous discovery and workflow mapping...")
        await asyncio.sleep(10) # Simulating wait for agents to register and start

        # 3. Trigger Differential Authorization Test
        # We manually trigger this for the benchmark to prove the engine works.
        # In a full run, the AttackChainAgent would trigger this after finding multiple identities.
        
        logger.info("Triggering Differential Authorization Test...")
        # Note: We need a workflow_id. In a real run we'd query the graph.
        # For this script, we'll poll the graph for a discovered workflow.
        
        workflow_id = None
        for _ in range(10):
            graph_res = await client.get(f"{API_BASE}/engagements/{session_id}/graph", headers=HEADERS)
            nodes = graph_res.json().get("nodes", [])
            workflows = [n for n in nodes if "Workflow" in n.get("labels", [])]
            if workflows:
                workflow_id = workflows[0]["id"]
                break
            await asyncio.sleep(5)
            
        if not workflow_id:
            logger.warning("No workflow discovered automatically. Seeding manual workflow for benchmark...")
            
            # Fallback: Seed a known IDOR target workflow directly into the graph
            # This ensures the test proceeds even if discovery is slow
            workflow_id = f"wf-{int(time.time())}"
            endpoint_id = f"ep-{int(time.time())}"
            
            # Use the graph API directly to seed
            seed_cypher = """
            MERGE (a:Asset {engagement_id: $sid, type: 'domain', id: 'asset-' + $sid})
            MERGE (e:Endpoint {id: $eid, engagement_id: $sid, url: $url, asset_id: a.id})
            MERGE (w:Workflow {id: $wid, engagement_id: $sid, name: 'Profile Access Journey'})
            MERGE (s1:WorkflowStep {id: $wid + '-s1', workflow_id: $wid, endpoint_id: e.id, order: 0, url: $url, engagement_id: $sid})
            MERGE (w)-[:HAS_STEP]->(s1)
            """
            
            from ai_osop.memory.graph_memory import GraphMemory
            graph_mem = GraphMemory()
            await graph_mem.connect()
            async with graph_mem._driver.session() as session:
                await session.run(seed_cypher, {"sid": session_id, "wid": workflow_id, "eid": endpoint_id, "url": f"{target_url}my-account"})
            await graph_mem.close()

            logger.info(f"Seeded Workflow: {workflow_id}")

        if workflow_id:
            logger.info(f"Found Workflow: {workflow_id}. Running Diff Auth Replay...")
            replay_payload = {
                "workflow_id": workflow_id,
                "target_user_label": "user_b"
            }
            
            # This is a task for the PlaywrightAgent (WorkflowAgent)
            task_payload = {
                "task_type": "replay_for_diff_auth",
                "agent_type": "workflow",
                "payload": replay_payload,
                "engagement_id": session_id
            }
            
            await client.post(f"{API_BASE}/tasks", json=task_payload, headers=HEADERS)
            logger.info("Differential testing task queued. Check dashboard for CRITICAL ANOMALY.")

if __name__ == "__main__":
    asyncio.run(run_benchmark())
