import os
import sys
import json
import time
import yaml
import httpx
import asyncio
from pathlib import Path
from typing import Dict, Any, List

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

API = "http://127.0.0.1:8200"
TOKEN = "dev-token"
H = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

async def run_benchmark(target: str, ground_truth_file: str) -> Dict[str, Any]:
    with open(ground_truth_file, "r") as f:
        gt = yaml.safe_load(f)
        
    print(f"\n[BENCHMARK] Target: {target} | Loaded {len(gt)} ground truth targets")
    
    # 1. Trigger fresh engagement
    session_id = f"bench-{int(time.time())}"
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{API}/engagements",
            headers=H,
            json={
                "engagement_id": session_id,
                "domains": [target.replace("http://", "").replace("https://", "").split(":")[0]],
                "allowed_techniques": ["recon", "vuln_scan", "browser_navigation"]
            },
            timeout=30
        )
        if r.status_code != 200:
            raise Exception(f"Failed to create engagement: {r.text}")
            
        eng_data = r.json()
        print(f"  Engagement created: {session_id}")
        
        # Transition to reconnaissance
        r = await client.post(
            f"{API}/engagements/{session_id}/transition?new_phase=reconnaissance",
            headers=H,
            timeout=30
        )
        if r.status_code != 200:
            raise Exception(f"Failed to transition to recon: {r.text}")
            
        print("  Active crawl initiated...")
        
        # Poll tasks until recon and vuln scan are completed
        t0 = time.time()
        timeout = 300 # 5 minutes hard ceiling
        completed_tasks = {}
        
        while time.time() - t0 < timeout:
            r = await client.get(f"{API}/tasks", headers=H, params={"engagement_id": session_id}, timeout=15)
            if r.status_code == 200:
                tasks = r.json()
                active = [t for t in tasks if t["status"] in ("pending", "running")]
                for t in tasks:
                    tid = t["id"]
                    tstatus = t["status"]
                    if tid not in completed_tasks or completed_tasks[tid] != tstatus:
                        completed_tasks[tid] = tstatus
                        print(f"    Task {tid} ({t['type']}): {tstatus}")
                if len(tasks) > 1 and len(active) == 0:
                    print("  All tasks completed execution.")
                    break
            await asyncio.sleep(5)
            
        # Get outcomes/vulnerabilities
        r = await client.get(f"{API}/engagements/{session_id}/findings", headers=H, timeout=15)
        findings = r.json() if r.status_code == 200 else []
        
        # Calculate scorecard metrics
        tp = 0
        fn = 0
        fp = len(findings) # Start with FP equal to findings, then decrement for true positives
        
        matched_findings = []
        for entry in gt:
            matched = False
            for f in findings:
                if entry["endpoint"] in f.get("url", "") and entry["type"].lower() in f.get("vuln_type", "").lower():
                    matched = True
                    matched_findings.append(f)
                    tp += 1
                    fp -= 1
                    break
            if not matched:
                fn += 1
                
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        
        # Simple coverage check based on crawled endpoints vs expected
        r = await client.get(f"{API}/engagements/{session_id}/graph", headers=H, timeout=15)
        graph = r.json() if r.status_code == 200 else {"nodes": [], "edges": []}
        endpoints = [n for n in graph.get("nodes", []) if "Endpoint" in n.get("labels", [])]
        
        scorecard = {
            "session_id": session_id,
            "target": target,
            "metrics": {
                "precision": round(precision, 2),
                "recall": round(recall, 2),
                "false_positives": fp,
                "true_positives": tp,
                "false_negatives": fn,
                "endpoints_discovered": len(endpoints),
            },
            "findings": findings
        }
        
        print("\n================ BENCHMARK SCORECARD ================")
        print(f"  Precision: {scorecard['metrics']['precision']}")
        print(f"  Recall:    {scorecard['metrics']['recall']}")
        print(f"  TP:        {scorecard['metrics']['true_positives']} | FP: {scorecard['metrics']['false_positives']} | FN: {scorecard['metrics']['false_negatives']}")
        print(f"  Endpoints: {scorecard['metrics']['endpoints_discovered']}")
        print("=====================================================")
        
        return scorecard

if __name__ == "__main__":
    target_host = "http://localhost:3000"
    gt_file = "benchmarks/ground_truth/juice_shop.yaml"
    asyncio.run(run_benchmark(target_host, gt_file))
