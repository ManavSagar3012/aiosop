#!/usr/bin/env python3
"""
P1 Multiplier Validation: Live Benchmark Against ginandjuice.shop

Tests whether the enhanced parameter extraction + payload generation
actually discovers the ground-truth vulnerabilities on the target.

Ground Truth (6 vulnerabilities):
1. SQLi on /catalog/product with productId parameter
2. SQLi on /catalog/product/stock with productId parameter  
3. XSS on /catalog with searchTerm parameter
4. XSS on /blog with search parameter
5. IDOR on /my-account with id parameter
6. JWT on /login with token parameter
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ai_osop.orchestrator.orchestrator import AIOSOP
from src.ai_osop.core.config import SessionConfig
from src.ai_osop.core.models import Task, AgentType, Engagement


async def run_benchmark_engagement():
    """Run a complete engagement against ginandjuice.shop and measure findings."""
    
    target = "https://ginandjuice.shop"
    engagement_name = f"p1-multiplier-test-{datetime.utcnow().isoformat()}"
    
    print(f"[BENCHMARK] Starting P1 Multiplier validation")
    print(f"[BENCHMARK] Target: {target}")
    print(f"[BENCHMARK] Engagement: {engagement_name}")
    print(f"[BENCHMARK] Testing: Enhanced parameter extraction + payload generation")
    print("-" * 80)
    
    # Initialize orchestrator
    config = SessionConfig(target=target, depth=3)
    orch = AIOSOP(config=config)
    
    try:
        # Start engagement
        engagement = await orch.create_engagement(
            engagement_name=engagement_name,
            target=target,
            description="P1 Multiplier validation with enhanced recon"
        )
        engagement_id = engagement.id
        print(f"[ENGAGEMENT] Created: {engagement_id}")
        
        # Phase 1: Recon (P1.1 + P1.2 with enhanced discovery)
        print(f"\n[PHASE 1.1] Starting URL discovery...")
        recon_task = Task(
            type="url_discovery",
            agent_type=AgentType.RECON,
            payload={"url": target, "depth": 3},
            engagement_id=engagement_id
        )
        await orch.task_scheduler.schedule_task(recon_task)
        
        # Wait for recon to complete
        while recon_task.status not in ("completed", "failed"):
            await asyncio.sleep(2)
        
        print(f"[PHASE 1.1] Status: {recon_task.status}")
        if recon_task.result:
            endpoints_found = recon_task.result.get("endpoints_found", 0)
            print(f"[PHASE 1.1] Endpoints discovered: {endpoints_found}")
        
        # Phase 1.2: Content discovery with form extraction
        print(f"\n[PHASE 1.2] Starting enhanced content discovery...")
        content_task = Task(
            type="content_discovery",
            agent_type=AgentType.RECON,
            payload={"url": target, "depth": 3},
            engagement_id=engagement_id
        )
        await orch.task_scheduler.schedule_task(content_task)
        
        while content_task.status not in ("completed", "failed"):
            await asyncio.sleep(2)
        
        print(f"[PHASE 1.2] Status: {content_task.status}")
        if content_task.result:
            param_intel = content_task.result.get("parameter_intelligence", {})
            print(f"[PHASE 1.2] Parameter intelligence: {param_intel}")
        
        # Phase 2: Vulnerability Analysis
        print(f"\n[PHASE 2] Analyzing endpoints for vulnerabilities...")
        
        # Get all discovered endpoints
        endpoints = await orch.graph_memory.get_endpoints_by_engagement(engagement_id)
        print(f"[PHASE 2] Total endpoints in graph: {len(endpoints)}")
        
        # Show endpoint parameters
        critical_endpoints = {}
        for ep in endpoints[:20]:  # Show top 20
            if any(kw in ep.path.lower() for kw in ["product", "catalog", "account", "blog", "login"]):
                critical_endpoints[ep.url] = {
                    "path": ep.path,
                    "parameters": ep.parameters,
                    "tags": ep.metadata.get("tags", [])
                }
        
        if critical_endpoints:
            print(f"\n[PHASE 2] Critical endpoints with enhanced parameters:")
            for url, info in list(critical_endpoints.items())[:10]:
                print(f"  - {url}")
                print(f"    Parameters: {info['parameters']}")
                print(f"    Tags: {info['tags']}")
        
        # Phase 3: Vulnerability Detection
        print(f"\n[PHASE 3] Scanning for vulnerabilities...")
        
        scan_task = Task(
            type="vulnerability_scan",
            agent_type=AgentType.VULN_ANALYSIS,
            payload={"engagement_id": engagement_id, "endpoints": endpoints[:50]},
            engagement_id=engagement_id
        )
        await orch.task_scheduler.schedule_task(scan_task)
        
        while scan_task.status not in ("completed", "failed"):
            await asyncio.sleep(2)
        
        print(f"[PHASE 3] Status: {scan_task.status}")
        if scan_task.result:
            vulns_found = scan_task.result.get("vulnerabilities_found", 0)
            print(f"[PHASE 3] Vulnerabilities identified: {vulns_found}")
        
        # Retrieve found vulnerabilities
        vulns = await orch.graph_memory.get_vulnerabilities_by_engagement(engagement_id)
        print(f"[PHASE 3] Total vulnerabilities: {len(vulns)}")
        
        # Analyze against ground truth
        print(f"\n" + "=" * 80)
        print(f"[RESULTS] Ground-Truth Validation")
        print(f"=" * 80)
        
        ground_truth = {
            "productId": ["SQLi", "/catalog/product", "/catalog/product/stock"],
            "searchTerm": ["XSS", "/catalog"],
            "search": ["XSS", "/blog"],
            "id": ["IDOR", "/my-account"],
            "token": ["JWT", "/login"],
        }
        
        found_params = set()
        found_vulns = {}
        
        for vuln in vulns:
            endpoint_url = vuln.endpoint_url if hasattr(vuln, 'endpoint_url') else ""
            vuln_type = vuln.classification if hasattr(vuln, 'classification') else vuln.type
            
            for param in vuln.parameters if hasattr(vuln, 'parameters') else []:
                found_params.add(param)
                if param not in found_vulns:
                    found_vulns[param] = []
                found_vulns[param].append({
                    "type": vuln_type,
                    "url": endpoint_url,
                    "severity": vuln.severity if hasattr(vuln, 'severity') else "medium"
                })
        
        # Score: how many ground-truth params did we find?
        matches = 0
        for gt_param in ground_truth.keys():
            if gt_param in found_params:
                matches += 1
                print(f"✓ FOUND: {gt_param}")
                for finding in found_vulns.get(gt_param, []):
                    print(f"    - {finding['type']} on {finding['url']} (severity: {finding['severity']})")
            else:
                print(f"✗ MISSED: {gt_param}")
        
        recall = (matches / len(ground_truth)) * 100
        print(f"\n[FINAL SCORE] Recall: {recall:.1f}% ({matches}/{len(ground_truth)} parameters)")
        
        if recall >= 80:
            print(f"[SUCCESS] P1 Multiplier fixes validated! Recall >= 80%")
            return True
        else:
            print(f"[WARNING] Recall < 80%. Review parameter extraction logic.")
            return False
            
    except Exception as e:
        print(f"[ERROR] Engagement failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Cleanup
        if orch:
            await orch.shutdown()


if __name__ == "__main__":
    try:
        success = asyncio.run(run_benchmark_engagement())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n[INTERRUPT] Benchmark cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"[FATAL] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
