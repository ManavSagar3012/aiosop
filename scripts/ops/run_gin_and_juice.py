import asyncio
import sys
import time
from datetime import datetime, timedelta
import httpx
from jose import jwt

sys.path.insert(0, "src")
from ai_osop.core.config import settings

API_BASE = "http://127.0.0.1:8200"


async def main():
    print("=" * 60)
    print("AI-OSOP E2E VERIFICATION RUNNER - TARGET: GINANDJUICE.SHOP")
    print("=" * 60)

    # 1. Generate Valid JWT
    secret = settings.jwt_secret or "dev-jwt-secret"
    token = jwt.encode(
        {
            "sub": "verification-lead",
            "role": "senior_operator",
            "exp": datetime.utcnow() + timedelta(hours=2),
        },
        secret,
        algorithm="HS256",
    )
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Create Unique Engagement ID
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    engagement_id = f"e2e-gj-{stamp}"
    print(f"Creating engagement: {engagement_id}")

    payload = {
        "engagement_id": engagement_id,
        "domains": ["ginandjuice.shop"],
        "allowed_techniques": ["passive", "active"],
        "authorization_ref": "E2E-GINANDJUICE-VERIFY",
        "roe": {"note": "E2E verification run against Gin and Juice Shop"},
    }

    async with httpx.AsyncClient(timeout=30) as client:
        # Create engagement
        r = await client.post(f"{API_BASE}/engagements", json=payload, headers=headers)
        if r.status_code != 200:
            print(f"FAIL: Failed to create engagement: {r.status_code} - {r.text}")
            return 1

        engagement_data = r.json()
        session_id = engagement_data["session_id"]
        print(
            f"SUCCESS: Engagement created. Session ID: {session_id} | Phase: {engagement_data.get('phase')}"
        )
        print("Polling status and task execution (will run for 600 seconds or until completed)...")
        print("-" * 60)

        start_time = time.time()
        completed = False
        duration = 600
        status = "unknown"

        while time.time() - start_time < duration:
            # Poll engagement status
            r_eng = await client.get(f"{API_BASE}/engagements/{session_id}", headers=headers)
            if r_eng.status_code == 200:
                eng = r_eng.json()
                phase = eng.get("phase")
                status = eng.get("status", "unknown")
                print(f"[{datetime.utcnow().isoformat()}] Phase: {phase} | Status: {status}")
            else:
                print(f"Error polling engagement: {r_eng.status_code}")

            # Poll audit-log events to see task history
            r_audit = await client.get(
                f"{API_BASE}/engagements/{session_id}/audit-log", headers=headers
            )
            if r_audit.status_code == 200:
                events = r_audit.json()
                scheduled = [e for e in events if e.get("event_type") == "task_scheduled"]
                completed_tasks = [e for e in events if e.get("event_type") == "task_completed"]
                failed_tasks = [e for e in events if e.get("event_type") == "task_failed"]

                print(
                    f"Tasks -> Scheduled: {len(scheduled)} | Completed: {len(completed_tasks)} | Failed: {len(failed_tasks)}"
                )
                for e in events:
                    if e.get("event_type") in (
                        "task_scheduled",
                        "task_completed",
                        "task_failed",
                        "auto_map_dispatch",
                    ):
                        action = e.get("action") or {}
                        res = e.get("result") or {}
                        t_id = action.get("task_id") or action.get("created_task_id")
                        t_type = action.get("task_type") or e.get("action_type")
                        print(
                            f"  - Event {e.get('event_type')} | Task: {t_id} ({t_type}) | Result: {res.get('status') or res.get('error') or ''}"
                        )
            else:
                print(f"Error polling audit log: {r_audit.status_code}")

            # Check findings/vulnerabilities
            r_vulns = await client.get(
                f"{API_BASE}/engagements/{session_id}/findings", headers=headers
            )
            if r_vulns.status_code == 200:
                eng_vulns = r_vulns.json()
                print(f"Vulnerabilities Found: {len(eng_vulns)}")
                for v in eng_vulns:
                    print(
                        f"  [VULN] {v.get('title')} ({v.get('severity')}) on {v.get('endpoint_id')}"
                    )

            # Stop if engagement status is completed
            if status == "completed":
                print("Engagement finished successfully!")
                completed = True
                break

            await asyncio.sleep(10)
        # Print final summary
        print("=" * 60)
        print("E2E RUN COMPLETED OR TIMED OUT - RUNNING GROUND TRUTH AUDIT")
        print("=" * 60)

        # 1. Fetch final findings
        findings = []
        r_vulns = await client.get(f"{API_BASE}/engagements/{session_id}/findings", headers=headers)
        if r_vulns.status_code == 200:
            findings = r_vulns.json()
            print(f"Final findings count: {len(findings)}")
            for v in findings:
                print(
                    f"- {v.get('title')} | Severity: {v.get('severity')} | Tool: {v.get('tool_source')}"
                )

        # 2. Fetch skipped scans and endpoints from Neo4j (via direct GraphMemory query)
        from ai_osop.memory.graph_memory import GraphMemory

        g = GraphMemory()
        await g.connect()
        skipped = await g.run_read_query(
            "MATCH (s:SkippedScan {engagement_id: $sid}) "
            "RETURN s.vuln_class as vuln_class, s.endpoint_url as endpoint_url, s.reason as reason",
            {"sid": session_id},
        )
        endpoints = await g.run_read_query(
            "MATCH (e:Endpoint {engagement_id: $sid}) "
            "RETURN e.url as url, e.method as method, e.query_keys as query_keys",
            {"sid": session_id},
        )
        await g.close()
        print(f"Skipped scans count: {len(skipped)}")
        print(f"Endpoints count: {len(endpoints)}")

        # 3. Load all tasks from PostgreSQL (for exact pipeline tracing)
        from ai_osop.memory.session_memory import SessionMemory
        from sqlalchemy import select
        from ai_osop.memory.session_memory import TaskORM

        sm_tasks = SessionMemory()
        await sm_tasks.connect()
        async with sm_tasks._async_session() as db:
            res = await db.execute(select(TaskORM).where(TaskORM.engagement_id == session_id))
            tasks_list = res.scalars().all()
        await sm_tasks.close()
        print(f"Total tasks retrieved from DB: {len(tasks_list)}")

        # 4. Run Ground Truth Engine
        from ai_osop.core.ground_truth import GroundTruthEngine

        # Seed the expected Ground Truth manifest with parameter-level preconditions
        expected_manifest = [
            {
                "vuln_class": "sqli",
                "path": "/catalog/product",
                "parameter": "productId",
                "description": "SQL Injection in productId parameter",
            },
            {
                "vuln_class": "sqli",
                "path": "/catalog/product/stock",
                "parameter": "productId",
                "description": "SQL Injection in stock check",
            },
            {
                "vuln_class": "xss",
                "path": "/catalog",
                "parameter": "searchTerm",
                "description": "Reflected XSS in searchTerm",
            },
            {
                "vuln_class": "xss",
                "path": "/blog",
                "parameter": "search",
                "description": "Reflected XSS in blog search",
            },
            {
                "vuln_class": "idor",
                "path": "/my-account",
                "parameter": "id",
                "description": "IDOR in my-account page",
            },
            {
                "vuln_class": "jwt_abuse",
                "path": "/login",
                "parameter": "token",
                "description": "JWT abuse on login callback",
            },
        ]

        engine = GroundTruthEngine(expected_manifest)
        gt_results = engine.evaluate_engagement(findings, tasks_list, skipped, endpoints)
        report_md = engine.generate_markdown_report(gt_results)

        # Save report
        report_path = "CAPABILITY_COVERAGE_REPORT.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_md)
        print(f"\nSUCCESS: Written capability coverage report to {report_path}")

        # 4. Run Post-Engagement Critic Agent
        from ai_osop.agents.critic_agent import PostEngagementCriticAgent
        from ai_osop.memory.session_memory import SessionMemory

        sm = SessionMemory()
        await sm.connect()

        gm = GraphMemory()
        await gm.connect()

        critic = PostEngagementCriticAgent(sm, gm)
        critic_md = await critic.generate_critique(session_id)

        await sm.close()
        await gm.close()

        # Save critique
        critique_path = "POST_ENGAGEMENT_CRITIQUE.md"
        with open(critique_path, "w", encoding="utf-8") as f:
            f.write(critic_md)
        print(f"SUCCESS: Written post-engagement critique to {critique_path}")
        print("=" * 60)
        try:
            print(critic_md)
        except UnicodeEncodeError:
            print("[Critique contains Unicode characters; see file for full content]")
        print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
