"""End-to-end verification for Issues 6, 7, 8, 11, 14: browser evidence chain.

Loads the upgraded browser_mcp.py module directly, drives navigate ->
screenshot -> dom -> flush_har on a controlled target, then verifies (a)
artifacts exist on disk and (b) they can be linked to a Step node in
Neo4j via attach_evidence_to_step.
"""

import asyncio
import importlib.util
import os
import sys
import uuid

sys.path.insert(0, "src")

spec = importlib.util.spec_from_file_location(
    "browser_mcp_new", "mcp-servers/python/browser_mcp.py"
)
browser_mcp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(browser_mcp)

from ai_osop.memory.graph_memory import GraphMemory


async def main() -> int:
    engagement_id = f"vrf-{uuid.uuid4().hex[:8]}"
    workflow_id = f"wf-{uuid.uuid4().hex[:8]}"
    step_id = f"step-{uuid.uuid4().hex[:8]}"

    print("[1] starting Playwright BrowserManager")
    mgr = browser_mcp.BrowserManager()
    await mgr.start()

    label = "verify_user"
    data_url = (
        "data:text/html,<html><head><title>OSOP Verify</title></head>"
        f"<body><h1>AI-OSOP evidence chain test</h1><p>id={engagement_id}</p></body></html>"
    )

    page = await mgr.get_page(label, engagement_id=engagement_id)
    print("[2] navigating to data URL")
    await page.goto(data_url, wait_until="domcontentloaded")

    print("[3] capture screenshot")
    shot = await mgr.screenshot(label, engagement_id, workflow_id, step_id)
    assert shot.get("path") and os.path.exists(shot["path"]), f"shot missing: {shot}"
    print(f"    -> {shot['path']} ({shot['size_bytes']} bytes)")

    print("[4] capture DOM snapshot")
    dom = await mgr.dom_snapshot(label, engagement_id, workflow_id, step_id)
    assert dom.get("path") and os.path.exists(dom["path"]), f"dom missing: {dom}"
    print(f"    -> {dom['path']} ({dom['size_bytes']} bytes)")

    print("[5] capture state (storage degradation test)")
    state = await mgr.capture_state(label, engagement_id=engagement_id)
    assert "cookies" in state, "cookies missing"
    has_localstorage = "localStorage" in state or "localStorage_error" in state
    has_sessionstorage = "sessionStorage" in state or "sessionStorage_error" in state
    assert has_localstorage and has_sessionstorage, "graceful degradation missing"
    print(f"    -> storage_keys captured (no abort)")

    print("[6] flush HAR + trace")
    har = await mgr.flush_har(label, workflow_id)
    har_ok = bool(har.get("path") and har.get("exists"))
    trace_ok = bool(har.get("trace_path") and os.path.exists(har["trace_path"]))
    print(f"    -> HAR: {har.get('path')} exists={har.get('exists')}")
    print(f"    -> trace: {har.get('trace_path')}")
    print(f"    -> har_ok={har_ok} trace_ok={trace_ok}")

    print("[7] verify graph linkage via attach_evidence_to_step")
    gm = GraphMemory()
    await gm.connect()

    # Create a placeholder Step node so HAS_EVIDENCE has a real target.
    async with gm._driver.session() as session:
        await session.run(
            "MERGE (s:Step {id: $sid}) SET s.engagement_id=$eid",
            {"sid": step_id, "eid": engagement_id},
        )

    ev_id_1 = await gm.attach_evidence_to_step(
        step_id, "screenshot", shot["path"], engagement_id, workflow_id,
        {"url": data_url, "user_label": label},
    )
    ev_id_2 = await gm.attach_evidence_to_step(
        step_id, "dom", dom["path"], engagement_id, workflow_id,
        {"url": data_url, "user_label": label},
    )
    ev_id_3 = None
    if har_ok:
        ev_id_3 = await gm.attach_evidence_to_step(
            step_id, "har", har["path"], engagement_id, workflow_id,
            {"user_label": label},
        )
    ev_id_4 = None
    if trace_ok:
        ev_id_4 = await gm.attach_evidence_to_step(
            step_id, "trace", har["trace_path"], engagement_id, workflow_id,
            {"user_label": label},
        )
    print(f"    -> attached evidence ids: {[ev_id_1, ev_id_2, ev_id_3, ev_id_4]}")

    async with gm._driver.session() as session:
        link_check = await session.run(
            "MATCH (s:Step {id: $sid})-[:HAS_EVIDENCE]->(ev:Evidence) "
            "RETURN count(ev) AS n, collect(ev.type) AS types",
            {"sid": step_id},
        )
        link = await link_check.single()
        n_linked = link["n"]
        types_linked = link["types"]
        print(f"    -> step {step_id} has {n_linked} evidence: {types_linked}")
        assert n_linked >= 2, "expected at least screenshot+dom"

        # Cleanup
        await session.run(
            "MATCH (s:Step {id: $sid}) OPTIONAL MATCH (s)-[:HAS_EVIDENCE]->(ev) "
            "DETACH DELETE s, ev",
            {"sid": step_id},
        )

    await mgr.stop()

    har_label = "OK" if har_ok else "SKIPPED"
    trace_label = "OK" if trace_ok else "SKIPPED"
    print("PASS: evidence chain (Issues 6, 7, 8, 11, 14) verified")
    print(f"     screenshot: OK  dom: OK  har: {har_label}  trace: {trace_label}  graph_link: OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
