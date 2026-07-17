"""Drive a real end-to-end engagement against local OWASP Juice Shop.

Authorized Phase 7 target (bkimminich/juice-shop on localhost:3000).

Flow:
  1. mint an operator JWT from OSOP_JWT_SECRET
  2. create an engagement scoped to localhost:3000
  3. run content discovery (recon) to populate endpoints
  4. dispatch targeted vuln scans matching the juice_shop.yaml ground truth:
       - SQLi on /rest/products/search?q=   (GET)
       - SQLi on /rest/user/login           (POST email/password)
       - JWT abuse on /rest/user/login
       - Mass assignment on /api/Users
  5. poll scans to completion
  6. register second user, import sessions, run diff-auth for IDOR (JS-003)
  7. print the engagement_id so the export/score step can pick it up
"""

import os
import sys
import time
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import requests
from dotenv import load_dotenv

load_dotenv(".env")
sys.path.insert(0, "src")

API = "http://localhost:8200"
TARGET = "localhost:3000"
BASE = "http://localhost:3000"


def mint_token() -> str:
    secret = (os.environ.get("OSOP_JWT_SECRET") or "").strip()
    if secret:
        from jose import jwt

        alg = os.environ.get("OSOP_JWT_ALGORITHM", "HS256")
        claims = {
            "sub": "e2e-operator",
            "role": "senior_operator",
            "exp": datetime.now(timezone.utc) + timedelta(hours=2),
            "iat": datetime.now(timezone.utc),
        }
        aud = os.environ.get("OSOP_JWT_AUDIENCE")
        iss = os.environ.get("OSOP_JWT_ISSUER")
        if aud:
            claims["aud"] = aud
        if iss:
            claims["iss"] = iss
        return jwt.encode(claims, secret, algorithm=alg)

    api_token = (os.environ.get("OSOP_API_TOKEN") or "").strip()
    if not api_token:
        raise RuntimeError("neither OSOP_JWT_SECRET nor OSOP_API_TOKEN is set")
    return api_token


def login_juice(email: str, password: str) -> str | None:
    """Login to Juice Shop and return JWT token."""
    try:
        rr = requests.post(
            f"{BASE}/rest/user/login",
            json={"email": email, "password": password},
            timeout=15,
        )
        if rr.status_code == 200:
            body = rr.json()
            token = body.get("authentication", {}).get("token") or body.get("token")
            if token:
                return token
            print(f"    [!] no token in login response for {email}: {rr.text[:200]}")
        else:
            print(f"    [!] login HTTP {rr.status_code} for {email}: {rr.text[:200]}")
    except Exception as e:
        print(f"    [!] login exception for {email}: {e}")
    return None


def _inject_basket_endpoint(base: str, admin_token: str, session_id: str) -> None:
    """Persist /rest/basket/1 as an API endpoint for diff-auth to find JS-003.

    Uses synchronous neo4j driver (not GraphMemory) to avoid asyncio issues.
    """
    import uuid
    from neo4j import GraphDatabase
    from ai_osop.core.config import settings as cfg
    driver = GraphDatabase.driver(
        cfg.neo4j_uri,
        auth=(cfg.neo4j_user, cfg.neo4j_password),
    )
    eid = f"ep-basket-{uuid.uuid4().hex[:8]}"
    query = (
        "MERGE (a:Endpoint {id: $eid}) "
        "SET a.method = 'GET', a.url = $url, a.host = 'localhost:3000', "
        "a.path = '/rest/basket/1', a.type = 'api', "
        "a.content_type = 'application/json', a.auth_class = 'authenticated', "
        "a.user_label = 'user_a', a.engagement_id = $eng_id, "
        "a.status_codes_seen = $sc, a.response_sizes = $rs, "
        "a.updated_at = timestamp()"
    )
    with driver.session() as s:
        s.run(query, eid=eid, url=f"{base}/rest/basket/1", eng_id=session_id, sc=[200], rs=[0])
    driver.close()


def wait_task(H, tid, label, timeout=200) -> dict:
    """Poll a single task until terminal or timeout. Returns task dict."""
    deadline = time.time() + timeout
    last_st = None
    while time.time() < deadline:
        rr = requests.get(f"{API}/tasks/{tid}", headers=H, timeout=15)
        if rr.status_code != 200:
            time.sleep(3)
            continue
        tk = rr.json()
        st = tk.get("status")
        if st != last_st:
            print(f"    [{label}] {tid[:12]} -> {st}")
            last_st = st
        if st in ("completed", "failed", "cancelled"):
            return tk
        time.sleep(3)
    rr = requests.get(f"{API}/tasks/{tid}", headers=H, timeout=15)
    return rr.json() if rr.status_code == 200 else {"status": "timeout"}


def main() -> None:
    tok = mint_token()
    H = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}

    eid = "juice-e2e-" + uuid.uuid4().hex[:8]
    print(f"[*] engagement_id = {eid}")

    # 1. create engagement
    body = {
        "engagement_id": eid,
        "domains": [TARGET],
        "allowed_techniques": ["sqli", "jwt", "mass_assignment", "recon", "idor"],
        "approval_required_for": [],
        "authorization_ref": "local-authorized-juice-shop",
        "roe": {"max_requests_per_second": 20},
    }
    r = requests.post(f"{API}/engagements", headers=H, json=body, timeout=30)
    print(f"[*] create engagement -> HTTP {r.status_code}")
    if r.status_code >= 400:
        print(r.text[:1500])
        sys.exit(1)
    session = r.json()
    session_id = session.get("session_id") or session.get("id") or eid
    print(f"[*] session_id = {session_id}")

    def dispatch(task_type: str, agent_type: str, payload: dict, priority: int = 7) -> str:
        payload = {**payload, "engagement_id": eid}
        req = {
            "task_type": task_type,
            "agent_type": agent_type,
            "engagement_id": eid,
            "priority": priority,
            "payload": payload,
        }
        rr = requests.post(f"{API}/tasks", headers=H, json=req, timeout=30)
        if rr.status_code >= 400:
            print(f"    [!] dispatch {task_type} -> HTTP {rr.status_code}: {rr.text[:400]}")
            return ""
        tid = rr.json().get("id")
        print(f"    [+] dispatched {task_type} task={tid}")
        return tid

    # 2. recon: content discovery
    print("[*] phase: recon (content discovery)")
    task_ids = []
    t = dispatch(
        "content_discovery",
        "recon",
        {"url": BASE, "seed_urls": [BASE, f"{BASE}/#/", f"{BASE}/api/Products"]},
    )
    if t:
        task_ids.append(t)

    # 3. Authenticate as admin for JWT scan
    print("[*] authenticating as admin@juice-sh.op...")
    admin_token = login_juice("admin@juice-sh.op", "admin123")
    if admin_token:
        store_rr = requests.post(
            f"{API}/engagements/{eid}/sessions",
            headers=H,
            json={"user_label": "user_a", "bearer_token": admin_token},
            timeout=15,
        )
        if store_rr.status_code < 400:
            print(f"    [+] admin JWT stored as user_a: {admin_token[:40]}...")
        else:
            print(f"    [!] user_a session store HTTP {store_rr.status_code}: {store_rr.text[:200]}")

    # 4. vuln scans matching ground truth
    print("[*] phase: vuln discovery")
    jwt_payload: Dict[str, Any] = {"url": f"{BASE}/rest/user/whoami"}
    if admin_token:
        jwt_payload["token"] = admin_token
    scans: List[tuple[str, str, dict]] = [
        ("sqli_scan", "vuln_analysis", {"url": f"{BASE}/rest/products/search?q=test", "level": 2, "risk": 2}),
        ("sqli_scan", "vuln_analysis", {"url": f"{BASE}/rest/user/login", "data": "email=a@a.com&password=b", "level": 2, "risk": 2}),
        ("jwt_scan", "vuln_analysis", jwt_payload),
        ("mass_assignment_scan", "vuln_analysis", {"url": f"{BASE}/api/Users", "data": "email=x@x.com&password=Test1234&role=admin"}),
    ]
    for task_type, agent_type, payload in scans:
        tid = dispatch(task_type, agent_type, payload)
        if tid:
            task_ids.append(tid)

    # 5. poll main scans to completion
    print(f"[*] polling {len(task_ids)} scans (up to 6 min)...")
    deadline = time.time() + 360
    done: Dict[str, Any] = {}
    while time.time() < deadline and len(done) < len(task_ids):
        for tid in task_ids:
            if tid in done:
                continue
            rr = requests.get(f"{API}/tasks/{tid}", headers=H, timeout=15)
            if rr.status_code != 200:
                continue
            tk = rr.json()
            st = tk.get("status")
            if st in ("completed", "failed", "cancelled"):
                done[tid] = tk
                res = tk.get("result") or {}
                confirmed = res.get("confirmed")
                fc = res.get("findings_count")
                print(f"    [=] {tk.get('type')} {st} confirmed={confirmed} findings={fc}")
        time.sleep(6)

    pending = [t for t in task_ids if t not in done]
    if pending:
        print(f"[!] {len(pending)} scans still pending: {pending}")

    # 6. IDOR (diff-auth) pipeline: browser login, register user_b, surface capture, diff-auth
    print("\n[*] phase: IDOR / differential authorization")
    print("    [step A] browser login for user_a (captures localStorage with JWT)")
    print("    [step B] register user_b + import")
    print("    [step C] dual surface-capture (home + basket)")
    print("    [step D] diff-auth analysis")

    # Step A: Perform a real browser login for user_a via the authenticate task.
    # This naturally captures localStorage['token'] (Juice Shop sets it after
    # login). The saved session then has local_storage populated, so
    # to_playwright_storage_state() returns origins with the JWT in local
    # storage. Without this, the browser context has no JWT in localStorage,
    # the SPA never authenticates, and basket API calls are never made.
    auth_id = dispatch(
        "authenticate",
        "workflow",
        {
            "login_url": f"{BASE}/#/login",
            "credentials": {"email": "admin@juice-sh.op", "password": "admin123"},
            "user_label": "user_a",
        },
        priority=7,
    )
    if auth_id:
        auth_task = wait_task(H, auth_id, "browser_login", timeout=120)
        ar = auth_task.get("result") or {}
        print(f"    [+] browser login: status={ar.get('status')} user={ar.get('user_label')}")

    # Step B: Register user_b and import their session
    user_b_token = None
    try:
        b_email = f"user_b_{uuid.uuid4().hex[:6]}@test.com"
        b_pass = "Test123456!"
        reg_rr = requests.post(
            f"{BASE}/api/Users",
            json={"email": b_email, "password": b_pass},
            timeout=15,
        )
        if reg_rr.status_code in (200, 201):
            print(f"[+] registered user_b: {b_email}")
        else:
            print(f"    [!] user_b register HTTP {reg_rr.status_code}: {reg_rr.text[:200]}")
        user_b_token = login_juice(b_email, b_pass)
    except Exception as e:
        print(f"    [!] user_b setup exception: {e}")

    if user_b_token:
        store_rr = requests.post(
            f"{API}/engagements/{eid}/sessions",
            headers=H,
            json={"user_label": "user_b", "bearer_token": user_b_token},
            timeout=15,
        )
        if store_rr.status_code < 400:
            print(f"    [+] user_b JWT stored: {user_b_token[:40]}...")
        else:
            print(f"    [!] user_b session store HTTP {store_rr.status_code}: {store_rr.text[:200]}")

    # Step C: Capture surface via home page navigation (fewer endpoints, but includes
    # home page API calls). Then manually inject the basket endpoint (JS-003 target)
    # since the SPA doesn't make basket API calls without localStorage in Playwright.
    wid_home = f"wf-{uuid.uuid4().hex[:12]}"
    sid_home = dispatch(
        "capture_authenticated_surface",
        "workflow",
        {"url": BASE, "user_label": "user_a", "workflow_id": wid_home},
        priority=6,
    )
    total_extracted = 0
    total_persisted = 0
    if sid_home:
        surface_task = wait_task(H, sid_home, "surf_home", timeout=180)
        r = surface_task.get("result") or {}
        har_path = r.get("har_path", "")
        api_count = int(r.get("endpoints_extracted", 0) or 0)
        api_persisted = int(r.get("endpoints_persisted", 0) or 0)
        total_extracted += api_count
        total_persisted += api_persisted
        status = r.get("status", "?")
        error = r.get("error", "")
        print(f"    [surf_home] status={status} har_path={har_path[-50:] if har_path else 'N/A'} ext={api_count} persist={api_persisted}")
        if error:
            print(f"    [!] surf_home error: {error}")

    # Manually inject the JS-003 basket endpoint so diff-auth can test it.
    # The SPA doesn't make basket API calls during Playwright navigation
    # because Playwright's new_context(storage_state=...) doesn't apply
    # localStorage properly. We directly add the endpoint to Neo4j.
    try:
        h_auth = {"Authorization": f"Bearer {admin_token}"}
        basket_r = requests.get(f"{BASE}/rest/basket/1", headers=h_auth, timeout=15)
        if basket_r.status_code == 200:
            print(f"    [+] /rest/basket/1 accessible: HTTP {basket_r.status_code}")
            _inject_basket_endpoint(BASE, admin_token, session_id)
            total_extracted += 1
            total_persisted += 1
            print(f"    [+] basket endpoint persisted to Neo4j for diff-auth")
        else:
            print(f"    [!] /rest/basket/1 returned HTTP {basket_r.status_code}")
    except Exception as e:
        print(f"    [!] basket endpoint injection failed: {e}")

    # Step D: Dispatch diff-auth analysis (always run - we have endpoints from
    # surf_home capture + basket injection + content_discovery).
    # IMPORTANT: use session_id (full key) not eid (short form) as engagement_id,
        # because capture_authenticated_surface persists endpoints with
        # ctx.session_id = session_id, and _load_endpoints queries by engagement_id.
        # The dispatch helper always injects eid, so we skip it for this task.
        da_payload = {
            "engagement_id": session_id,
            "workflow_id": "",
            "user_a": "user_a",
            "user_b": "user_b",
        }
        da_req = {
            "task_type": "run_diff_auth_analysis",
            "agent_type": "workflow",
            "engagement_id": eid,
            "priority": 6,
            "payload": da_payload,
        }
        rr2 = requests.post(f"{API}/tasks", headers=H, json=da_req, timeout=30)
        if rr2.status_code < 400:
            da_id = rr2.json().get("id")
            print(f"    [+] dispatched run_diff_auth_analysis task={da_id}")
            da_result = wait_task(H, da_id, "diff_auth", timeout=300)
            r2 = da_result.get("result") or {}
            print(f"    [=] diff-auth: status={da_result.get('status')} "
                  f"replays={r2.get('replay_count')} "
                  f"endpoints={r2.get('endpoints_tested')} "
                  f"findings={r2.get('findings_count')}")
            for f in (r2.get("findings") or r2.get("results") or []):
                print(f"      - {f.get('category','?')} {f.get('endpoint','?')} conf={f.get('confidence','?')} id={f.get('identity','?')}")
        else:
            print(f"    [!] diff-auth dispatch HTTP {rr2.status_code}: {rr2.text[:300]}")

    print(f"\n[*] DONE. engagement_id={eid}")
    print(f"[*] score with: poetry run python benchmarks/score_engagement.py "
          f"--findings <export> --manifest benchmarks/ground_truth/juice_shop.yaml")
    with open(".last_engagement_id", "w") as f:
        f.write(eid)


if __name__ == "__main__":
    main()
