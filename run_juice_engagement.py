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

    # 6. IDOR (diff-auth) pipeline: register user_b, import sessions, dispatch
    print("\n[*] phase: IDOR / differential authorization")
    user_b_token = None
    try:
        # Register a second user via the API
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
        # Login as user_b
        user_b_token = login_juice(b_email, b_pass)
    except Exception as e:
        print(f"    [!] user_b setup exception: {e}")

    # Import user_b session
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

    # Generate a workflow_id upfront so we can pass it to both the surface
    # capture and the diff-auth analyzer — avoids depending on the return value.
    wid = f"wf-{uuid.uuid4().hex[:12]}"
    surface_id = dispatch(
        "capture_authenticated_surface",
        "workflow",
        {"url": BASE, "user_label": "user_a", "workflow_id": wid},
        priority=6,
    )

    if surface_id:
        surface_task = wait_task(H, surface_id, "surface_capture", timeout=180)
        r = surface_task.get("result") or {}
        har_path = r.get("har_path", "")
        api_count = r.get("endpoints_extracted", 0)
        api_persisted = r.get("endpoints_persisted", 0)
        status = r.get("status", "?")
        error = r.get("error", "")
        print(f"    [+] status={status} workflow_id={wid} har_path={har_path[-50:] if har_path else 'N/A'} ext={api_count} persist={api_persisted}")
        if error:
            print(f"    [!] surface_capture error: {error}")
        if not har_path or api_count == 0:
            # Diagnostic: dump full result when no endpoints found
            import json as _json
            print(f"    [dbg] surface result dump: {_json.dumps(r, default=str)[:600]}")

        # Dispatch diff-auth analysis: replay endpoints as user_a / user_b / anonymous.
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
            for f in (r2.get("findings") or r2.get("results") or [])[:5]:
                print(f"      - {f.get('type','?')} {f.get('endpoint','?')} conf={f.get('confidence','?')}")
        else:
            print(f"    [!] diff-auth dispatch HTTP {rr2.status_code}: {rr2.text[:300]}")

    print(f"\n[*] DONE. engagement_id={eid}")
    print(f"[*] score with: poetry run python benchmarks/score_engagement.py "
          f"--findings <export> --manifest benchmarks/ground_truth/juice_shop.yaml")
    with open(".last_engagement_id", "w") as f:
        f.write(eid)


if __name__ == "__main__":
    main()
