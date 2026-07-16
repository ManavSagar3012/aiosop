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
  5. poll each task to completion, print verdicts
  6. print the engagement_id so the export/score step can pick it up
"""

import os
import sys
import time
import json
import uuid
from datetime import datetime, timedelta, timezone

import requests
from dotenv import load_dotenv

load_dotenv(".env")
sys.path.insert(0, "src")

API = "http://localhost:8200"
TARGET = "localhost:3000"
BASE = "http://localhost:3000"


def mint_token() -> str:
    """Return the bearer the running API accepts.

    Precedence mirrors deps.verify_token: a non-empty OSOP_JWT_SECRET means the
    API expects a signed JWT; otherwise it does constant-time equality against
    OSOP_API_TOKEN. This API instance has an empty jwt_secret, so the static
    token is the correct credential.
    """
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


def main() -> None:
    tok = mint_token()
    H = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}

    eid = "juice-e2e-" + uuid.uuid4().hex[:8]
    print(f"[*] engagement_id = {eid}")

    # 1. create engagement
    body = {
        "engagement_id": eid,
        "domains": [TARGET],
        "allowed_techniques": ["sqli", "jwt", "mass_assignment", "recon"],
        "approval_required_for": [],  # no gating for the local authorized target
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

    # 2. recon: content discovery to populate endpoints
    print("[*] phase: recon (content discovery)")
    task_ids = []
    t = dispatch(
        "content_discovery",
        "recon",
        {"url": BASE, "seed_urls": [BASE, f"{BASE}/#/", f"{BASE}/api/Products"]},
    )
    if t:
        task_ids.append(t)

    # 3. vuln scans matching ground truth
    print("[*] phase: vuln discovery")
    scans = [
        ("sqli_scan", "vuln_analysis", {"url": f"{BASE}/rest/products/search?q=test", "level": 2, "risk": 2}),
        ("sqli_scan", "vuln_analysis", {"url": f"{BASE}/rest/user/login", "data": "email=a@a.com&password=b", "level": 2, "risk": 2}),
        ("jwt_scan", "vuln_analysis", {"url": f"{BASE}/rest/user/login"}),
        ("mass_assignment_scan", "vuln_analysis", {"url": f"{BASE}/api/Users", "data": "email=x@x.com&password=Test1234&role=admin"}),
    ]
    for task_type, agent_type, payload in scans:
        tid = dispatch(task_type, agent_type, payload)
        if tid:
            task_ids.append(tid)

    # 4. poll to completion
    print(f"[*] polling {len(task_ids)} tasks (up to 6 min)...")
    deadline = time.time() + 360
    done = {}
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
                print(f"    [=] {tk.get('type')} {st} confirmed={confirmed} findings={fc} reason={str(res.get('reason'))[:80]}")
        time.sleep(6)

    pending = [t for t in task_ids if t not in done]
    if pending:
        print(f"[!] {len(pending)} tasks still pending at deadline: {pending}")

    print(f"\n[*] DONE. engagement_id={eid}")
    print(f"[*] export with: gm.export_findings_json('{eid}', path=...)")
    # write the engagement id for the scoring step
    with open(".last_engagement_id", "w") as f:
        f.write(eid)


if __name__ == "__main__":
    main()
