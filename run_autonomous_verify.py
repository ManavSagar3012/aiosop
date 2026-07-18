#!/usr/bin/env python
"""Autonomous verification driver — NO hand-driving.

Issues exactly ONE state-changing API call (POST /engagements) and then only
OBSERVES. The platform's autonomous phase_monitor drives the entire chain:
recon -> guest XHR capture + registration/login probe -> endpoint discovery ->
autonomous dispatch of sqli / mass-assignment / jwt / diff-auth scans.

Unlike run_juice_engagement.py (which hand-drives every scan at hardcoded
endpoints), this script never dispatches a scan, never logs in with real admin
credentials, and never seeds an endpoint into Neo4j. Whatever findings appear
were discovered autonomously.

At the end it exports the persisted findings via GraphMemory.export_findings_json
(the same seam benchmarks/score_engagement.py consumes) and scores them against
benchmarks/ground_truth/juice_shop.yaml.

Run:  .venv/Scripts/python run_autonomous_verify.py
"""
import asyncio
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

import requests
from dotenv import load_dotenv

load_dotenv()

API = "http://localhost:8200"
TARGET = "localhost:3000"
DEADLINE_S = 1500  # 25 min hard cap (two identities + deep nav lengthen recon)
QUIET_STOP_S = 150  # stop early if no task/finding/phase change for this long
POLL_S = 8
FINDINGS_PATH = "autonomous_findings.json"
SCORECARD_PATH = "autonomous_scorecard.json"
MANIFEST = "benchmarks/ground_truth/juice_shop.yaml"
_ACTIVE = ("pending", "running", "scheduled", "requeued", "assigned", "in_progress")
_TERMINAL_PHASE = ("completed", "reporting", "report", "done", "halted", "closed")


def mint_token() -> str:
    secret = (os.environ.get("OSOP_JWT_SECRET") or "").strip()
    if secret:
        from jose import jwt

        alg = os.environ.get("OSOP_JWT_ALGORITHM", "HS256")
        claims = {
            "sub": "autonomous-verify",
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


def main() -> int:
    tok = mint_token()
    h = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
    eid = f"juice-auto-{uuid.uuid4().hex[:8]}"
    body = {
        "engagement_id": eid,
        "domains": [TARGET],
        "allowed_techniques": ["recon", "sqli", "jwt", "mass_assignment", "idor"],
        "approval_required_for": [],
        "authorization_ref": "local-authorized-juice-shop",
        "roe": {"max_requests_per_second": 20},
    }
    print(f"[*] POST /engagements engagement_id={eid}", flush=True)
    r = requests.post(f"{API}/engagements", headers=h, json=body, timeout=60)
    if r.status_code >= 400:
        print(f"[!] create failed HTTP {r.status_code}: {r.text[:600]}", flush=True)
        return 2
    sess = r.json()
    sid = sess.get("session_id") or eid
    print(f"[+] session_id={sid} phase={sess.get('phase')}", flush=True)
    print("[*] AUTONOMOUS — this script dispatches NO scans. Observing...", flush=True)

    seen = {}  # task_id -> (type, status)
    last_change = time.time()
    start = time.time()
    last_phase = None
    findings_n = 0

    while time.time() - start < DEADLINE_S:
        try:
            er = requests.get(f"{API}/engagements/{sid}", headers=h, timeout=15)
            phase = er.json().get("phase") if er.status_code == 200 else None
        except Exception:
            phase = None
        if phase and phase != last_phase:
            print(f"    [phase] -> {phase}  (+{int(time.time()-start)}s)", flush=True)
            last_phase = phase
            last_change = time.time()

        try:
            tr = requests.get(f"{API}/tasks", headers=h, timeout=15)
            tasks = tr.json() if tr.status_code == 200 else []
        except Exception:
            tasks = []
        mine = [t for t in tasks if isinstance(t, dict) and t.get("engagement_id") in (sid, eid)]
        for t in mine:
            tid = t.get("id")
            key = (t.get("type"), t.get("status"))
            if seen.get(tid) != key:
                print(
                    f"    [task] {str(t.get('type')):<28} "
                    f"{str(t.get('status')):<11} {str(tid)[:14]}",
                    flush=True,
                )
                seen[tid] = key
                last_change = time.time()

        try:
            fr = requests.get(f"{API}/engagements/{sid}/findings", headers=h, timeout=15)
            fl = fr.json() if fr.status_code == 200 else []
            n = len(fl) if isinstance(fl, list) else len(fl.get("findings", []))
        except Exception:
            n = findings_n
        if n != findings_n:
            print(f"    [findings] {findings_n} -> {n}", flush=True)
            findings_n = n
            last_change = time.time()

        active = [t for t in mine if str(t.get("status")) in _ACTIVE]
        terminal = str(phase or "").lower() in _TERMINAL_PHASE
        idle = time.time() - last_change
        if seen and not active and idle > QUIET_STOP_S:
            print(f"[*] quiescent {int(idle)}s, no active tasks — stop.", flush=True)
            break
        if terminal and not active:
            print(f"[*] terminal phase '{phase}', no active tasks — stop.", flush=True)
            break
        time.sleep(POLL_S)

    elapsed = int(time.time() - start)
    print(
        f"[*] observation ended +{elapsed}s. tasks_seen={len(seen)} findings={findings_n}",
        flush=True,
    )
    by_type = {}
    for ttype, tstatus in seen.values():
        by_type.setdefault(ttype, {}).setdefault(tstatus, 0)
        by_type[ttype][tstatus] += 1
    print(f"[*] task summary: {by_type}", flush=True)

    try:
        asyncio.run(_export(sid, FINDINGS_PATH))
    except Exception as e:
        print(f"[!] export failed: {e}", flush=True)
        return 3

    print(f"[*] scoring {FINDINGS_PATH} vs {MANIFEST}", flush=True)
    proc = subprocess.run(
        [
            sys.executable,
            "benchmarks/score_engagement.py",
            "--findings",
            FINDINGS_PATH,
            "--manifest",
            MANIFEST,
            "--out",
            SCORECARD_PATH,
        ],
        capture_output=True,
        text=True,
    )
    sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    print(
        f"[*] DONE. session_id={sid} findings={FINDINGS_PATH} scorecard={SCORECARD_PATH}",
        flush=True,
    )
    return 0


async def _export(session_id: str, path: str) -> None:
    from ai_osop.memory.graph_memory import GraphMemory

    gm = GraphMemory()
    await gm.connect()
    try:
        findings = await gm.export_findings_json(session_id, path=path)
        print(f"[+] exported {len(findings)} findings -> {path}", flush=True)
    finally:
        await gm.close()


if __name__ == "__main__":
    raise SystemExit(main())
