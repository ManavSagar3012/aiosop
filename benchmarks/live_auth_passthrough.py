"""Live proof: auth passthrough threads a real session to a live target.

WHAT THIS PROVES (end-to-end, against real infra — not doubles)
    The feature claim on branch fix/mock-findings-honest-stub-tool-guard is that
    the generalized surface oracles, when handed an authenticated SessionClient,
    drive their probes THROUGH that session — so an injection point that only
    exists behind login becomes reachable. Every existing test asserts this with
    in-memory doubles. This script asserts it against the real stack:

        * live Neo4j          (Endpoint node the scan reads from)
        * live Postgres+Redis (SessionStore the authed client is built from)
        * live OWASP Juice Shop on :3000 (the target the oracle actually hits)

METHOD
    1. Register + log in a fresh Juice Shop user -> a real RS256 JWT.
    2. Persist that JWT into the real SessionStore under an auth_user label.
    3. Seed ONE auth-gated Endpoint into live Neo4j: /rest/basket/6?q= is 401
       anonymous, 200 authenticated. It carries a query param so the SQLi
       oracle treats it as an injectable GET candidate and probes it.
    4. Run the REAL run_generalized_sqli TWICE over that endpoint:
         a) authed  — client = store.as_user(...), wrapped to record statuses
         b) anon    — client = None (historical cookie-less path)
    5. Assert the authed run's live probes were admitted by the target (a 200
       appears; no 401) while the anon run was rejected (401 appears, never 200).

    That status split is only possible if the injected SessionClient carried the
    Authorization header through the exact production scan code path to the live
    server. If auth were dropped anywhere in the chain, the authed run would 401
    just like the anon run and the assertion fails.

USAGE
    docker run --rm -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
    # (Neo4j / Postgres / Redis already up via the project's compose stack)
    .venv/Scripts/python.exe benchmarks/live_auth_passthrough.py \
        --target http://localhost:3000

    Exit 0 + "LIVE PROOF PASSED" on success; non-zero on any failed assertion.
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import sys
import time
from pathlib import Path
from typing import Any, List, Optional, Tuple

import httpx

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ai_osop.auth.session_store import SessionStore  # noqa: E402
from ai_osop.core import deterministic_scan as ds  # noqa: E402
from ai_osop.memory.graph_memory import GraphMemory  # noqa: E402
from ai_osop.memory.session_memory import SessionMemory  # noqa: E402

GATED_PATH = "/rest/basket/6"  # 401 anon, 200 authed on stock Juice Shop


# --------------------------------------------------------------------------- #
# A thin recorder that wraps the real SessionClient. It changes NO behavior —
# it only observes the status of every live response the oracle receives, so we
# can prove where the probes landed. This is instrumentation, not a stub: the
# underlying request, auth header, and target are all real.
# --------------------------------------------------------------------------- #
class _RecordingClient:
    def __init__(self, inner: Any):
        self._inner = inner
        self.statuses: List[int] = []

    async def _record(self, resp: httpx.Response) -> httpx.Response:
        self.statuses.append(resp.status_code)
        return resp

    async def get(self, url: str, **kw: Any) -> httpx.Response:
        return await self._record(await self._inner.get(url, **kw))

    async def post(self, url: str, **kw: Any) -> httpx.Response:
        return await self._record(await self._inner.post(url, **kw))

    async def request(self, method: str, url: str, **kw: Any) -> httpx.Response:
        return await self._record(await self._inner.request(method, url, **kw))


async def _register_and_login(target: str) -> str:
    """Create a fresh Juice Shop account and return its bearer JWT."""
    email = f"osop_live_{int(time.time())}_{secrets.token_hex(3)}@test.local"
    password = "Passw0rd!123"
    async with httpx.AsyncClient(base_url=target, timeout=20) as c:
        reg = await c.post(
            "/api/Users/",
            json={
                "email": email,
                "password": password,
                "passwordRepeat": password,
                "securityQuestion": {"id": 1},
                "securityAnswer": "x",
            },
        )
        if reg.status_code not in (200, 201):
            raise RuntimeError(f"registration failed: {reg.status_code} {reg.text[:200]}")
        login = await c.post(
            "/rest/user/login", json={"email": email, "password": password}
        )
        if login.status_code != 200:
            raise RuntimeError(f"login failed: {login.status_code} {login.text[:200]}")
        token = login.json()["authentication"]["token"]
    if not token:
        raise RuntimeError("login returned an empty token")
    return token


async def _seed_endpoint(gm: GraphMemory, engagement_id: str, target: str) -> None:
    """Write ONE auth-gated Endpoint node the SQLi oracle will treat as a GET
    injection candidate (has a query param). Idempotent MERGE on id."""
    url = f"{target}{GATED_PATH}?q=1"
    q = (
        "MERGE (e:Endpoint {id: $id}) "
        "SET e.engagement_id = $eid, e.url = $url, e.method = 'GET', "
        "e.path = $path, e.query_keys = $qk, e.parameters = $qk, "
        "e.has_body = false, e.body_schema_keys = []"
    )
    async with gm._driver.session() as s:
        await s.run(
            q,
            id=f"{engagement_id}:gated-basket",
            eid=engagement_id,
            url=url,
            path=GATED_PATH,
            qk=["q"],
        )


async def _cleanup(gm: GraphMemory, store: SessionStore, eid: str, label: str) -> None:
    try:
        async with gm._driver.session() as s:
            await s.run("MATCH (e:Endpoint {engagement_id:$eid}) DETACH DELETE e", eid=eid)
    except Exception:
        pass
    try:
        await store.delete_session(eid, label)
    except Exception:
        pass


async def run(target: str) -> int:
    engagement_id = f"live-authpass-{secrets.token_hex(4)}"
    auth_user = "live_customer"

    sm = SessionMemory()
    gm = GraphMemory()
    await sm.connect()
    await gm.connect()
    store = SessionStore(sm, gm)

    ok = True
    try:
        token = await _register_and_login(target)
        print(f"[setup] got live JWT ({len(token)} chars) for {auth_user}")

        await store.save_session(engagement_id, auth_user, bearer_token=token)
        print(f"[setup] persisted session into real SessionStore under '{auth_user}'")

        await _seed_endpoint(gm, engagement_id, target)
        print(f"[setup] seeded auth-gated Endpoint {GATED_PATH}?q= into live Neo4j")

        # --- Run A: AUTHENTICATED (real SessionClient, wrapped to record) ---
        async with store.as_user(engagement_id, auth_user, base_url=target) as sc:
            rec_auth = _RecordingClient(sc)
            await ds.run_generalized_sqli(
                engagement_id, gm, per_check_timeout=15.0, client=rec_auth
            )
        auth_statuses = rec_auth.statuses
        print(f"[run A: authed] live probe statuses: {sorted(set(auth_statuses))}")

        # --- Run B: ANONYMOUS (historical cookie-less path) -----------------
        # Wrap a real cookie-less client the same way to observe its statuses.
        anon_inner = httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15)
        rec_anon = _RecordingClient(anon_inner)
        try:
            await ds.run_generalized_sqli(
                engagement_id, gm, per_check_timeout=15.0, client=rec_anon
            )
        finally:
            await anon_inner.aclose()
        anon_statuses = rec_anon.statuses
        print(f"[run B: anon]   live probe statuses: {sorted(set(anon_statuses))}")

        # --- Assertions -----------------------------------------------------
        def check(name: str, cond: bool) -> None:
            nonlocal ok
            print(f"  {'PASS' if cond else 'FAIL'}  {name}")
            ok = ok and cond

        check("authed run issued live probes", len(auth_statuses) > 0)
        check("anon run issued live probes", len(anon_statuses) > 0)
        check("authed run was ADMITTED by target (>=1 non-401 2xx)",
              any(200 <= s < 300 for s in auth_statuses))
        check("authed run never got 401 (token carried through)",
              401 not in auth_statuses)
        check("anon run was REJECTED by target (>=1 401)", 401 in anon_statuses)
        check("anon run never got a 2xx on the gated endpoint",
              not any(200 <= s < 300 for s in anon_statuses))
    finally:
        await _cleanup(gm, store, engagement_id, auth_user)
        try:
            await gm.close()
        except Exception:
            pass
        try:
            await sm.close()
        except Exception:
            pass

    print("\n" + ("LIVE PROOF PASSED" if ok else "LIVE PROOF FAILED"))
    return 0 if ok else 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default="http://localhost:3000", help="Juice Shop base URL")
    args = ap.parse_args(argv)
    return asyncio.run(run(args.target))


if __name__ == "__main__":
    raise SystemExit(main())
