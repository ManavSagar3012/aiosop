# AIOSOP Capability Benchmark — OWASP Juice Shop

The platform's first **reproducible, evidence-backed** proof that AIOSOP's
detection engines can discover and validate real vulnerability classes. It is
deliberately **decoupled** from the orchestrator / Neo4j / LLM stack so that a
capability result cannot be faked by, or blocked by, that fragile layer. It
drives the platform's **real** engines against a known, legal, intentionally
vulnerable target and scores the outcome against a **ground-truth manifest**.

## Why this exists

Before this, the only "autonomous" evidence in the repo was a completed run that
found **0** findings against Juice Shop plus several `_partial` runs that died at
init. "Can it find bugs?" had no measured answer. This benchmark makes the
answer a number that anyone can reproduce.

## What it proves (and what it does NOT)

- **PROVES:** the deterministic capability core — SQLi (auth-bypass + error),
  JWT forgery (`alg:none`), broken-access-control (IDOR), and role mass-assignment
  surfacing — works
  against a live target with deterministic oracles, zero false positives on the
  negative controls, and zero hangs across repeated runs.
- **DOES NOT prove:** the full autonomous pipeline (API + Neo4j + agents + LLM
  planning). That is the next milestone; this benchmark isolates capability from
  orchestration on purpose.

## Design principles

| Principle | Implementation |
|-----------|----------------|
| Deterministic verification | A finding is `VALIDATED` only by an objective oracle (issued session JWT, DB parse error, forged-identity echo, cross-account 200 vs anon 401) — never an LLM opinion. |
| Ground truth | `MANIFEST` marks each check `expected=True/False`. `expected=False` entries are **negative controls**; a validation there is a false positive. |
| Hang-proof | Every check runs under a hard `asyncio.wait_for` timeout. A wedged check becomes a `TIMEOUT` datapoint; the suite never hangs. Stability = clean (no-timeout) runs / total. |
| Real code | Imports the actual platform engines (`DifferentialAuthEngine`, `JWTTester`, `js_analyzer` `SECRET_RULES`) — it benchmarks the platform, not a re-implementation. |

## Run it

```bash
# 1. start the target
docker run --rm -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
# 2. run the benchmark (3 repeats -> stability signal)
.venv/Scripts/python.exe benchmarks/juiceshop/bench.py \
    --target http://localhost:3000 --timeout 40 --repeat 3
```

Machine-readable evidence is written to `benchmarks/juiceshop/results/bench-<ts>.json`
(per-check verdicts, confidence, timing, request/response evidence, scoreboard).

## Checks

| id | class | oracle | scored |
|----|-------|--------|--------|
| `sqli_login_bypass` | CWE-89 | injected email + bogus password yields a session JWT | ✓ |
| `sqli_search_error` | CWE-89 | paren-breakout payload raises a SQLite parse error | ✓ |
| `sqli_search_negative` | control | benign query must NOT trip the SQLi oracle | ✓ (neg) |
| `idor_basket` | CWE-639 | real `DifferentialAuthEngine`: attacker 2xx on victim basket, anon 401 | ✓ |
| `idor_public_negative` | control | public homepage must NOT be flagged IDOR (FP-suppression) | ✓ (neg) |
| `jwt_forgery` | CWE-347 | real `JWTTester`: forged-identity sentinel echoed back | ✓ |
| `admin_registration` | CWE-915 | role field produces an `admin` account and authenticated read-back confirms it | ✓ |
| `admin_registration_negative` | control | normal registration must persist the `customer` role | ✓ (neg) |
| `secrets_in_js` | CWE-798 | real `SECRET_RULES` + placeholder/entropy filter | informational |
| `nuclei_scan` | multi | scoped `nuclei` breadth pass | informational |

## Interpreting confidence

`idor_basket` may report `confidence 0.50 / needs_manual_confirmation`. That is
the engine correctly *surfacing* a real anomaly without over-claiming when it
lacks structural ownership proof (e.g. Juice Shop nests the id under `data.id`
and empty baskets carry no owned items). It is a candidate to confirm, not a
false positive — the underlying IDOR is real (verified manually: an attacker
reads another user's basket, `UserId` differs, anon is 401).

## Known follow-ups surfaced by this benchmark

1. `DifferentialAuthEngine._ownership_match` ignored nested id fields (`data.id`)
   and cross-owner identity (`UserId`), under-scoring genuine IDOR to 0.5.
   (The substring-collision false-positive it *also* had is now fixed — see
   `tests/test_diff_auth_ownership_fp.py`.)
2. `nuclei` scoped pass finds nothing on Juice Shop (expected: app-logic target,
   not CVE-laden) — nuclei is low-yield here and should be demoted for such apps.
