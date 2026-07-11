# AI-OSOP Production Qualification Report

**Generated:** 2026-07-10T16:34:23.094955Z
**Git SHA:** (see RELEASE_CERTIFICATE.md)

---

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | 20 |
| Passed | 20 |
| Failed | 0 |
| Success Rate | 100.0% |

## Suite Results

| Suite | Status | Passed | Failed |
|-------|--------|--------|--------|
| test_security.py | PASS | 10 | 0 |
| test_reliability.py | PASS | 6 | 0 |
| test_scale.py | PASS | 4 | 0 |

## Detailed Output

### test_security.py
```
============================================================
AI-OSOP Security Qualification Suite
============================================================
------------------------------------------------------------
[PASS] jwt_valid_token: Decoded sub=operator-1
[PASS] jwt_expired_token: Expired token correctly rejected
[PASS] jwt_algorithm_none: alg=none correctly rejected by guard
[PASS] jwt_wrong_secret: Token with wrong secret rejected
[PASS] rbac_require_role_rejects: operator correctly rejected with 403
[PASS] rbac_require_role_allows: senior_operator correctly allowed
[PASS] ownership_operator_own: operator accessed own engagement
[PASS] ownership_operator_other: operator-1 correctly denied 403
[PASS] ownership_senior_global: senior_operator accessed any engagement
[PASS] session_encryption_prod: Correctly raised RuntimeError: OSOP_SESSION_ENCRYPTION_KEY is required in product
------------------------------------------------------------
Results: 10 passed, 0 failed
============================================================

```

### test_reliability.py
```
============================================================
AI-OSOP Reliability Qualification Suite
============================================================
------------------------------------------------------------
[PASS] mcp_circuit_opens: Circuit breaker opened after 5 failures
[PASS] mcp_circuit_recovers: Circuit breaker recovered after 31s and successful probe
[PASS] mcp_circuit_blocks: Execution blocked with circuit_open status
[PASS] task_retry_fields: max_retries=3, retry_count=0
[PASS] approval_timeout_field: requested_at set: 2026-07-10T16:34:17.950326
[PASS] warm_storage_fallback: Loaded from warm storage successfully
------------------------------------------------------------
Results: 6 passed, 0 failed
============================================================

```

### test_scale.py
```
============================================================
AI-OSOP Scale Qualification Suite
============================================================
------------------------------------------------------------
[PASS] engage_creation_100: 100 engagements in 0.002s (43197/s)
[PASS] task_creation_1000: 1000 tasks in 0.022s (45305/s)
[PASS] vuln_creation_10k: 10k vulns in 0.168s (59528/s)
[PASS] session_serialize_1000: 1000 serializations in 0.016s (avg 0.016ms)
------------------------------------------------------------
Results: 4 passed, 0 failed
============================================================

--- STDERR ---
C:\Users\HP\OneDrive\Desktop\burp_mcp\ai-osop\scripts\qualification\test_scale.py:123: PydanticDeprecatedSince20: The `dict` method is deprecated; use `model_dump` instead. Deprecated in Pydantic V2.0 to be removed in V3.0. See Pydantic V2 Migration Guide at https://errors.pydantic.dev/2.13/migration/
  _ = session.dict()

```

---

## Certification

**QUALIFICATION PASSED** — All suites passed without failure.
