"""
Test Suite: Finding Validation Corpus & False Positive Resistance (P1.1 / P1.3 Gate)
Validates >= 95% precision on a labeled test corpus of 50 web vulnerability scenarios:
- Real IDOR & access control violations (with ownership proofs)
- Deceptive false positives (soft 200 denials, public resources, catch-all responses, out of scope)
- Hardening & fingerprint observations
"""

import pytest
from ai_osop.core.finding_validation import (
    C_VALIDATED,
    C_HARDENING,
    C_FINGERPRINT,
    C_OUT_OF_SCOPE,
    C_FALSE_POSITIVE,
    validate_finding,
)


@pytest.fixture
def scope_hosts():
    return ["api.target.com", "lab-target.local", "10.0.0.5"]


def test_validation_corpus_50_scenarios(scope_hosts):
    # Construct 50 labeled scenarios
    scenarios = []

    # 1-15: Real vulnerabilities with valid independent verification proof
    for i in range(15):
        scenarios.append(
            {
                "id": f"real-vuln-{i}",
                "title": f"BOLA / IDOR in Account Document endpoint #{i}",
                "vuln_type": "idor",
                "endpoint_id": "ep-123",
                "evidence": [
                    {
                        "request": f"GET /documents/{100 + i}",
                        "response": (
                            f'HTTP/1.0 200 OK\n\n{{"id": {100 + i}, '
                            f'"owner_id": "user_a", "secret": "data"}}'
                        ),
                        "impact": "Exposed confidential document owned by user_a to user_b",
                        "reproducible": True,
                        "differential": {
                            "baseline": {"status": 200, "user": "user_a"},
                            "attack": {"status": 200, "user": "user_b", "ownership_matched": True},
                            "delta": "Horizontal privilege escalation observed",
                        },
                    }
                ],
                "validated": True,
                "validation_authority": "diff_auth_engine",
                "validation_state": "VALIDATED",
                "target": "lab-target.local",
                "expected_class": C_VALIDATED,
            }
        )

    # 16-25: Soft Denials (HTTP 200 containing explicit denial body) -> Must NOT be C_VALIDATED
    for i in range(10):
        scenarios.append(
            {
                "id": f"soft-denial-{i}",
                "title": f"Candidate IDOR #{i}",
                "vuln_type": "idor",
                "endpoint_id": "ep-456",
                "evidence": [
                    {
                        "request": f"GET /api/user/{i}",
                        "response": (
                            "HTTP/1.1 200 OK\n\n"
                            '{"success": false, "error": "Access denied: unauthorized user"}'
                        ),
                        "reproducible": False,
                    }
                ],
                "target": "api.target.com",
                "expected_not_class": C_VALIDATED,
            }
        )

    # 26-30: Catch-All responses / WAF responses -> False Positive
    for i in range(5):
        scenarios.append(
            {
                "id": f"catch-all-{i}",
                "title": f"SQL Injection In URL Parameter #{i}",
                "vuln_type": "sqli",
                "endpoint_id": "ep-789",
                "evidence": [
                    {
                        "request": f"GET /search?q={i}'",
                        "response": "HTTP/1.1 200 OK\n\n<html>Generic error handler</html>",
                        "catch_all": True,
                    }
                ],
                "target": "api.target.com",
                "expected_class": C_FALSE_POSITIVE,
            }
        )

    # 31-35: Out of Scope Targets -> C_OUT_OF_SCOPE
    for i in range(5):
        scenarios.append(
            {
                "id": f"out-scope-{i}",
                "title": f"Git Exposure on Third Party #{i}",
                "vuln_type": "info_disclosure",
                "endpoint_id": "ep-out",
                "evidence": [
                    {
                        "request": "GET /.git/config",
                        "response": "HTTP/1.1 200 OK",
                        "out_of_scan_scope": True,
                    }
                ],
                "target": f"unauthorized-vendor-{i}.com",
                "expected_class": C_OUT_OF_SCOPE,
            }
        )

    # 36-40: Missing Security Headers claimed, but headers actually present -> C_FALSE_POSITIVE
    for i in range(5):
        scenarios.append(
            {
                "id": f"header-fp-{i}",
                "title": "Missing Security Headers",
                "vuln_type": "misconfiguration",
                "endpoint_id": "ep-hdr",
                "evidence": [
                    {
                        "request": "GET /",
                        "response": (
                            "HTTP/1.1 200 OK\n"
                            "Strict-Transport-Security: max-age=31536000\n"
                            "X-Content-Type-Options: nosniff\n"
                            "X-Frame-Options: DENY\n"
                            "Content-Security-Policy: default-src 'self'\n"
                            "Referrer-Policy: no-referrer\n"
                            "Permissions-Policy: geolocation=()\n"
                            "X-Permitted-Cross-Domain-Policies: none\n"
                            "Cross-Origin-Embedder-Policy: require-corp\n"
                            "Cross-Origin-Opener-Policy: same-origin\n"
                            "Cross-Origin-Resource-Policy: same-origin\n"
                        ),
                    }
                ],
                "target": "api.target.com",
                "expected_class": C_FALSE_POSITIVE,
            }
        )

    # 41-45: Fingerprint observations -> C_FINGERPRINT
    for i in range(5):
        scenarios.append(
            {
                "id": f"fingerprint-{i}",
                "title": f"Wappalyzer Technology Detection: Nginx #{i}",
                "vuln_type": "tech_detect",
                "endpoint_id": "ep-fp",
                "evidence": [{"request": "GET /", "response": "Server: nginx/1.24"}],
                "target": "api.target.com",
                "expected_class": C_FINGERPRINT,
            }
        )

    # 46-50: Hardening items -> C_HARDENING
    for i in range(5):
        scenarios.append(
            {
                "id": f"hardening-{i}",
                "title": f"Weak Content Security Policy #{i}",
                "vuln_type": "weak_csp",
                "endpoint_id": "ep-hard",
                "evidence": [
                    {"request": "GET /", "response": "Content-Security-Policy: unsafe-inline"}
                ],
                "target": "api.target.com",
                "expected_class": C_HARDENING,
            }
        )

    assert len(scenarios) == 50

    correct = 0
    false_promotions = 0

    for sc in scenarios:
        res = validate_finding(sc, scope_hosts=scope_hosts)
        actual_class = res.get("security_class")

        if actual_class == C_VALIDATED and "expected_not_class" in sc:
            if sc["expected_not_class"] == C_VALIDATED:
                false_promotions += 1

        is_match = False
        if "expected_class" in sc:
            if actual_class == sc["expected_class"]:
                is_match = True
        elif "expected_not_class" in sc:
            if actual_class != sc["expected_not_class"]:
                is_match = True

        if is_match:
            correct += 1

    accuracy = correct / len(scenarios)
    assert (
        false_promotions == 0
    ), f"Critical error: {false_promotions} unverified findings promoted to C_VALIDATED!"
    assert (
        accuracy >= 0.95
    ), f"Expected >= 95% precision on labeled corpus, achieved {accuracy * 100:.1f}% ({correct}/50)"
