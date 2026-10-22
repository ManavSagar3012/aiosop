from ai_osop.reporting.exporters import ReportExporter


def test_sarif_export(tmp_path):
    exporter = ReportExporter(str(tmp_path))
    findings = [
        {
            "id": "vuln-001",
            "cwe": "CWE-89",
            "title": "SQL Injection in User Search",
            "description": "SQL injection identified via parameter tampering.",
            "severity": "critical",
            "cvss": 9.8,
            "endpoint": "/api/v1/users",
            "reproduction_curl": "curl -X GET 'http://target/api/v1/users?id=1%27%20OR%201=1--'",
            "evidence_hashes": ["sha256:abc123def456"],
            "merkle_root": "sha256:root789",
            "verification_status": "verified",
        },
        {
            "id": "vuln-002",
            "cwe": "CWE-200",
            "title": "Information Disclosure",
            "description": "Server header exposes version.",
            "severity": "low",
            "cvss": 3.1,
            "endpoint": "/info",
            "reproduction_curl": "curl -I http://target/info",
            "evidence_hashes": ["sha256:lowevidence"],
            "merkle_root": "sha256:rootlow",
            "verification_status": "candidate",
        },
    ]

    sarif = exporter.export_sarif(findings, engagement_id="eng-test-123")

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "AI-OSOP Security Platform"
    assert len(run["results"]) == 2

    r0 = run["results"][0]
    assert r0["ruleId"] == "CWE-89"
    assert r0["level"] == "error"
    assert r0["properties"]["finding_id"] == "vuln-001"
    assert r0["properties"]["verification_status"] == "verified"
    assert r0["properties"]["evidence_merkle_root"] == "sha256:root789"
    assert "curl" in r0["properties"]["reproduction_curl"]

    r1 = run["results"][1]
    assert r1["ruleId"] == "CWE-200"
    assert r1["level"] == "note"
    assert r1["properties"]["verification_status"] == "candidate"


def test_cyclonedx_vex_export(tmp_path):
    exporter = ReportExporter(str(tmp_path))
    findings = [
        {
            "id": "vuln-101",
            "title": "BOLA / IDOR on Orders",
            "description": "User A can view User B's orders",
            "severity": "high",
            "cvss": 8.5,
            "endpoint": "/api/v1/orders/99",
            "verification_status": "verified",
            "merkle_root": "sha256:merkle_bola_123",
            "evidence_hashes": ["sha256:req_resp_hash"],
        },
        {
            "id": "vuln-102",
            "title": "Rejected Candidate",
            "description": "Appeared vulnerable but soft-denied",
            "severity": "medium",
            "cvss": 5.0,
            "endpoint": "/api/v1/status",
            "verification_status": "rejected",
            "merkle_root": "sha256:rejected_root",
        },
    ]

    vex = exporter.export_cyclonedx_vex(
        findings, engagement_id="eng-vex-1", project_name="Acme Portal"
    )

    assert vex["bomFormat"] == "CycloneDX"
    assert vex["specVersion"] == "1.5"
    assert len(vex["vulnerabilities"]) == 2

    v0 = vex["vulnerabilities"][0]
    assert v0["id"] == "vuln-101"
    assert v0["analysis"]["state"] == "exploitable"
    assert v0["ratings"][0]["severity"] == "high"

    prop_map = {p["name"]: p["value"] for p in v0["properties"]}
    assert prop_map["evidence_merkle_root"] == "sha256:merkle_bola_123"

    v1 = vex["vulnerabilities"][1]
    assert v1["id"] == "vuln-102"
    assert v1["analysis"]["state"] == "false_positive"


def test_attestation_manifest(tmp_path):
    exporter = ReportExporter(str(tmp_path))
    report_content = b"PDF ATTED REPORT CONTENT 12345"

    # Unkeyed SHA-256
    manifest = exporter.generate_attestation_manifest(report_content)
    assert manifest["algorithm"] == "SHA-256"
    assert len(manifest["sha256"]) == 64
    assert manifest["signature"] == manifest["sha256"]
    assert manifest["byte_count"] == len(report_content)

    # Keyed HMAC-SHA256
    manifest_keyed = exporter.generate_attestation_manifest(
        report_content, authority_key="secret-roe-key"
    )
    assert manifest_keyed["algorithm"] == "HMAC-SHA256"
    assert len(manifest_keyed["signature"]) == 64
    assert manifest_keyed["signature"] != manifest_keyed["sha256"]
