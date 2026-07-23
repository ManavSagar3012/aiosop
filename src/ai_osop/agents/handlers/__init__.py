"""VulnAgent handler modules — one per task_type.

BLK-4 / MAJ-2 (2026-07-23): the 3257-line VulnAnalysisAgent monolith with its
25-branch ``if/elif task_type`` chain has been split into per-class handler
modules. Each handler is independently testable and independently measurable.

The 9 task types that already had standalone agent files (csrf, ssrf, jwt,
websocket, saml, file_upload, pollution, takeover, smuggling, race) have their
dead-code branches DELETED from vuln_agent — the scheduler routes to the
dedicated agent and the branch was unreachable.

The remaining 13 task types (burp_scan, intruder_fuzz, nuclei_scan, sqli_scan,
xss_scan, dom_xss_scan, stored_xss_scan, mass_assignment_scan,
secret_liveness_scan, ssrf_metadata_chain, oauth_reset_scan, open_redirect_scan,
nosql_scan, cache_poisoning_scan, ai_mcp_scan, correlate_findings, triage_finding)
each get a handler module here.
"""
