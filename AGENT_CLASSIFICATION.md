# Agent Classification Audit

**Date:** July 22, 2026
**Auditor:** Independent Audit (followup to AI-OSOP Audit)

---

## Executive Summary

This document classifies every agent file in `src/ai_osop/agents/` by:
- **Path:** Which code path is authoritative (dedicated agent or vuln_agent.py)
- **Quality:** Whether the implementation is GENUINE (real detection logic) or STUB (placeholder)
- **Coverage:** Whether tests exist for the agent

## Classification Key

| Category | Meaning |
|----------|---------|
| **AUTHORITATIVE** | This is the SOLE code path for this task type |
| **DUAL_AUTHORITATIVE** | Both vuln_agent.py AND a dedicated agent handle this type |
| **DEAD_DISPATCHER** | The handler in vuln_agent.py is never reached from scheduler |
| **STUB** | Minimal implementation, likely placeholder |
| **GENUINE** | Real detection logic with validation and evidence |

---

## Agent Classification Table

### A. Dedicated Agents (scheduler routes to these by AgentType)

| Agent | Lines | Task Type | Quality | Tests | Notes |
|-------|-------|-----------|---------|-------|-------|
| recon_agent.py | 57KB/1,224 | dns_enum, port_scan, service_probe, osint, tech_fingerprint, full_recon, expand_subdomains, content_discovery, openapi_ingest | **GENUINE** | Yes | Large, well-implemented recon agent |
| workflow_agent.py | 72KB/1,550 | navigate, authenticate, register, map_workflow, replay_for_diff_auth, extract_semantics, capture_session, capture_authenticated_surface, extract_har_api_inventory, run_diff_auth_analysis, map_business_logic | **GENUINE** | Yes | Large, drives Playwright automation |
| exploit_agent.py | 21KB/457 | validate_exploit, exploit_validation | **GENUINE** | Yes | Sandbox-based exploit validation |
| attack_chain_agent.py | 32KB/697 | discover_paths, account_takeover, validate_chain, propagate_risk, find_lateral_movement | **GENUINE** | Yes | Attack chain analysis |
| graphql_agent.py | 15.9KB/433 | gql_discover_schema, gql_test_authorization, gql_find_hidden, gql_batch_abuse | **GENUINE** | Yes | GraphQL security testing |
| js_analyzer_agent.py | 20.9KB/560 | analyze_js, extract_endpoints_from_js, detect_secrets_in_js | **GENUINE** | Yes | JavaScript analysis |
| mobile_agent.py | 18.8KB/488 | analyze_deep_links, intercept_mobile_traffic, test_mobile_api | **GENUINE** | Yes | Mobile app testing |
| cloud_agent.py | 12.9KB/304 | cloud scan tasks | **GENUINE** | Yes | Cloud security testing |
| stateful_logic_agent.py | 13KB/340 | map_business_process, violate_invariant, analyze_state_drift | **GENUINE** | Yes | Business logic analysis |
| visual_agent.py | 9.1KB/212 | analyze_screenshot, compare_views | **GENUINE** | Yes | Visual analysis |
| reporting_agent.py | 16.9KB/388 | generate_report, generate_yield_report, compile_evidence | **GENUINE** | Yes | Report generation |
| payload_agent.py | 9.1KB/208 | generate_payloads, mutate_payload, evolve_population, process_feedback | **STUB** | Yes | Basic payload generation |
| codeql_agent.py | 5.2KB/120 | ingest_sarif, map_sast_to_graph | **STUB** | No | SARIF ingestion, limited tests |
| concurrency_agent.py | 8.3KB/180 | test_race_condition, test_state_machine_bypass | **STUB** | No | See race_scanner instead |
| context_manager_agent.py | 6KB/130 | manage_context tasks | **STUB** | No | Context management, limited tests |
| critic_agent.py | 6.2KB/142 | review tasks | **STUB** | No | Review agent, limited tests |
| human_oversight_agent.py | 2.9KB/64 | evaluate_risk, format_approval | **STUB** | No | Minimal implementation |
| nextjs_agent.py | 2.1KB/55 | audit_server_actions, test_middleware | **STUB** | Yes | Next.js specific, small |
| react_agent.py | 3.6KB/85 | analyze_bundle, probe_components | **STUB** | No | React analysis, small |
| retrieval_agent.py | 4.5KB/105 | retrieval tasks | **STUB** | Yes | Knowledge retrieval |
| stack_profiler_agent.py | 4.1KB/97 | profile_stack | **STUB** | No | Stack profiling |
| chain_composer_agent.py | 1.4KB/36 | compose_exploit_chain | **STUB** | No | Minimal, 36 lines |

### B. Dedicated Scanner Agents (scheduler routes via specific AgentType)

These are the scanners dispatched by phase_monitor with their own AgentType.

| Agent | Lines | Task Type | Quality | Tests | Notes |
|-------|-------|-----------|---------|-------|-------|
| ssti_agent.py | 199 | ssti_scan | **GENUINE** | Yes | SSTI detection with validation |
| csrf_agent.py | 204 | csrf_scan | **GENUINE** | Yes | CSRF detection with cookie/auth logic |
| ssrf_agent.py | 109 | ssrf_scan | **GENUINE** | Yes | SSRF detection (small but has tests) |
| race_scanner.py | 113 | race_scan | **GENUINE** | Yes | Race condition detection |
| upload_scanner.py | 92 | upload_scan | **GENUINE** | Yes | File upload vulnerability |
| pollution_scanner.py | 94 | pollution_scan | **GENUINE** | Yes | Prototype pollution |
| takeover_agent.py | 82 | takeover_scan | **GENUINE** | Yes | Subdomain takeover |
| smuggling_scanner.py | 85 | smuggling_scan | **STUB** | Yes | HTTP smuggling (basic) |
| websocket_agent.py | 79 | websocket_scan | **STUB** | Yes | WebSocket testing (basic) |
| saml_agent.py | 82 | saml_scan | **STUB** | Yes | SAML testing (basic) |
| jwt_agent.py | 82 | jwt_scan | **STUB** | Yes | JWT testing (basic, real logic in vuln_agent) |

### C. Live vuln_agent.py Handlers (scheduler routes with AgentType.VULN_ANALYSIS)

| Handler | Task Type | Quality | Notes |
|---------|-----------|---------|-------|
| _execute_burp_scan | burp_scan | **GENUINE** | Full Burp Suite integration |
| _execute_intruder_fuzz | intruder_fuzz | **GENUINE** | Burp Intruder fuzzing |
| _execute_nuclei_scan | nuclei_scan | **GENUINE** | Full Nuclei integration with FP triage |
| _execute_sqli_scan | sqli_scan | **GENUINE** | Real SQLi detection via oracle + sqlmap |
| _execute_xss_scan | xss_scan | **GENUINE** | Browser-execution confirmed XSS |
| _execute_jwt_scan | jwt_scan | **GENUINE** | Real JWT forgery (alg:none, secret, kid) |
| _execute_mass_assignment_scan | mass_assignment_scan | **GENUINE** | Baseline-suppressed mass assignment |

### D. Dead vuln_agent.py Handlers (scheduler routes to dedicated agents)

These handlers in vuln_agent.py are NEVER reached from the scheduler path.
The scheduler dispatches these task types to dedicated agent files.

| Handler in vuln_agent.py | Task Type | Dispatched To |
|--------------------------|-----------|---------------|
| _execute_csrf_scan | csrf_scan | csrf_agent.py |
| _execute_ssrf_scan | ssrf_scan | ssrf_agent.py |
| _execute_subdomain_takeover_scan | subdomain_takeover_scan | takeover_agent.py |
| _execute_file_upload_scan | file_upload_scan | upload_scanner.py |
| _execute_prototype_pollution_scan | prototype_pollution_scan | pollution_scanner.py |
| _execute_websocket_scan | websocket_scan | websocket_agent.py |
| _execute_saml_scan | saml_scan | saml_agent.py |
| _execute_race_limit_scan | race_limit_scan | race_scanner.py |
| _execute_request_smuggling_scan | request_smuggling_scan | smuggling_scanner.py |

### E. Unique vuln_agent.py Handlers (no dedicated agent, may be reached from external callers)

| Handler | Task Type | Quality | Notes |
|---------|-----------|---------|-------|
| _execute_ssrf_metadata_chain | ssrf_metadata_chain | **GENUINE** | SSRF metadata probe |
| _execute_secret_liveness_scan | secret_liveness_scan | **GENUINE** | Secret verification |
| _execute_oauth_reset_scan | oauth_reset_scan | **STUB** | OAuth flow testing |
| _execute_open_redirect_scan | open_redirect_scan | **GENUINE** | Open redirect detection |
| _execute_nosql_scan | nosql_scan | **STUB** | NoSQL injection |
| _execute_cache_poisoning_scan | cache_poisoning_scan | **GENUINE** | Cache poisoning |
| _execute_ai_mcp_scan | ai_mcp_scan | **STUB** | AI MCP testing |
| _execute_stored_xss_scan | stored_xss_scan | **GENUINE** | Stored XSS |
| _execute_correlation | correlate_findings | **GENUINE** | Finding correlation |
| _execute_triage | triage_finding | **GENUINE** | Finding triage |

---

## Dual-Path Counts

| Metric | Count |
|--------|-------|
| Total agent/scanner files | 33 |
| GENUINE agents | 1
