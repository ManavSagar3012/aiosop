# Improvement Plan for AI-OSOP (P1 Issues)

## Objective
Address the critical P1 gaps identified in `3-INSPECTION_REPORT.md` to enhance the system's threat intelligence capabilities, security posture against prompt injection, and reliability through rate limiting.

## P1 Improvements Breakdown

### 1. Implement Threat Intel MCP (ISSUE-001)
- **Files**: `src/ai_osop/adapters/threat_intel_mcp.py`
- **Steps**:
    - Research NVD API and ExploitDB search mechanisms.
    - Implement the MCP server protocol for threat intelligence retrieval.
    - Expose endpoints for CVE data and ExploitDB PoCs.
    - Integrate with `VulnAnalysisAgent` to consume this data.

### 2. Implement Prompt Injection Defense (ISSUE-002)
- **Files**: `src/ai_osop/safety/prompt_defense.py`, `src/ai_osop/core/llm_client.py`
- **Steps**:
    - Research and select a prompt sanitation library (e.g., NeMo Guardrails).
    - Implement `safety/prompt_defense.py` to sanitize incoming web content.
    - Integrate `prompt_defense` into `core/llm_client.py` request flow.

### 3. Implement Rate Limiting (ISSUE-003)
- **Files**: `src/ai_osop/orchestrator/orchestrator.py`, `src/ai_osop/safety/rate_limiter.py`
- **Steps**:
    - Define Token Bucket/Leaky Bucket logic in `safety/rate_limiter.py`.
    - Modify `orchestrator/orchestrator.py` task execution loop to utilize the rate limiter before spawning agent tasks.

## Verification & Testing
- Add unit tests for each new module in `tests/`.
- Verify Threat Intel MCP endpoints using `pytest`.
- Simulate prompt injection attacks to verify defense.
- Perform load tests to verify rate limiter behavior during heavy activity.
