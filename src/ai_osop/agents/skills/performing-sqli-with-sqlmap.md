# Skill: Performing SQL Injection with SQLMap

This skill provides instructions for utilizing `sqlmap` to validate and exploit SQL injection vulnerabilities identified by other agents.

## Methodology

1.  **Target Verification:**
    *   Accept the vulnerable URL and any associated data (POST parameters, headers).
    *   Verify the target is within the authorized scope of the engagement.

2.  **Detection Phase:**
    *   Initialize `sqlmap` with `--batch` to automate decision-making.
    *   Use `--random-agent` to evade basic pattern-based WAF signatures.
    *   Check for DBMS type and version.

3.  **Exploitation Phase:**
    *   If a vulnerability is confirmed, enumerate databases (`--dbs`).
    *   Identify the current database and user (`--current-db`, `--current-user`).
    *   If authorized, list tables for the target database.

4.  **Data Extraction (Approval Required):**
    *   For high-impact validation, dump a limited number of entries from a non-sensitive table (e.g., `products` or `config`) to provide definitive proof of concept.

## Tool Integration

```python
# API Call via SecurityBridgeAdapter
result = await security_bridge.run_sqlmap(url=vuln_url, dump=False)
```
