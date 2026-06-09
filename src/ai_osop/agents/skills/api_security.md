# API Security Testing (OWASP Top 10)

## Procedures

### Step 1: API Discovery & Documentation Audit
- Enumerate API endpoints using wordlists, documentation (Swagger/OpenAPI), and traffic observation.
- Identify shadow, zombie, and deprecated APIs that may lack modern security controls.
- Audit OpenAPI specifications for sensitive information disclosure or misconfigured schemas.

### Step 2: Broken Object Level Authorization (BOLA)
- Identify all endpoints that accept object IDs (e.g., `/api/users/{id}/profile`).
- Attempt to access or modify resources belonging to other users by systematically cycling through IDs.
- Test for UUID guessing if IDs are not purely incremental.

### Step 3: Authentication & Authorization (BFLA)
- Test for Broken Function Level Authorization (BFLA) by attempting to access administrative endpoints with regular user tokens.
- Audit JWT implementations for common flaws (alg:none, weak secrets, lack of signature verification).
- Check for missing authentication on sensitive endpoints (e.g., `/api/admin/export`).

### Step 4: Data Exposure & Rate Limiting
- Identify excessive data exposure where the API returns more information than the client requires.
- Test for Unrestricted Resource Consumption by hammering endpoints to identify lack of rate limiting or payload size limits.
- Audit for Unrestricted Access to Sensitive Business Logic (e.g., inventory checking, price calculations).
