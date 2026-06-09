# Broken Object Level Authorization (BOLA) Testing

## Procedures

### Step 1: Resource Identifier Enumeration
- Identify all API endpoints and web pages that accept object identifiers (e.g., numeric IDs, UUIDs, slugs).
- Document the structure and format of these identifiers.
- Identify the relationship between the identifier and the authenticated user.

### Step 2: Identifier Manipulation & Fuzzing
- Systematically cycle through identifiers to attempt access to other users' objects.
- Test for predictive identifiers (e.g., `user_1001`, `user_1002`).
- Attempt to use "Special" identifiers, such as `0`, `-1`, or `null`.

### Step 3: Cross-Tenant Access Testing
- If the application is multi-tenant, attempt to access resources belonging to a different tenant.
- Audit for lack of tenant-level scoping in database queries.
- Identify parameters used for tenant identification (e.g., `tenant_id`, `org_id`).

### Step 4: Authorization Logic Audit
- Verify that authorization checks are performed on every request, not just at the start of a session.
- Audit the server-side code for "ownership validation" on resource access.
- Identify and exploit caching-related authorization bypasses.
