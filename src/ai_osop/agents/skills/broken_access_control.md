# Broken Access Control (BAC) Testing

## Procedures

### Step 1: Authorization Mapping
- Map all user roles and their associated permissions (RBAC/ABAC).
- Identify administrative and privileged endpoints that should be restricted.
- Document the application's intended access control matrix.

### Step 2: Horizontal Privilege Escalation
- Attempt to access or modify resources belonging to another user at the same privilege level.
- Test for IDOR in all CRUD (Create, Read, Update, Delete) operations.
- Identify parameters used to define user ownership (e.g., `user_id`, `account_no`).

### Step 3: Vertical Privilege Escalation
- Attempt to access administrative functions using a standard user account.
- Test for "Forceful Browsing" to restricted URLs (e.g., `/admin/config`).
- Audit the client-side modification of roles or scopes during authentication.

### Step 4: Logic & State Bypass
- Attempt to bypass access controls by manipulating session state or request parameters.
- Test for access control discrepancies between different interfaces (Web vs. API vs. Mobile).
- Identify and exploit flaws in multi-step workflows (e.g., bypassing a payment step).
