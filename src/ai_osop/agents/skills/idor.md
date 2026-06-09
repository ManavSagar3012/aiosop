# IDOR Vulnerability Exploitation

## Workflow

### Step 1: Map Object References
- Identify IDs in URLs (`/api/users/101`) or bodies (`{"id": 101}`).
- Check numeric, UUID, and hashed formats.

### Step 2: Horizontal IDOR
- Access same-level user resources by changing IDs.

### Step 3: Vertical IDOR
- Access admin/elevated resources with regular token.

### Step 4: Indirect References
- Test for IDOR in headers, request bodies, and GraphQL.
