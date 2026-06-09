# API Security (OWASP Top 10)

## Workflow

### Step 1: API Mapping
- Fuzz for endpoints using `ffuf` and SecLists.
- Check for GraphQL, hidden versions (`/v1`, `/beta`).

### Step 2: Broken Object Level Auth (BOLA)
- Test IDOR across all resource endpoints.

### Step 3: Mass Assignment (BOPLA)
- Try adding `role: admin` or `is_admin: true` to JSON payloads.

### Step 4: Resource Consumption
- Test for large pagination `limit=999999` and GraphQL depth.

### Step 5: Improper Inventory
- Search for shadow/deprecated APIs.
