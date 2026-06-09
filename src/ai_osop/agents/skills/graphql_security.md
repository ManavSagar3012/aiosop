# GraphQL Security Assessment

## Procedures

### Step 1: Schema Discovery & Introspection
- Attempt to fetch the full API schema using introspection queries.
- Identify all available types, queries, mutations, and subscriptions.
- Map relationships between objects and identify sensitive fields (e.g., email, password, roles).

### Step 2: Authorization & Access Control
- Test for Broken Object Level Authorization (BOLA) by manipulating object IDs in queries.
- Verify if private fields are accessible through unauthorized queries or nested objects.
- Test mutations to ensure only authorized users can create, update, or delete resources.

### Step 3: Injection & Validation
- Test queries for SQL injection, NoSQL injection, and OS command injection through arguments.
- Attempt to bypass input validation by using malformed scalars or custom types.
- Check for Cross-Site Scripting (XSS) if GraphQL data is rendered in a web UI.

### Step 4: Denial of Service (DoS) Prevention
- Test for deeply nested recursive queries that could exhaust server resources.
- Attempt batching attacks by sending many queries in a single request.
- Analyze the complexity of queries and verify if the server enforces depth or cost limits.
