# JWT Token Security

## Workflow

### Step 1: Decode & Analyze
- Use `jwt_tool` or base64 decode.
- Check for sensitive data in payload (PII, roles).

### Step 2: Algorithm None Attack
- Set `alg: none` in header.
- Remove signature and test for bypass.

### Step 3: Algorithm Confusion
- Switch RS256 to HS256.
- Sign with public key as secret.

### Step 4: HMAC Brute Force
- Brute-force secrets with `hashcat` (mode 16500).

### Step 5: Claim Manipulation
- Inject `kid` SQLi or path traversal.
- Host malicious JWKS for `jku` injection.
