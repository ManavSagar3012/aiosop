# JWT Token Security (JWT Abuse)

## Procedures

### Step 1: JWT Structure & Header Analysis
- Decode the JWT to identify the header, payload, and signature.
- Analyze the header for used algorithms (alg) and key identifiers (kid).
- Check for sensitive information leaked in the payload (PII, internal IDs).

### Step 2: Signature Verification & Algorithm Attacks
- Test the `alg: none` attack by modifying the header and removing the signature.
- Attempt an HMAC-SHA256 (HS256) signature bypass if the server expects RS256 (Algorithm Confusion).
- Check for the lack of signature verification on the server-side.

### Step 3: Weak Secret & Key Management
- Brute-force the HMAC secret using common wordlists (e.g., `rockyou.txt`) if HS256 is used.
- Identify `kid` (Key ID) injection vulnerabilities (SQLi, path traversal) if the server uses `kid` to fetch keys.
- Check for public availability of the RSA public key if used for signature verification.

### Step 4: Claim Validation & Lifecycle
- Audit the `exp` (expiration) claim for lack of enforcement or excessively long lifetimes.
- Test the `nbf` (not before) and `iat` (issued at) claims for temporal anomalies.
- Check for the lack of a blacklist or revocation mechanism for compromised tokens.
