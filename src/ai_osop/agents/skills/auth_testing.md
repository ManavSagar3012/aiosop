# API Authentication Weakness Testing

## Procedures

### Step 1: Authentication Mechanism Audit
- Identify all authentication methods supported (API Keys, Basic Auth, Bearer Tokens, OAuth2).
- Audit the transmission of credentials for lack of encryption (non-HTTPS).
- Check for insecure storage of credentials on the client-side (e.g., in URLs, cookies without `HttpOnly`).

### Step 2: Credential Security & Brute-Force
- Test for weak password policies and lack of complexity requirements.
- Audit the application's susceptibility to brute-force and credential stuffing attacks.
- Check for lack of rate limiting or account lockout mechanisms on authentication endpoints.

### Step 3: Token Security & Lifecycle
- Verify session token entropy and uniqueness to prevent prediction.
- Audit token expiration (TTL) and the presence of a secure revocation mechanism.
- Check for JWT-specific weaknesses (alg:none, weak secrets, lack of signature validation).

### Step 4: Multi-Factor Authentication (MFA) Audit
- Identify if MFA is enforced for sensitive operations.
- Attempt to bypass MFA using session fixation, token reuse, or response manipulation.
- Audit for lack of MFA on "forgot password" or account recovery workflows.
