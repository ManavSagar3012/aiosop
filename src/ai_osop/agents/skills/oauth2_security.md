# OAuth2 & OpenID Connect Security Testing

## Procedures

### Step 1: OAuth Flow & Scope Enumeration
- Identify the OAuth flow in use (Authorization Code, Implicit, Client Credentials, etc.).
- Enumerate requested scopes and identify overly permissive ones (e.g., `*`, `full_access`).
- Audit the client registration process for lack of verification or insecure defaults.

### Step 2: Redirect URI Manipulation
- Test for open redirects by modifying the `redirect_uri` parameter to point to an attacker-controlled domain.
- Attempt to bypass URI validation using path traversal, different subdomains, or special characters.
- Check for lack of `state` parameter or weak entropy in `state`, which allows for CSRF.

### Step 3: Authorization Code & Token Abuse
- Attempt to intercept or leak authorization codes through referer headers or logging.
- Test for Authorization Code Reuse and lack of PKCE enforcement.
- Check for token leakage in URLs, browser history, or local storage.

### Step 4: Token Validation & Scoping
- Attempt to use an access token for one service/user on a different service/user (token substitution).
- Audit for lack of audience (aud) and issuer (iss) validation in JWT-based OAuth tokens.
- Identify "Zombie Tokens" (tokens that remain valid after revocation or user logout).
