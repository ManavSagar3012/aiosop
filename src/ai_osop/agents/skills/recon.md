# Web Application Scanning & Recon

## Procedures

### Step 1: Infrastructure Mapping
- Map all hostnames, IP addresses, and open ports.
- Identify server software and versions (banners).

### Step 2: Configuration Audit
- Check for default files (.bak, .old, .git).
- Identify exposed admin panels (/admin, /wp-admin).
- Audit HTTP methods (PUT, DELETE).

### Step 3: SSL/TLS Assessment
- Check for expired or self-signed certificates.
- Identify weak ciphers or protocols (SSLv3).

### Step 4: Vulnerability Probing
- Perform basic XSS/SQLi injection in common parameters.
- Check for missing security headers (CSP, HSTS).
