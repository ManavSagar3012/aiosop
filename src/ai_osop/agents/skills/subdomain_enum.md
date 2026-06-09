# Subdomain Enumeration (Attack Surface Mapping)

## Procedures

### Step 1: Passive Enumeration
- Query search engines (Google, Bing, DuckDuckGo) using `site:` operators to find indexed subdomains.
- Analyze Certificate Transparency (CT) logs using tools like `crt.sh` or `certspotter`.
- Use passive DNS databases and aggregators (VirusTotal, SecurityTrails, Shodan).

### Step 2: Active Enumeration
- Perform DNS zone transfers (`AXFR`) against target name servers to identify misconfigurations.
- Use DNS brute-forcing with high-quality wordlists and permutation generation.
- Perform DNS cache snooping to identify domains frequently resolved by internal users.

### Step 3: Infrastructure Verification
- Resolve discovered subdomains to IP addresses and identify associated hosting providers (AWS, Cloudflare, etc.).
- Identify "Dead" subdomains (subdomains that point to non-existent cloud resources) for potential Subdomain Takeover.
- Map the relationship between subdomains and their associated IP ranges and ASN.

### Step 4: Vulnerability Filtering
- Identify development, staging, and UAT environments which often lack production-level security.
- Scan for open ports and services on discovered IPs to prioritize further testing.
- Identify subdomains with sensitive names (e.g., `vpn.`, `dev-api.`, `internal.`, `jenkins.`).
