# External Reconnaissance & OSINT

## Procedures

### Step 1: Organizational Profiling
- Identify key personnel, email formats, and organizational structure using LinkedIn and company websites.
- Enumerate public-facing domains, IP ranges, and ASN using WHOIS and BGP data.
- Search for job postings to identify technologies used within the organization (e.g., "Looking for AWS/Kubernetes expert").

### Step 2: Information Leakage Audit
- Use Google Dorks to find sensitive files (`filetype:pdf`, `filetype:xls`, `inurl:config`, `intitle:"index of"`).
- Search for leaked credentials and internal information on paste sites (Pastebin) and GitHub.
- Audit public metadata in documents (PDF, DOCX) for usernames, internal paths, and software versions.

### Step 3: Infrastructure & Third-Party Exposure
- Identify cloud assets and SaaS platforms used by the organization (O365, Slack, Salesforce).
- Map the external attack surface using Shodan and Censys to identify forgotten or misconfigured services.
- Audit for brand impersonation and typosquatting domains targeting the organization.

### Step 4: Social Engineering Reconnaissance
- Identify potential targets for phishing and vishing based on role and public exposure.
- Gather information for believable pretexts (recent company news, partnerships, internal events).
- Audit for physical security weaknesses (office locations, badge types) if within scope.
