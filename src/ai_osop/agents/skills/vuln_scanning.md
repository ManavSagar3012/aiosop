# Vulnerability Scanning & Management

## Procedures

### Step 1: Target Discovery
- Define the scan scope: IP ranges, hostnames, and exclude lists.
- Perform host discovery using ICMP, ARP, and TCP/UDP probes.
- Identify live hosts and their associated operating systems.

### Step 2: Service & Version Detection
- Conduct port scans to identify open services (Nmap/Nessus).
- Perform banner grabbing and service fingerprinting to identify versions.
- Match discovered versions against known CVE databases.

### Step 3: Vulnerability Assessment
- Execute authenticated and unauthenticated scans to identify missing patches and misconfigurations.
- Audit for default credentials and weak passwords on discovered services.
- Identify SSL/TLS weaknesses and expired certificates.

### Step 4: Triage & Reporting
- Prioritize vulnerabilities based on CVSS scores and exploit availability.
- Eliminate false positives through manual verification or secondary tools.
- Generate comprehensive reports with remediation guidance for stakeholders.
