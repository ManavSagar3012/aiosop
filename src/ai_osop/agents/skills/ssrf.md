# SSRF Vulnerability Exploitation

## Workflow

### Step 1: Discover Injection Points
- Identify parameters accepting URLs/hostnames.

### Step 2: Cloud Metadata Probing
- AWS/GCP: `http://169.254.169.254/latest/meta-data/`
- Azure: `http://169.254.169.254/metadata/instance`

### Step 3: Internal Infrastructure
- Scan localhost: `127.0.0.1`, `0.0.0.0`.
- Scan internal subnets: `10.0.0.0/8`, `172.16.0.0/12`.

### Step 4: Protocol Handlers
- `file:///etc/passwd`, `gopher://`, `dict://`.

### Step 5: Bypass Techniques
- IP encoding, DNS rebinding, URL redirects.
