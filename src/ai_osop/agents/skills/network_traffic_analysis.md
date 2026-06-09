# Network Traffic Analysis (Threat Detection)

## Procedures

### Step 1: Baseline & Protocol Analysis
- Deploy Zeek or custom packet capture tools to monitor network traffic on critical segments.
- Identify and baseline normal protocol usage (HTTP, DNS, TLS, SMB, RPC).
- Analyze TLS certificates for anomalies, self-signed certificates, and expired signatures.

### Step 2: Connection & Flow Analysis
- Monitor for unusual connection patterns, such as periodic callbacks (Beaconing) to external IPs.
- Identify data exfiltration indicators by monitoring for large outbound transfers or spikes in bytes-sent.
- Track internal-to-internal (East-West) traffic to detect potential lateral movement.

### Step 3: DNS & Application Layer Inspection
- Analyze DNS logs for high-entropy subdomains (DNS Tunneling) or DGA-like patterns.
- Inspect HTTP headers and payloads for suspicious user agents, URI patterns, and encoded payloads.
- Identify unauthorized protocol usage (e.g., SSH over port 443, IRC in production zones).

### Step 4: Anomaly Correlation & Alerting
- Correlate network events with endpoint logs to identify the source of suspicious traffic.
- Map identified anomalies to MITRE ATT&CK techniques (e.g., T1071 C2, T1048 Exfiltration).
- Generate alerts for high-fidelity indicators and integrate with SIEM platforms.
