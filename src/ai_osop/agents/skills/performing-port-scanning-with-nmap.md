# Skill: Performing Port Scanning with Nmap

This skill provides instructions for utilizing `nmap` for service discovery, version detection, and port scanning.

## Methodology

1.  **Host Discovery:**
    *   Perform a fast scan to identify live hosts in the scoped network.
    *   Exclude any restricted IPs or domains.

2.  **Service Enumeration:**
    *   Identify open ports and the services running on them.
    *   Perform version detection (`-sV`) to identify specific software versions.
    *   Identify the operating system if possible.

3.  **Vulnerability Correlation:**
    *   Correlate found service versions with the Threat Intel MCP to identify known CVEs.

## Tool Integration

```python
# API Call via SecurityBridgeAdapter
assets = await security_bridge.run_nmap(target=ip_or_host, fast=True)
```
