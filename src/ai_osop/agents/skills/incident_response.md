# Security Incident Triage & Response

## Procedures

### Step 1: Initial Detection & Classification
- Identify and validate suspicious activity using SIEM alerts and endpoint telemetry.
- Classify the incident by type (e.g., malware, unauthorized access, data theft).
- Assign an initial severity level based on business impact and data sensitivity.

### Step 2: Containment & Isolation
- Implement short-term containment to stop the immediate threat (e.g., isolating a host).
- Revoke compromised credentials and block malicious network connections.
- Perform long-term containment, such as network segmentation or firewall rule updates.

### Step 3: Investigation & Forensic Analysis
- Collect volatile evidence (e.g., memory, network state) before it is lost.
- Perform deep-dive analysis of system logs, artifact files, and malware samples.
- Reconstruct the attack timeline and identify the root cause and extent of compromise.

### Step 4: Eradication, Recovery & Post-Incident
- Systematically remove malware and persistent artifacts from affected systems.
- Restore systems from verified clean backups and validate against re-infection.
- Facilitate post-incident reviews to document lessons learned and improve future response.
