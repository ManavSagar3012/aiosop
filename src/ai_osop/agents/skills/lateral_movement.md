# Lateral Movement Detection & Execution

## Procedures

### Step 1: Post-Compromise Enumeration
- Identify the current user's privileges, group memberships, and active sessions.
- Enumerate established network connections and listening ports on the local host.
- Search for stored credentials in memory (LSASS), registry, and local files (config, history).

### Step 2: Target Selection & Reconnaissance
- Scan the internal network for accessible hosts and services (e.g., port 445 for SMB, 3389 for RDP).
- Identify high-value targets, such as Domain Controllers, file servers, and administrative workstations.
- Audit for shared credentials and "Path to Admin" using BloodHound or similar graph tools.

### Step 3: Lateral Movement Execution
- Use Pass-the-Hash (PtH) or Pass-the-Ticket (PtT) to authenticate to remote systems without plaintext passwords.
- Execute remote commands using WMI, PsExec, WinRM, or SSH if credentials/keys are available.
- Abuse DCOM or RPC services for stealthy execution and evasion of endpoint detection.

### Step 4: Persistence & Tunnelling
- Establish persistent access on lateral targets using registry run keys, scheduled tasks, or services.
- Create network tunnels (SSH tunneling, SOCKS proxy) to facilitate deeper network access.
- Perform internal pivoting to bypass firewalls and reach isolated network segments.
