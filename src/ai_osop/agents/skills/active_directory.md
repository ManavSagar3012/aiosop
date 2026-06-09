# Active Directory Penetration Testing

## Procedures

### Step 1: Internal Reconnaissance
- Enumerate domain users, groups, and computers using `Net` commands or LDAP queries.
- Identify high-value targets such as Domain Admins, SQL servers, and Domain Controllers.
- Map the network layout and identify sensitive file shares (e.g., SYSVOL).

### Step 2: Credential Harvesting & Initial Access
- Perform LLMNR/NBT-NS poisoning and SMB relay attacks to capture hashes.
- Identify accounts susceptible to AS-REP Roasting (no pre-authentication required).
- Perform Kerberoasting against service accounts with Service Principal Names (SPNs).

### Step 3: Privilege Escalation
- Audit for GPO misconfigurations that allow for local admin rights or script execution.
- Search for stored credentials in scripts, configuration files, and Group Policy Preferences (GPP).
- Identify and exploit unquoted service paths or vulnerable third-party software on domain-joined machines.

### Step 4: Domain Dominance & Persistence
- Use BloodHound to identify the shortest path to Domain Admin.
- Execute DCSync attacks to extract the KRBTGT hash for Golden Ticket creation.
- Establish persistence via Skeleton Key, Silver Tickets, or malicious GPO modifications.
