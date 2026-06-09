# Privilege Escalation Assessment (Linux/Windows)

## Procedures

### Step 1: System Information & Environment Audit
- Identify OS version, kernel version, and installed patches to find known local exploits.
- Enumerate running processes and services, especially those running as root or SYSTEM.
- Audit environment variables (e.g., PATH) for insecurely configured or writable directories.

### Step 2: User & Permission Analysis
- Identify current user privileges and group memberships (e.g., `sudo` group, `Backup Operators`).
- Search for SUID/SGID binaries (Linux) or unquoted service paths (Windows) that can be abused.
- Audit file and directory permissions for sensitive files (e.g., `/etc/shadow`, `SAM` database).

### Step 3: Credential Harvesting & Secret Discovery
- Search for plaintext credentials in configuration files, scripts, logs, and browser databases.
- Identify SSH keys, GPG keys, and certificates stored on the filesystem.
- Extract credentials from memory (e.g., using `Mimikatz` or `gcore`) if permissions allow.

### Step 4: Misconfiguration & Service Exploitation
- Abuse misconfigured services, such as writable service binaries or insecure registry keys.
- Exploit vulnerable kernel modules or drivers using publicly available PoCs.
- Identify and exploit logical flaws, such as insecure inter-process communication (IPC).
