# SCA Dependency Scanning (Software Composition Analysis)

## Procedures

### Step 1: Manifest & Lockfile Discovery
- Identify all package manifest files in the project (`package.json`, `requirements.txt`, `pom.xml`, `go.mod`).
- Locate associated lockfiles (`package-lock.json`, `poetry.lock`, `Gemfile.lock`) for precise versioning.
- Identify the primary programming languages and frameworks used.

### Step 2: Vulnerability Detection (Snyk/Trivy)
- Execute SCA scans using tools like Snyk, Trivy, or `pip-audit`.
- Identify direct and transitive dependencies with known CVEs.
- Correlate discovered vulnerabilities with the application's actual usage (reachability analysis).

### Step 3: License Compliance Audit
- Audit identified dependencies for restrictive or incompatible licenses (e.g., GPL, AGPL).
- Identify dependencies with missing or ambiguous license information.
- Generate a Bill of Materials (SBOM) for compliance documentation.

### Step 4: Remediation & Patching
- Prioritize vulnerabilities based on severity, exploit maturity, and potential impact.
- Identify the minimum version upgrade required to resolve identified flaws.
- Automate the generation of fix pull requests and verify compatibility through CI/CD.
