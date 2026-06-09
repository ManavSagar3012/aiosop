# Container Security & Trivy Scanning

## Procedures

### Step 1: Image & Layer Analysis
- Identify the container images used in the project (Dockerfiles, Kubernetes manifests).
- Audit base images for bloatedness and presence of unnecessary packages.
- Analyze image layers for leaked secrets, hardcoded credentials, and sensitive configurations.

### Step 2: Vulnerability Scanning (Trivy)
- Execute image scans using Trivy or Grype to identify OS package and library CVEs.
- Scan the filesystem and git repositories for exposed secrets and configuration flaws.
- Audit Kubernetes manifests for misconfigurations (e.g., privileged containers, missing resource limits).

### Step 3: Runtime & Configuration Audit
- Audit for insecure Dockerfile instructions (`USER root`, `EXPOSE` sensitive ports).
- Identify containers running with excessive capabilities (e.g., `CAP_SYS_ADMIN`).
- Verify the use of read-only root filesystems and restricted volume mounts.

### Step 4: Supply Chain & Provenance
- Verify the integrity of images using signatures (e.g., `cosign`).
- Audit the use of private registries and authorized base image sources.
- Establish a "Trusted Image" policy to prevent the deployment of unvetted or vulnerable containers.
