# Securing Kubernetes on Cloud

## Procedures

### Step 1: Cluster & Node Hardening
- Audit the API server configuration for secure access controls and TLS encryption.
- Verify that worker nodes are running a minimal, hardened OS and are regularly patched.
- Ensure that etcd is encrypted at rest and network-isolated from unauthorized access.

### Step 2: RBAC & Identity Management
- Audit Role-Based Access Control (RBAC) to ensure least privilege for users and service accounts.
- Identify and eliminate cluster-admin sprawl and broad permissions across namespaces.
- Verify integration with cloud-native identity systems (e.g., IAM Roles for Service Accounts).

### Step 3: Network & Workload Isolation
- Implement and enforce NetworkPolicies to restrict pod-to-pod and egress traffic.
- Use Pod Security Admission to enforce baseline and restricted security profiles.
- Verify that containers are running as non-root users and with restricted capabilities.

### Step 4: Monitoring & Runtime Security
- Enable and audit Kubernetes API server logs for suspicious activities.
- Use runtime security tools (e.g., Falco) to detect anomalous container behavior.
- Regularly scan container images and Kubernetes manifests for misconfigurations.
