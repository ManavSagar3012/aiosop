# Securing Serverless Functions

## Procedures

### Step 1: IAM & Least Privilege
- Audit execution roles to ensure least privilege access to cloud resources (e.g., S3, DynamoDB).
- Identify and eliminate overly permissive wildcards in IAM policies.
- Verify that function-level permissions are used instead of shared account-level roles.

### Step 2: Input Validation & Event Poisoning
- Sanitize all event inputs (e.g., API Gateway, S3 triggers, SQS messages) to prevent injection.
- Test for event source poisoning where malicious data is introduced via upstream services.
- Verify that schema validation is enforced for all incoming event payloads.

### Step 3: Secrets & Sensitive Data
- Ensure no secrets or API keys are hardcoded in function source code.
- Verify integration with centralized secrets management (e.g., AWS Secrets Manager, Vault).
- Audit function logs for accidental leakage of sensitive data or PII.

### Step 4: Runtime & Dependency Security
- Scan function dependencies for known vulnerabilities using SCA tools.
- Monitor function execution for anomalous behavior (e.g., outbound network connections).
- Implement runtime protections to detect and block malicious code execution.
