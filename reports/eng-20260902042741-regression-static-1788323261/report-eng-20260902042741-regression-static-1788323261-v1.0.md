# CONFIDENTIAL / CLIENT-SENSITIVE
# Executive Summary
**Engagement ID:** eng-20260902042741-regression-static-1788323261
**Date Generated:** 2026-09-02
**Version:** v1.0

## Risk Narrative
**CLASSIFICATION: CONFIDENTIAL**

**Executive Risk Narrative — Engagement eng-20260902042741-regression-static-1788323261**

This engagement assessed a single asset comprising 10 endpoints, yielding 29 total findings: 2 critical, 6 high, 2 medium, 0 low, and 19 informational. The overall risk posture is driven primarily by the two critical-severity findings, both residing in the Redis infrastructure layer: an integer overflow in Redis Lua scripting (affecting versions prior to 8.2.1) and a use-after-free condition in the Redis Lua parser (affecting versions prior to 8.2.2). Memory-corruption vulnerabilities of this class in a data-tier service carry credible potential for remote code execution, denial of service, or full host compromise, and must be treated as the highest-priority remediation items. The six high-severity findings materially compound this exposure, and the aggregate of 8 critical/high findings against a relatively small attack surface indicates a concentrated, elevated risk profile that warrants executive attention and immediate remediation resources.

The high-severity findings are dominated by injection-class web vulnerabilities, most notably SQL injection via the POST parameters 'username' and 'password', identified through web audit differential analysis. Because these flaws sit directly on the authentication path, they present a credible path to authentication bypass, credential harvesting, or backend database compromise. A medium-severity cross-site scripting flaw via the GET parameter 'to' further evidences gaps in input handling on the same application surface, while the 19 informational findings, though individually lower risk, point to broader hygiene and hardening opportunities. The concentration of injection and memory-safety defects across both the application and infrastructure layers suggests a systemic input-validation and dependency-management gap rather than isolated coding errors. We recommend immediate upgrade of the affected Redis instances, remediation of the SQL injection findings through parameterized queries, output encoding to address the XSS vector, and a follow-up regression retest to verify closure before the next release cycle.

**— END OF CONFIDENTIAL NARRATIVE —**

## Assessment Overview
- **Total Assets Discovered:** 1
- **Total Endpoints Mapped:** 10
- **Critical Vulnerabilities:** 2
- **High Vulnerabilities:** 6

## Key Findings Summary

- **medium**: XSS via GET parameter 'to' (web_audit differential) (xss)

- **high**: SQLI via POST parameter 'username' (web_audit differential) (sqli)

- **high**: SQLI via POST parameter 'password' (web_audit differential) (sqli)

- **critical**: Redis < 8.2.1 lua script - Integer Overflow (rce)

- **critical**: Redis Lua Parser < 8.2.2 - Use After Free (rce)


# CONFIDENTIAL / CLIENT-SENSITIVE
# Technical Details
**Engagement ID:** eng-20260902042741-regression-static-1788323261









## A. Validated Vulnerabilities (0)


No vulnerabilities passed the validation gates this engagement.



## B. Security Hardening Items (0)


No hardening items identified.



## C. Technology & Infrastructure Observations (0)


No technology observations.

These are informational asset fingerprints (infrastructure, certificates, services).
They are attack-surface metadata, not security issues.


## D. Discarded Signals (29)



### D.1 Out of Scope (29)
The platform refused to promote these to findings because the evidence shows
the scanner touched targets outside the authorized engagement scope:

- XSS via GET parameter 'to' (web_audit differential) — matched target outside scope: unknown

- SQLI via POST parameter 'username' (web_audit differential) — matched target outside scope: unknown

- SQLI via POST parameter 'password' (web_audit differential) — matched target outside scope: unknown

- Redis < 8.2.1 lua script - Integer Overflow — matched target outside scope: unknown

- Redis Lua Parser < 8.2.2 - Use After Free — matched target outside scope: unknown

- Redis  < 8.2.1 Lua Long-String Delimiter - Out-of-Bounds Read — matched target outside scope: unknown

- Redis Lua Sandbox < 8.2.2 - Cross-User Escape — matched target outside scope: unknown

- Redis - Default Logins — matched target outside scope: unknown

- Redis Server - Unauthenticated Access — matched target outside scope: unknown

- Prometheus Metrics - Detect — matched target outside scope: unknown

- Public Swagger API - Detect — matched target outside scope: unknown

- robots.txt file — matched target outside scope: unknown

- robots.txt endpoint prober — matched target outside scope: unknown

- MySQL Info - Enumeration — matched target outside scope: unknown

- Redis Info - Detect — matched target outside scope: unknown

- SMB Version - Detection — matched target outside scope: unknown

- SMB - Enum Domains — matched target outside scope: unknown

- SMB - Enumeration — matched target outside scope: unknown

- smb2-capabilities - Enumeration — matched target outside scope: unknown

- SMB2 Server Time - Detection — matched target outside scope: unknown

- SMB Operating System - Detect — matched target outside scope: unknown

- PostgreSQL Authentication - Detect — matched target outside scope: unknown

- HTTP Missing Security Headers — matched target outside scope: unknown

- Add DOM EventListener - Detection — matched target outside scope: unknown

- Deprecated Feature-Policy Header - Detection — matched target outside scope: unknown

- OWASP Juice Shop — matched target outside scope: unknown

- X-Recruiting Header — matched target outside scope: unknown

- FingerprintHub Technology Fingerprint — matched target outside scope: unknown

- Wappalyzer Technology Detection — matched target outside scope: unknown


