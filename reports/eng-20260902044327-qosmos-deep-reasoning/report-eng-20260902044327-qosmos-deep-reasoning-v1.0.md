# CONFIDENTIAL / CLIENT-SENSITIVE
# Executive Summary
**Engagement ID:** eng-20260902044327-qosmos-deep-reasoning
**Date Generated:** 2026-09-02
**Version:** v1.0

## Risk Narrative
**CLASSIFICATION: CONFIDENTIAL**

**Engagement:** eng-20260902044327-qosmos-deep-reasoning | **Scope:** 3 assets, 11 endpoints | **Total Findings:** 28

The security assessment conducted under engagement eng-20260902044327-qosmos-deep-reasoning evaluated three assets comprising eleven endpoints and produced a total of twenty-eight findings, all of which were classified at informational severity. No critical, high, medium, or low severity findings were identified within the assessed scope, indicating that the tested attack surface did not present immediately exploitable vulnerabilities under the conditions evaluated. From an executive risk perspective, this is a favorable outcome: no urgent remediation obligations, no exposure requiring incident response escalation, and no findings that suggest a compromise of confidentiality, integrity, or availability of the in-scope systems. However, leadership should interpret this result as a snapshot of the current assessment scope and methodology rather than an absolute assurance statement; the absence of higher-severity findings reflects the environment as tested and should be validated through periodic reassessment as the infrastructure evolves.

The twenty-eight informational findings, while not requiring urgent action, represent meaningful hardening opportunities that reduce residual risk and strengthen the organization's defense-in-depth posture. The detection of missing HTTP security headers suggests that protective controls such as Content-Security-Policy, Strict-Transport-Security, and X-Content-Type-Options may not be uniformly enforced, leaving the application marginally more susceptible to content injection and clickjacking techniques. Similarly, the absence of Subresource Integrity on externally loaded resources introduces a limited supply-chain integrity consideration should a third-party host be compromised. The TLS version detection finding warrants verification that only modern protocol versions are permitted, and the identification of AWS bucket storage and CloudFront services within the environment highlights cloud infrastructure whose configuration — particularly bucket access policies and CDN origin protections — should be reviewed against current best practices. We recommend incorporating these items into the next scheduled hardening cycle, with a targeted configuration review of the cloud-hosted components and a follow-up assessment to confirm closure and re-baseline the risk posture.

**CLASSIFICATION: CONFIDENTIAL**

## Assessment Overview
- **Total Assets Discovered:** 3
- **Total Endpoints Mapped:** 11
- **Critical Vulnerabilities:** 0
- **High Vulnerabilities:** 0

## Key Findings Summary

- **info**: HTTP Missing Security Headers (unknown)

- **info**: Missing Subresource Integrity (unknown)

- **info**: TLS Version - Detect (unknown)

- **info**: Detect websites using AWS bucket storage (unknown)

- **info**: AWS Cloudfront service detection (unknown)


# CONFIDENTIAL / CLIENT-SENSITIVE
# Technical Details
**Engagement ID:** eng-20260902044327-qosmos-deep-reasoning

## Verified Vulnerabilities


### 1. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:40:35 GMT\r\nEtag: W/\"bacb45c7f489406e0bea577d1133b149\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:06 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 3d6a70e0d040874e2947b442f16b4e70.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: cJCj0ZkCRAXBGv3nQikVa3uKEFrFDJcB-yfmDIa3aQqXeavMoIOuKg==\r\nX-Amz-Cf-Pop: DEL51-P6\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: J1VjaW5hcP19zM5dFfUQ6hdryzKID.6o\r\nX-Cache: RefreshHit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin

...[truncated 381 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `b149b6b6bc213a714bfd249e822c983eac84ef19d75f45b2b716ad4321804ad7`
**Chain of Custody ID**: `no-audit-event`

---

### 2. Missing Subresource Integrity
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Checks if external script and stylesheet tags in the HTML response are missing the Subresource Integrity (SRI) attribute.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "missing-sri", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:41:17 GMT\r\nEtag: W/\"bacb45c7f489406e0bea577d1133b149\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:06 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 7aa37237e11e6e6039dc11fe35425ecc.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: -Kga1Kgj3EGvcHmMvc_OqZH7BeyLKD1zp_0HYMMJo3V3q0XD5UBDFQ==\r\nX-Amz-Cf-Pop: DEL51-P6\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: J1VjaW5hcP19zM5dFfUQ6hdryzKID.6o\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"m

...[truncated 728 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `262eed45378034d095a2d03bdfbcb0e81d8adee378c0fec13cbacd0b013b5140`
**Chain of Custody ID**: `no-audit-event`

---

### 3. TLS Version - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
TLS version detection is a security process used to determine the version of the Transport Layer Security (TLS) protocol used by a computer or server.
It is important to detect the TLS version in order to ensure secure communication between two computers or servers.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tls-version", "matched_at": "qosmos.qnulabs.com:443", "url": "qosmos.qnulabs.com", "request": null, "response": null, "extracted_results": ["tls12"]}, {"type": "nuclei_finding", "template": "tls-version", "matched_at": "qosmos.qnulabs.com:443", "url": "qosmos.qnulabs.com", "request": null, "response": null, "extracted_results": ["tls13"]}]
```
**Artifact SHA-256 Hash**: `a1da5b13e32b7f5b12f93a2d02a55263278a5d9e40647b7e4069e8a6545f14f3`
**Chain of Custody ID**: `no-audit-event`

---

### 4. Detect websites using AWS bucket storage
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-bucket-service", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:1.9.7.20) Gecko/ Firefox/3.6.11\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:40:49 GMT\r\nEtag: W/\"bacb45c7f489406e0bea577d1133b149\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:06 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 4046ba0b0690630d34bcf05ad3e17f74.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: bgU6dPMOXX_Cr1iTzLC4Odnc-jGqXkgVvtFuibIh_GAGsmm1hCRBZg==\r\nX-Amz-Cf-Pop: DEL51-P6\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: J1VjaW5hcP19zM5dFfUQ6hdryzKID.6o\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-B7EC2z2L.js\">

...[truncated 346 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `0793935e91da7f8e78157eb171291b6cb75e2b41f999eef6b94fcb4c98556584`
**Chain of Custody ID**: `no-audit-event`

---

### 5. AWS Cloudfront service detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Detect websites using AWS cloudfront service

#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-cloudfront-service", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:1.9.7.20) Gecko/ Firefox/3.6.11\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:40:49 GMT\r\nEtag: W/\"bacb45c7f489406e0bea577d1133b149\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:06 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 4046ba0b0690630d34bcf05ad3e17f74.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: bgU6dPMOXX_Cr1iTzLC4Odnc-jGqXkgVvtFuibIh_GAGsmm1hCRBZg==\r\nX-Amz-Cf-Pop: DEL51-P6\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: J1VjaW5hcP19zM5dFfUQ6hdryzKID.6o\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-B7EC2z2L.j

...[truncated 350 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `d443722cc8cac964a49866a834723f3d4b099545fe9d6032fd530dac23791e31`
**Chain of Custody ID**: `no-audit-event`

---

### 6. Detect SSL Certificate Issuer
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Extract the issuer's organization from the target's certificate. Issuers are entities which sign and distribute certificates.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "ssl-issuer", "matched_at": "qosmos.qnulabs.com:443", "url": "qosmos.qnulabs.com", "request": null, "response": null, "extracted_results": ["Amazon"]}]
```
**Artifact SHA-256 Hash**: `96bfd1a2f05316561efb09df823d9133b5e4b55c795a870b44534b663d3af773`
**Chain of Custody ID**: `no-audit-event`

---

### 7. SSL DNS Names
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Extract the Subject Alternative Name (SAN) from the target's certificate. SAN facilitates the usage of additional hostnames with the same certificate.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "ssl-dns-names", "matched_at": "qosmos.qnulabs.com:443", "url": "qosmos.qnulabs.com", "request": null, "response": null, "extracted_results": ["qosmos.qnulabs.com", "console.qosmos.qnulabs.com"]}]
```
**Artifact SHA-256 Hash**: `948c7ca2459c635fbdd4b413dc8f18d850b06c2f1225d9465d2e73012a155edf`
**Chain of Custody ID**: `no-audit-event`

---

### 8. WAF Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
A web application firewall was detected.

#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "waf-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "POST / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (ZZ; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36\r\nConnection: close\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\n_=<script>alert(1)</script>", "response": "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 1053\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html\r\nDate: Wed, 02 Sep 2026 06:37:40 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: CloudFront\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVia: 1.1 389c05fcee7d9d909c44e981aec88496.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 30t7DENO2xrPkms-223tL1tfAqGRSUas3MLP85dH9Iz-I3ckqedmnw==\r\nX-Amz-Cf-Pop: DEL51-P6\r\nX-Cache: Error from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<HTML><HEAD><META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=iso-8859-1\">\n<TITLE>ERROR: The request could not be satisfied</TITLE>\n</HEAD><BODY>\n<H1>403 ERROR</H1>\n<H2>The request could not be satisfied.</H2>\n<HR noshade size=\"1px\">\nThis distribution is not configured to allow the HTTP request method that was used for this request. The distribution supports only cachable requests.\nWe can't connect to the server for this app or website at this time. There might be too much traffic or a configuration error. Try again later, or contact the app or website owner.\n<BR clear=\"all\">\nIf you provide content to customers through CloudFront, you can find steps to troubleshoot and help prevent this error by reviewing the CloudFront documentation.\n<BR clear=\"all\">\n<HR noshade size=\"1px\">\n<PRE>\nGenerated by cloudfront (CloudFront)\nRequest ID: 30t7DENO2xrPkms-223tL1tfAqGRSUas3MLP85dH9Iz-I3ckqedmnw==\n</PRE>\n<ADDRESS>\n</ADDRESS>\n</BODY></HTML>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:waf-detect"], "baseline_status": 200, "baseline_len": 2934}}]
```
**Artifact SHA-256 Hash**: `9b64684879a85e049d3fac8db7631377d570f92d01431cd1ad151bb14d48508d`
**Chain of Custody ID**: `no-audit-event`

---

### 9. AWS Service - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Detect if AWS is being used in the application.

#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:40:35 GMT\r\nEtag: W/\"bacb45c7f489406e0bea577d1133b149\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:06 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 3d6a70e0d040874e2947b442f16b4e70.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: cJCj0ZkCRAXBGv3nQikVa3uKEFrFDJcB-yfmDIa3aQqXeavMoIOuKg==\r\nX-Amz-Cf-Pop: DEL51-P6\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: J1VjaW5hcP19zM5dFfUQ6hdryzKID.6o\r\nX-Cache: RefreshHit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/inde

...[truncated 516 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `3a2e395a5ff6e62821d7742b63a318fbcc7d075b1f5cd0244f14710700dd9746`
**Chain of Custody ID**: `no-audit-event`

---

### 10. Weak Content Security Policy - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Detected misconfigured CSP directives containing unsafe and overly permissive keywords that weakened resource loading restrictions. This configuration allowed high-risk script behaviors, resulting in reduced protection against XSS attacks.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:1.9.7.20) Gecko/ Firefox/3.6.11\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:40:49 GMT\r\nEtag: W/\"bacb45c7f489406e0bea577d1133b149\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:06 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 4046ba0b0690630d34bcf05ad3e17f74.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: bgU6dPMOXX_Cr1iTzLC4Odnc-jGqXkgVvtFuibIh_GAGsmm1hCRBZg==\r\nX-Amz-Cf-Pop: DEL51-P6\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: J1VjaW5hcP19zM5dFfUQ6hdryzKID.6o\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-B7EC2z2L.js\"></s

...[truncated 524 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a5bcec871fdb00c0ffefa2d0be5a648100d9c33dec634bfb8d5636296520f09b`
**Chain of Custody ID**: `no-audit-event`

---

### 11. Wappalyzer Technology Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:41:12 GMT\r\nEtag: W/\"bacb45c7f489406e0bea577d1133b149\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:06 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 d0a577b9f8d7db1f14de308059fcd518.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: ahSCLq5rDTFogt3vWrO-AHOf70gwroAjpFXyhzJFpIVn8ELdHzbaBg==\r\nX-Amz-Cf-Pop: DEL51-P6\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: J1VjaW5hcP19zM5dFfUQ6hdryzKID.6o\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\

...[truncated 557 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `4f2e01ddc5a6078a0e403e73c3e22b422cb81783ee5e1770c0d13e8884c2fac4`
**Chain of Custody ID**: `no-audit-event`

---

### 12. Detect Amazon-S3 Bucket
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "s3-detect", "matched_at": "https://qosmos.qnulabs.com/%c0", "url": "https://qosmos.qnulabs.com/", "request": "GET /%c0 HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:41:22 GMT\r\nEtag: W/\"bacb45c7f489406e0bea577d1133b149\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:06 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 2ccb5c74843a981956109951c6465318.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: hfhFA4UdPAGsgcjG2Pkb7IV8RHnr7iQQq1pnh-ovV7gnJirE_C-oLg==\r\nX-Amz-Cf-Pop: DEL51-P6\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: J1VjaW5hcP19zM5dFfUQ6hdryzKID.6o\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/i

...[truncated 518 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `0e0810b801504e93a25fbf03686e0a3c055f2d57e8a6f0abdf3f1f0b7fdf7146`
**Chain of Custody ID**: `no-audit-event`

---

### 13. NS Record Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
An NS record was detected. An NS record delegates a subdomain to a set of name servers.

#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "nameserver-fingerprint", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 22969\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n", "response": ";; opcode: QUERY, status: NOERROR, id: 22969\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 512\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t600\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-1546.awsdns-01.co.uk.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-877.awsdns-45.net.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-1482.awsdns-57.org.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-250.awsdns-31.com.\n", "extracted_results": ["ns-1546.awsdns-01.co.uk.", "ns-877.awsdns-45.net.", "ns-1482.awsdns-57.org.", "ns-250.awsdns-31.com."], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "qosmos.qnulabs.com:80", "scoped_endpoints": ["qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `7e62eaa5f66584250509e6ac743d9d27fd66590433d807b9fa33b8e8aeb2b26a`
**Chain of Custody ID**: `no-audit-event`

---

### 14. DNS SaaS Service Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
A CNAME DNS record was discovered

#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "dns-saas-service-detection", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 54772\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n", "response": ";; opcode: QUERY, status: NOERROR, id: 54772\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n; EDE: 10 (RRSIGs Missing): (for DNSKEY qnulabs.com., id = 58432)\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t600\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\n", "extracted_results": ["dzvhrea2cko08.cloudfront.net"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "qosmos.qnulabs.com:80", "scoped_endpoints": ["qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `d1940aa0b064ca6c0a64485914c22e51678eb441ba68d059164e4b1ae40fda68`
**Chain of Custody ID**: `no-audit-event`

---

### 15. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:50:17 GMT\r\nEtag: W/\"4bce326d5c648f46d7e54026f5b287be\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:50 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 10c5a528558b3f3ec50565fb90c4da76.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: Kb4SpfK4D4LyDTLQwBy87jGLcMBFhowVn2LHKF6Yw9yovIBpK_XqWA==\r\nX-Amz-Cf-Pop: MRS53-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 7YTuZWHer..j1JGby6JIk_e_IIJfIE3a\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-0tTg5-UT.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CGwIMOIx.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `22650d920f1272f4db36b2ef58dd8350ee3e91b1e54ea31661fdbdd99fc2a4d0`
**Chain of Custody ID**: `no-audit-event`

---

### 16. Missing Subresource Integrity
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Checks if external script and stylesheet tags in the HTML response are missing the Subresource Integrity (SRI) attribute.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "missing-sri", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:48:35 GMT\r\nEtag: W/\"4bce326d5c648f46d7e54026f5b287be\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:50 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 4a557a877fe1a4451716e444419fc1c4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: hoK2JJZXJRzQogag6JqcgbD5zXkhLrYSr-iOf8GPajipaJ_i7uV0Wg==\r\nX-Amz-Cf-Pop: MRS53-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 7YTuZWHer..j1JGby6JIk_e_IIJfIE3a\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-0tTg5-UT.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CGwIMOIx.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": ["https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap", "https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap"]}]
```
**Artifact SHA-256 Hash**: `c501b2e7f2db11007ca5bdc6d98bbd3ffda016563121ba707cabfb235a0d6476`
**Chain of Custody ID**: `no-audit-event`

---

### 17. TLS Version - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
TLS version detection is a security process used to determine the version of the Transport Layer Security (TLS) protocol used by a computer or server.
It is important to detect the TLS version in order to ensure secure communication between two computers or servers.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tls-version", "matched_at": "console.qosmos.qnulabs.com:443", "url": "console.qosmos.qnulabs.com", "request": null, "response": null, "extracted_results": ["tls12"]}, {"type": "nuclei_finding", "template": "tls-version", "matched_at": "console.qosmos.qnulabs.com:443", "url": "console.qosmos.qnulabs.com", "request": null, "response": null, "extracted_results": ["tls13"]}]
```
**Artifact SHA-256 Hash**: `987a58d7c8653b7cce1ad620e752e3f80b1b940f3ed4b1812cfa90a386c1a0dc`
**Chain of Custody ID**: `no-audit-event`

---

### 18. Detect websites using AWS bucket storage
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-bucket-service", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; WebView/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:48:19 GMT\r\nEtag: W/\"4bce326d5c648f46d7e54026f5b287be\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:50 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 a97e77b4c0c3924b6b8061855eed731a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: chjXauB-KgvyL63dIjPq9zTL35s-503ro7I5Od1rJTfP_-_SYeAuaQ==\r\nX-Amz-Cf-Pop: MRS53-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 7YTuZWHer..j1JGby6JIk_e_IIJfIE3a\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-0tTg5-UT.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CGwIMOIx.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `e2963385734d43a9554f1dfe13619cc3416d1297d50ee38865fff84b62bb1d5e`
**Chain of Custody ID**: `no-audit-event`

---

### 19. AWS Cloudfront service detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Detect websites using AWS cloudfront service

#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-cloudfront-service", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; WebView/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:48:19 GMT\r\nEtag: W/\"4bce326d5c648f46d7e54026f5b287be\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:50 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 a97e77b4c0c3924b6b8061855eed731a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: chjXauB-KgvyL63dIjPq9zTL35s-503ro7I5Od1rJTfP_-_SYeAuaQ==\r\nX-Amz-Cf-Pop: MRS53-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 7YTuZWHer..j1JGby6JIk_e_IIJfIE3a\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-0tTg5-UT.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CGwIMOIx.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `bdb92b1d04ecc6dea7452f7b59badc38909e1ffd53292ae58ce90db905d41528`
**Chain of Custody ID**: `no-audit-event`

---

### 20. Detect SSL Certificate Issuer
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Extract the issuer's organization from the target's certificate. Issuers are entities which sign and distribute certificates.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "ssl-issuer", "matched_at": "console.qosmos.qnulabs.com:443", "url": "console.qosmos.qnulabs.com", "request": null, "response": null, "extracted_results": ["Amazon"]}]
```
**Artifact SHA-256 Hash**: `6edd165fe8c81ac0addd1ec0458186fa7dc2a036465e7bb8a364240e5bb3d86a`
**Chain of Custody ID**: `no-audit-event`

---

### 21. SSL DNS Names
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Extract the Subject Alternative Name (SAN) from the target's certificate. SAN facilitates the usage of additional hostnames with the same certificate.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "ssl-dns-names", "matched_at": "console.qosmos.qnulabs.com:443", "url": "console.qosmos.qnulabs.com", "request": null, "response": null, "extracted_results": ["qosmos.qnulabs.com", "console.qosmos.qnulabs.com"]}]
```
**Artifact SHA-256 Hash**: `2f8d9817d5e1ab14eaab7c6ddc2cb5f7cd94e97583b7591be2cea99d17cc2537`
**Chain of Custody ID**: `no-audit-event`

---

### 22. WAF Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
A web application firewall was detected.

#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "waf-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "POST / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0\r\nConnection: close\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\n_=<script>alert(1)</script>", "response": "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 1053\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html\r\nDate: Wed, 02 Sep 2026 06:44:28 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: CloudFront\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVia: 1.1 bed126d6f8ff1ad6bb93d4a49c5567b0.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: zUjY0DqLJhtkpwxdb7Mx8svL6swy0gVThStDJlN4BrBzYKmeLXzqQg==\r\nX-Amz-Cf-Pop: MRS53-P1\r\nX-Cache: Error from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<HTML><HEAD><META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=iso-8859-1\">\n<TITLE>ERROR: The request could not be satisfied</TITLE>\n</HEAD><BODY>\n<H1>403 ERROR</H1>\n<H2>The request could not be satisfied.</H2>\n<HR noshade size=\"1px\">\nThis distribution is not configured to allow the HTTP request method that was used for this request. The distribution supports only cachable requests.\nWe can't connect to the server for this app or website at this time. There might be too much traffic or a configuration error. Try again later, or contact the app or website owner.\n<BR clear=\"all\">\nIf you provide content to customers through CloudFront, you can find steps to troubleshoot and help prevent this error by reviewing the CloudFront documentation.\n<BR clear=\"all\">\n<HR noshade size=\"1px\">\n<PRE>\nGenerated by cloudfront (CloudFront)\nRequest ID: zUjY0DqLJhtkpwxdb7Mx8svL6swy0gVThStDJlN4BrBzYKmeLXzqQg==\n</PRE>\n<ADDRESS>\n</ADDRESS>\n</BODY></HTML>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:waf-detect", "matched_response_indistinguishable_from_catch_all_baseline"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `5139685a847076ed3153642c552d55d369a1ee0143db70680e23e571336d5dc6`
**Chain of Custody ID**: `no-audit-event`

---

### 23. Weak Content Security Policy - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Detected misconfigured CSP directives containing unsafe and overly permissive keywords that weakened resource loading restrictions. This configuration allowed high-risk script behaviors, resulting in reduced protection against XSS attacks.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; WebView/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:48:19 GMT\r\nEtag: W/\"4bce326d5c648f46d7e54026f5b287be\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:50 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 a97e77b4c0c3924b6b8061855eed731a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: chjXauB-KgvyL63dIjPq9zTL35s-503ro7I5Od1rJTfP_-_SYeAuaQ==\r\nX-Amz-Cf-Pop: MRS53-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 7YTuZWHer..j1JGby6JIk_e_IIJfIE3a\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-0tTg5-UT.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CGwIMOIx.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": ["frame-ancestors 'self'"], "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:weak-csp-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `15eb764e903eb96ab0b0973e1d066b5c7164b8d40582590101a8877b5d4042e2`
**Chain of Custody ID**: `no-audit-event`

---

### 24. Wappalyzer Technology Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.2; rv:140.0) Gecko/20100101 Firefox/140.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:48:36 GMT\r\nEtag: W/\"4bce326d5c648f46d7e54026f5b287be\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:50 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 58ca16e6d47a8a5b398b40d6ef8d996a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 5EOwpELfRbYhoMxA9xFV83EfUwIh_HTlQgQW9E1-isQ8-ylKYxnTgw==\r\nX-Amz-Cf-Pop: MRS53-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 7YTuZWHer..j1JGby6JIk_e_IIJfIE3a\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-0tTg5-UT.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CGwIMOIx.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:tech-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `a1455fc586a1351000b114dcecdb401b15533ccc160ef88ad2ce40709ce48dd1`
**Chain of Custody ID**: `no-audit-event`

---

### 25. Detect Amazon-S3 Bucket
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "s3-detect", "matched_at": "https://console.qosmos.qnulabs.com/%c0", "url": "https://console.qosmos.qnulabs.com/", "request": "GET /%c0 HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Kubuntu; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:49:41 GMT\r\nEtag: W/\"4bce326d5c648f46d7e54026f5b287be\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:50 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 885f60dd355c44f5842663fc7e3ceea6.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: TYrL3X8ZvH20OL4rSpgt9xsuvCNspn5qjBSSwmMDnMgmvGHNk4OUbQ==\r\nX-Amz-Cf-Pop: MRS53-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 7YTuZWHer..j1JGby6JIk_e_IIJfIE3a\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-0tTg5-UT.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CGwIMOIx.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:s3-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `832ff3a3d5cc6de95de54f2f9e5adb87cbd5a56c627f39baea724a446b952439`
**Chain of Custody ID**: `no-audit-event`

---

### 26. AWS Service - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Detect if AWS is being used in the application.

#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Wed, 02 Sep 2026 06:50:17 GMT\r\nEtag: W/\"4bce326d5c648f46d7e54026f5b287be\"\r\nLast-Modified: Tue, 01 Sep 2026 16:52:50 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 10c5a528558b3f3ec50565fb90c4da76.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: Kb4SpfK4D4LyDTLQwBy87jGLcMBFhowVn2LHKF6Yw9yovIBpK_XqWA==\r\nX-Amz-Cf-Pop: MRS53-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 7YTuZWHer..j1JGby6JIk_e_IIJfIE3a\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-0tTg5-UT.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CGwIMOIx.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:aws-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `6cde997def56b4f3e3818332b16ab9c71db9ed4507eb31a0e7dfa6b957df3acb`
**Chain of Custody ID**: `no-audit-event`

---

### 27. NS Record Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
An NS record was detected. An NS record delegates a subdomain to a set of name servers.

#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "nameserver-fingerprint", "matched_at": "console.qosmos.qnulabs.com", "url": "console.qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 62504\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t NS\n", "response": ";; opcode: QUERY, status: NOERROR, id: 62504\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 512\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t NS\n\n;; ANSWER SECTION:\nconsole.qosmos.qnulabs.com.\t600\tIN\tCNAME\td17s1sh6h7yidz.cloudfront.net.\nd17s1sh6h7yidz.cloudfront.net.\t21600\tIN\tNS\tns-978.awsdns-58.net.\nd17s1sh6h7yidz.cloudfront.net.\t21600\tIN\tNS\tns-1037.awsdns-01.org.\nd17s1sh6h7yidz.cloudfront.net.\t21600\tIN\tNS\tns-407.awsdns-50.com.\nd17s1sh6h7yidz.cloudfront.net.\t21600\tIN\tNS\tns-1869.awsdns-41.co.uk.\n", "extracted_results": ["ns-978.awsdns-58.net.", "ns-1037.awsdns-01.org.", "ns-407.awsdns-50.com.", "ns-1869.awsdns-41.co.uk."], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "console.qosmos.qnulabs.com:80", "scoped_endpoints": ["console.qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `86b7059414af3f35cfad5e0b185ce592cca7a20f8b43a97057a35d6fca10bad3`
**Chain of Custody ID**: `no-audit-event`

---

### 28. DNS SaaS Service Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
A CNAME DNS record was discovered

#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "dns-saas-service-detection", "matched_at": "console.qosmos.qnulabs.com", "url": "console.qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 13839\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t CNAME\n", "response": ";; opcode: QUERY, status: NOERROR, id: 13839\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n; EDE: 10 (RRSIGs Missing): (for DNSKEY qnulabs.com., id = 58432)\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t CNAME\n\n;; ANSWER SECTION:\nconsole.qosmos.qnulabs.com.\t600\tIN\tCNAME\td17s1sh6h7yidz.cloudfront.net.\n", "extracted_results": ["d17s1sh6h7yidz.cloudfront.net"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "console.qosmos.qnulabs.com:80", "scoped_endpoints": ["console.qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `a2bcf9fe50c2b2bdc63003c375ae99ad0586830e41d6f81acd1e5166f6ba8eea`
**Chain of Custody ID**: `no-audit-event`

---
