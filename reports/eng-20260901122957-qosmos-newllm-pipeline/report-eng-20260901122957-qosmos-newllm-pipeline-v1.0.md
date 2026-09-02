# CONFIDENTIAL / CLIENT-SENSITIVE
# Executive Summary
**Engagement ID:** eng-20260901122957-qosmos-newllm-pipeline
**Date Generated:** 2026-09-01
**Version:** v1.0

## Risk Narrative
**CLASSIFICATION: CONFIDENTIAL**

**Executive Risk Narrative — Engagement eng-20260901122957 (Qosmos NewLLM Pipeline)**

The security assessment of the Qosmos NewLLM pipeline encompassed 3 assets and 8 endpoints, yielding a total of 28 findings. The severity distribution is notably favorable: zero critical, zero high, zero medium, and zero low severity findings were identified, with all 28 observations classified as informational. From an executive risk perspective, this indicates that no immediately exploitable vulnerabilities were detected within the assessed scope during this engagement window, and the current risk posture does not present urgent remediation obligations. It should be noted, however, that the absence of higher-severity findings reflects the coverage and detection capabilities applied during this assessment cycle and should not be interpreted as an absolute guarantee of security; ongoing validation through periodic reassessment remains a prudent control.

The informational findings, while not representing active risk, constitute a meaningful hardening agenda. These include missing HTTP security headers (which degrade defense-in-depth against client-side attacks such as clickjacking and content injection), missing Subresource Integrity on referenced resources (introducing supply-chain integrity exposure for client-side content), TLS version observations warranting verification against current cryptographic standards, and detection of AWS S3 bucket storage and CloudFront services within the environment (useful attack-surface mapping intelligence). We recommend a structured hardening roadmap: implementation of standard security headers, adoption of SRI attributes, confirmation that TLS configurations align with modern protocol baselines, and continued governance of the identified cloud footprint. These low-cost measures would elevate the environment from an acceptable baseline to a demonstrably hardened posture ahead of future assessment cycles.

**CLASSIFICATION: CONFIDENTIAL**

## Assessment Overview
- **Total Assets Discovered:** 3
- **Total Endpoints Mapped:** 8
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
**Engagement ID:** eng-20260901122957-qosmos-newllm-pipeline

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
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:08:13 GMT\r\nEtag: W/\"d9c5c78857f13cbc3d349b7fa1731ea5\"\r\nLast-Modified: Tue, 01 Sep 2026 07:12:40 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 eeb60fee72923d35b96c344ca988f3aa.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 8rUbNb8GAQfmqTxn0b8SaIrf6nGpTZMcuRlnWBbsWU94wbe2NfBu3Q==\r\nX-Amz-Cf-Pop: MAA51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: O13khrio0_VViCp5_DyC3oOiYOwOBmEm\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <scrip

...[truncated 410 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `5a02e1fef01157c2f1f5f80a1eaf985bcf76b718cfcf4064ebaa899f2f264aa9`
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
[{"type": "nuclei_finding", "template": "missing-sri", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:07:35 GMT\r\nEtag: W/\"d9c5c78857f13cbc3d349b7fa1731ea5\"\r\nLast-Modified: Tue, 01 Sep 2026 07:12:40 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 a29f9f1ff42721dbcda7f3bae04962a0.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: mdLKuQFlEkzpxUEuQnOufKtDfQIohjrMgecYrRY-wr3JTSObsSvmgA==\r\nX-Amz-Cf-Pop: MAA51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: O13khrio0_VViCp5_DyC3oOiYOwOBmEm\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets

...[truncated 695 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `904936f346f2c44e138e0dd6b7742c655d045aa74e506e0246ade226ccb24f94`
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
[{"type": "nuclei_finding", "template": "aws-bucket-service", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:07:57 GMT\r\nEtag: W/\"d9c5c78857f13cbc3d349b7fa1731ea5\"\r\nLast-Modified: Tue, 01 Sep 2026 07:12:40 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 a3fb484d1976725d16c101a322c16b38.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: zh-bvN2EXms_IN5NDzQEq4AP4-QmQaCmDsNp41NS65SWt-lBAFufXQ==\r\nX-Amz-Cf-Pop: MAA51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: O13khrio0_VViCp5_DyC3oOiYOwOBmEm\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"

...[truncated 401 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `873076fb0deeddad49079988c5ccfb1c7cb2e75d41a44df223cf58e91082e733`
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
[{"type": "nuclei_finding", "template": "aws-cloudfront-service", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:07:57 GMT\r\nEtag: W/\"d9c5c78857f13cbc3d349b7fa1731ea5\"\r\nLast-Modified: Tue, 01 Sep 2026 07:12:40 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 a3fb484d1976725d16c101a322c16b38.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: zh-bvN2EXms_IN5NDzQEq4AP4-QmQaCmDsNp41NS65SWt-lBAFufXQ==\r\nX-Amz-Cf-Pop: MAA51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: O13khrio0_VViCp5_DyC3oOiYOwOBmEm\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script typ

...[truncated 405 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `edb4fd9d0fa458f5fbb99efbb481143359adb88d358be7c55eb0dd1898a7960e`
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
[{"type": "nuclei_finding", "template": "waf-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "POST / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36\r\nConnection: close\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\n_=<script>alert(1)</script>", "response": "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 1053\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html\r\nDate: Tue, 01 Sep 2026 14:04:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: CloudFront\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVia: 1.1 d2bf6e8429807ec6b44496cc5ab410ae.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: woErst67sOWp08pmN3nptCs9N0NZk7Vo-0KIyag1CDnlnRReKzXHmg==\r\nX-Amz-Cf-Pop: MAA51-P3\r\nX-Cache: Error from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<HTML><HEAD><META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=iso-8859-1\">\n<TITLE>ERROR: The request could not be satisfied</TITLE>\n</HEAD><BODY>\n<H1>403 ERROR</H1>\n<H2>The request could not be satisfied.</H2>\n<HR noshade size=\"1px\">\nThis distribution is not configured to allow the HTTP request method that was used for this request. The distribution supports only cachable requests.\nWe can't connect to the server for this app or website at this time. There might be too much traffic or a configuration error. Try again later, or contact the app or website owner.\n<BR clear=\"all\">\nIf you provide content to customers through CloudFront, you can find steps to troubleshoot and help prevent this error by reviewing the CloudFront documentation.\n<BR clear=\"all\">\n<HR noshade size=\"1px\">\n<PRE>\nGenerated by cloudfront (CloudFront)\nRequest ID: woErst67sOWp08pmN3nptCs9N0NZk7Vo-0KIyag1CDnlnRReKzXHmg==\n</PRE>\n<ADDRESS>\n</ADDRESS>\n</BODY></HTML>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:waf-detect"], "baseline_status": 200, "baseline_len": 2934}}]
```
**Artifact SHA-256 Hash**: `4b47ae334295284388e1de04c1ac9282ff070bf68bb502d0a63b8847f282a58b`
**Chain of Custody ID**: `no-audit-event`

---

### 9. Wappalyzer Technology Detection
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
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:78.0) Gecko/20100101 Firefox/78.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:07:47 GMT\r\nEtag: W/\"d9c5c78857f13cbc3d349b7fa1731ea5\"\r\nLast-Modified: Tue, 01 Sep 2026 07:12:40 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 abafbc5a94c5f59aa2cab9b9acb17d0a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: xqC7R-UIU2qenUDNxNtP76vpuSA2dyWbbo8cxvCyjHt7XzhRt-DF7w==\r\nX-Amz-Cf-Pop: MAA51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: O13khrio0_VViCp5_DyC3oOiYOwOBmEm\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-BKhQi

...[truncated 510 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `b1ef01076146d90b1432f230c2fe30ad26f93d8a8d1c1b9e9394fd0b5ae8868a`
**Chain of Custody ID**: `no-audit-event`

---

### 10. Detect Amazon-S3 Bucket
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
[{"type": "nuclei_finding", "template": "s3-detect", "matched_at": "https://qosmos.qnulabs.com/%c0", "url": "https://qosmos.qnulabs.com/", "request": "GET /%c0 HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:1.9.6.20) Gecko/ Firefox/3.6.1\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:07:51 GMT\r\nEtag: W/\"d9c5c78857f13cbc3d349b7fa1731ea5\"\r\nLast-Modified: Tue, 01 Sep 2026 07:12:40 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 ab8ea6deedbd5a43d4532a9469070864.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: QsO5YdhUeJRBaKNImVwsCCPSxxgJpecezla3XQZkresDToEugkO75A==\r\nX-Amz-Cf-Pop: MAA51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: O13khrio0_VViCp5_DyC3oOiYOwOBmEm\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-BKhQibDq.js\"></sc

...[truncated 495 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `3d007187013b49553ea647bfc2ae54d0bf11b69da51812ca35f48f73c1e22b17`
**Chain of Custody ID**: `no-audit-event`

---

### 11. Weak Content Security Policy - Detect
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
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:07:57 GMT\r\nEtag: W/\"d9c5c78857f13cbc3d349b7fa1731ea5\"\r\nLast-Modified: Tue, 01 Sep 2026 07:12:40 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 a3fb484d1976725d16c101a322c16b38.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: zh-bvN2EXms_IN5NDzQEq4AP4-QmQaCmDsNp41NS65SWt-lBAFufXQ==\r\nX-Amz-Cf-Pop: MAA51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: O13khrio0_VViCp5_DyC3oOiYOwOBmEm\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"mod

...[truncated 579 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `8ff334a3285334b92c5e9508be9c9bc47088648f3eebdefb990b82da73775443`
**Chain of Custody ID**: `no-audit-event`

---

### 12. AWS Service - Detect
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
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:08:13 GMT\r\nEtag: W/\"d9c5c78857f13cbc3d349b7fa1731ea5\"\r\nLast-Modified: Tue, 01 Sep 2026 07:12:40 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 eeb60fee72923d35b96c344ca988f3aa.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 8rUbNb8GAQfmqTxn0b8SaIrf6nGpTZMcuRlnWBbsWU94wbe2NfBu3Q==\r\nX-Amz-Cf-Pop: MAA51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: O13khrio0_VViCp5_DyC3oOiYOwOBmEm\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" c

...[truncated 545 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `99cba53b4cb702aedaa6881db81ecc11c902cdaf9916bea1388edb806aa3e6fe`
**Chain of Custody ID**: `no-audit-event`

---

### 13. DNS SaaS Service Detection
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
[{"type": "nuclei_finding", "template": "dns-saas-service-detection", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 5345\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n", "response": ";; opcode: QUERY, status: NOERROR, id: 5345\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n; EDE: 10 (RRSIGs Missing): (for DNSKEY qnulabs.com., id = 58432)\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t600\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\n", "extracted_results": ["dzvhrea2cko08.cloudfront.net"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "qosmos.qnulabs.com:80", "scoped_endpoints": ["qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `37fa4b9f5663010e904ce00c0c7c5457aff602d1af5fcadb70b48f5a2e999b72`
**Chain of Custody ID**: `no-audit-event`

---

### 14. NS Record Detection
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
[{"type": "nuclei_finding", "template": "nameserver-fingerprint", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 8627\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n", "response": ";; opcode: QUERY, status: NOERROR, id: 8627\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n; EDE: 10 (RRSIGs Missing): (for DNSKEY qnulabs.com., id = 58432)\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t600\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-1482.awsdns-57.org.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-1546.awsdns-01.co.uk.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-250.awsdns-31.com.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-877.awsdns-45.net.\n", "extracted_results": ["ns-877.awsdns-45.net.", "ns-1482.awsdns-57.org.", "ns-1546.awsdns-01.co.uk.", "ns-250.awsdns-31.com."], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "qosmos.qnulabs.com:80", "scoped_endpoints": ["qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `7bb921693b9730e4131f4561a2fbe249fcf1b99b7e145810cc6137dba6735d24`
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
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_16) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:14:18 GMT\r\nEtag: W/\"f373bcc661c03104d90c9c0f2eba6fb6\"\r\nLast-Modified: Tue, 01 Sep 2026 07:13:25 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 aa718b51992946d39cbcbf89964c8d54.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: dC5Csp1j3YuFywYykYu5qcLCmcWnAZXamm26tcIOYEaTiKSZZu_kLw==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: RV0m9RKRupsp1ZgOkL1F2IfGqhw4DZAW\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-DeMLg0-x.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `fe1a5b3858c4aa7d9246eabc5004714c6a8ceb7f88774c984b5c3032e2d3e187`
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
[{"type": "nuclei_finding", "template": "missing-sri", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:14:22 GMT\r\nEtag: W/\"f373bcc661c03104d90c9c0f2eba6fb6\"\r\nLast-Modified: Tue, 01 Sep 2026 07:13:25 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 b0862a575160d5e8ac2904d78b1688de.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: H3joR9Bjisw3ckuu1wxKDgTjb0GULcseKkx6dc9xKrgPy77yz4l8ZQ==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: RV0m9RKRupsp1ZgOkL1F2IfGqhw4DZAW\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-DeMLg0-x.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": ["https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap", "https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap"]}]
```
**Artifact SHA-256 Hash**: `5433827c877b20e2445c479a2ecb2ec084712e789b02d6e1d1316b4fad3340c7`
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
[{"type": "nuclei_finding", "template": "aws-bucket-service", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:14:15 GMT\r\nEtag: W/\"f373bcc661c03104d90c9c0f2eba6fb6\"\r\nLast-Modified: Tue, 01 Sep 2026 07:13:25 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 8ba9ea38e425686fc9c844ebae37e2c8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: bXnbUrKuK7KCG-smLnwRSmoT_KaODJXWTvwoHNcCZopIXN3C4w_VGw==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: RV0m9RKRupsp1ZgOkL1F2IfGqhw4DZAW\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-DeMLg0-x.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `054e8c58d981bb43fa4e4626b6711b6708c468d2c63634566c054401b1f3dcad`
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
[{"type": "nuclei_finding", "template": "aws-cloudfront-service", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:14:15 GMT\r\nEtag: W/\"f373bcc661c03104d90c9c0f2eba6fb6\"\r\nLast-Modified: Tue, 01 Sep 2026 07:13:25 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 8ba9ea38e425686fc9c844ebae37e2c8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: bXnbUrKuK7KCG-smLnwRSmoT_KaODJXWTvwoHNcCZopIXN3C4w_VGw==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: RV0m9RKRupsp1ZgOkL1F2IfGqhw4DZAW\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-DeMLg0-x.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `1131474e63eeb2b202185c641a7eaae374c1e412c137942f1de5614f75339458`
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
[{"type": "nuclei_finding", "template": "waf-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "POST / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.15\r\nConnection: close\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\n_=<script>alert(1)</script>", "response": "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 1053\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html\r\nDate: Tue, 01 Sep 2026 14:11:18 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: CloudFront\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVia: 1.1 b0862a575160d5e8ac2904d78b1688de.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: bDaruxnCITB70Ku2TmoSQ8TMZs2TrDqJ7ig3zmnyH40a8fz8ORV6Hg==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Cache: Error from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<HTML><HEAD><META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=iso-8859-1\">\n<TITLE>ERROR: The request could not be satisfied</TITLE>\n</HEAD><BODY>\n<H1>403 ERROR</H1>\n<H2>The request could not be satisfied.</H2>\n<HR noshade size=\"1px\">\nThis distribution is not configured to allow the HTTP request method that was used for this request. The distribution supports only cachable requests.\nWe can't connect to the server for this app or website at this time. There might be too much traffic or a configuration error. Try again later, or contact the app or website owner.\n<BR clear=\"all\">\nIf you provide content to customers through CloudFront, you can find steps to troubleshoot and help prevent this error by reviewing the CloudFront documentation.\n<BR clear=\"all\">\n<HR noshade size=\"1px\">\n<PRE>\nGenerated by cloudfront (CloudFront)\nRequest ID: bDaruxnCITB70Ku2TmoSQ8TMZs2TrDqJ7ig3zmnyH40a8fz8ORV6Hg==\n</PRE>\n<ADDRESS>\n</ADDRESS>\n</BODY></HTML>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:waf-detect", "matched_response_indistinguishable_from_catch_all_baseline"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `7fe5ba0d2f4026be484d9d34384ff510ab4e75b75e945a7ebbb5e1c136f7acbc`
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
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:14:15 GMT\r\nEtag: W/\"f373bcc661c03104d90c9c0f2eba6fb6\"\r\nLast-Modified: Tue, 01 Sep 2026 07:13:25 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 8ba9ea38e425686fc9c844ebae37e2c8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: bXnbUrKuK7KCG-smLnwRSmoT_KaODJXWTvwoHNcCZopIXN3C4w_VGw==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: RV0m9RKRupsp1ZgOkL1F2IfGqhw4DZAW\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-DeMLg0-x.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": ["frame-ancestors 'self'"], "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:weak-csp-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `c097e322b8b4f4f3a779a6fa34555fc9a52de003e8ba166d0d3e07021555bfa9`
**Chain of Custody ID**: `no-audit-event`

---

### 24. AWS Service - Detect
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
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_16) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:14:18 GMT\r\nEtag: W/\"f373bcc661c03104d90c9c0f2eba6fb6\"\r\nLast-Modified: Tue, 01 Sep 2026 07:13:25 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 aa718b51992946d39cbcbf89964c8d54.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: dC5Csp1j3YuFywYykYu5qcLCmcWnAZXamm26tcIOYEaTiKSZZu_kLw==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: RV0m9RKRupsp1ZgOkL1F2IfGqhw4DZAW\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-DeMLg0-x.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:aws-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `f07294d89749f599cadb620c77a12937390c9c4e2aa6150087763c52923ff64c`
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
[{"type": "nuclei_finding", "template": "s3-detect", "matched_at": "https://console.qosmos.qnulabs.com/%c0", "url": "https://console.qosmos.qnulabs.com/", "request": "GET /%c0 HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:14:18 GMT\r\nEtag: W/\"f373bcc661c03104d90c9c0f2eba6fb6\"\r\nLast-Modified: Tue, 01 Sep 2026 07:13:25 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 8c01bb988e27b4929e8704da99750b3e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 4PZgZNNAwsSZXQvP0GQ53aoelYUQKT4LAgShQ8KFp8zsaSYGCX2-3w==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: RV0m9RKRupsp1ZgOkL1F2IfGqhw4DZAW\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-DeMLg0-x.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:s3-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `3a3d9c8857e9d3ad81edfbd356f98f8c95fa68eb02c78dd53862da835db1cad0`
**Chain of Custody ID**: `no-audit-event`

---

### 26. Wappalyzer Technology Detection
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
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 01 Sep 2026 14:14:21 GMT\r\nEtag: W/\"f373bcc661c03104d90c9c0f2eba6fb6\"\r\nLast-Modified: Tue, 01 Sep 2026 07:13:25 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 ccb163695642c564a3fe181a890f291e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: BGUUTqu9o9TOZ_VzeiXzbRjD5MRM_DvN4ZeYL5PTZwjHjb2FnmyGfA==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: RV0m9RKRupsp1ZgOkL1F2IfGqhw4DZAW\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-DeMLg0-x.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:tech-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `62fa0e58b95fa26e22b8b7f9afaeca2fac52cea97e0bb0e76feacabde7d479a6`
**Chain of Custody ID**: `no-audit-event`

---

### 27. DNS SaaS Service Detection
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
[{"type": "nuclei_finding", "template": "dns-saas-service-detection", "matched_at": "console.qosmos.qnulabs.com", "url": "console.qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 15149\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t CNAME\n", "response": ";; opcode: QUERY, status: NOERROR, id: 15149\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 512\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t CNAME\n\n;; ANSWER SECTION:\nconsole.qosmos.qnulabs.com.\t600\tIN\tCNAME\td17s1sh6h7yidz.cloudfront.net.\n", "extracted_results": ["d17s1sh6h7yidz.cloudfront.net"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "console.qosmos.qnulabs.com:80", "scoped_endpoints": ["console.qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `a802f1168fde5fd7d3a579924a02b66d0565b5930ade1c73c412e47b134ac538`
**Chain of Custody ID**: `no-audit-event`

---

### 28. NS Record Detection
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
[{"type": "nuclei_finding", "template": "nameserver-fingerprint", "matched_at": "console.qosmos.qnulabs.com", "url": "console.qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 26452\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t NS\n", "response": ";; opcode: QUERY, status: NOERROR, id: 26452\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n; EDE: 10 (RRSIGs Missing): (for DNSKEY qnulabs.com., id = 58432)\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t NS\n\n;; ANSWER SECTION:\nconsole.qosmos.qnulabs.com.\t600\tIN\tCNAME\td17s1sh6h7yidz.cloudfront.net.\nd17s1sh6h7yidz.cloudfront.net.\t172800\tIN\tNS\tns-1037.awsdns-01.org.\nd17s1sh6h7yidz.cloudfront.net.\t172800\tIN\tNS\tns-1869.awsdns-41.co.uk.\nd17s1sh6h7yidz.cloudfront.net.\t172800\tIN\tNS\tns-407.awsdns-50.com.\nd17s1sh6h7yidz.cloudfront.net.\t172800\tIN\tNS\tns-978.awsdns-58.net.\n", "extracted_results": ["ns-1037.awsdns-01.org.", "ns-1869.awsdns-41.co.uk.", "ns-407.awsdns-50.com.", "ns-978.awsdns-58.net."], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "console.qosmos.qnulabs.com:80", "scoped_endpoints": ["console.qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `fdf3efa9c3e54bcd1536279e8f9ffea4cbbb14f1a5cfff2dc1f6055ea17dd4e7`
**Chain of Custody ID**: `no-audit-event`

---
