# CONFIDENTIAL / CLIENT-SENSITIVE
# Executive Summary
**Engagement ID:** eng-20260831073142-qosmos-full-auth
**Date Generated:** 2026-08-31
**Version:** v1.0

## Risk Narrative
**CONFIDENTIAL**

**Executive Risk Narrative — Engagement eng-20260831073142-qosmos-full-auth**

The assessment covered one in-scope asset across three identified endpoints, producing a total of fourteen findings. Notably, the results contained no Critical, High, Medium, or Low severity issues; all fourteen findings were classified as Informational. From a risk perspective, this indicates that the assessed environment did not exhibit exploitable vulnerabilities or material configuration weaknesses during the testing window, and the overall residual risk to the business from this scope is currently assessed as low. Executive stakeholders should interpret this as a favorable security posture for the tested surface at this point in time, while recognizing that an informational-only profile reflects the depth and scope of this engagement rather than a guarantee of absence of risk.

While none of the findings represent immediate threat exposure, the informational items collectively point to defense-in-depth hardening opportunities that are worth addressing as part of routine security hygiene. These include the absence of recommended HTTP security headers, missing Subresource Integrity (SRI) attributes on loaded resources, and detectable TLS version information, alongside identification of the environment's reliance on AWS S3 bucket storage and CloudFront content delivery. Individually, each of these is low impact; collectively, they can incrementally expand attack surface or reduce resilience against client-side attacks such as content injection and protocol downgrade scenarios over time. We recommend tracking these items in the remediation backlog, prioritizing security header implementation and SRI adoption as quick wins, and re-assessing the environment periodically—particularly after infrastructure or CDN configuration changes—to ensure the current low-risk posture is maintained.

## Assessment Overview
- **Total Assets Discovered:** 1
- **Total Endpoints Mapped:** 3
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
**Engagement ID:** eng-20260831073142-qosmos-full-auth

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
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) ConnectPC Safari/537.36 Browser\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 07:46:41 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 c8efc826694be10245262237f60d9356.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: nJg3cqrU0qfB18u-92tfQPQt41JUmgU9JElr5rMa8yTQGJaLVetFig==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"mod

...[truncated 398 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a630c0375b18c90441ab059095356fed98e644e228d575a008adf8079928b989`
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
[{"type": "nuclei_finding", "template": "missing-sri", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 07:46:08 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 677944308fd1609f92564a7dd6155d3a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: sKz3ZEeqITe12iTEczq2iaO2wSXU2KH3H2xVeDIcpFNNIReMXXG_Dw==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"mo

...[truncated 727 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `40008159fbe2adfa03b0f116d6325769859ce5d1ad882be3b4b1dbcda20fc482`
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
[{"type": "nuclei_finding", "template": "aws-bucket-service", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.8\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 07:46:27 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 c8efc826694be10245262237f60d9356.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: lbUVGDxPfZQeG5tOC6KXRKz5vaqE_GWa9KO8eTkxNXii2Qg2jddNZw==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/ass

...[truncated 370 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `53d792600eba4a71b0b116194af63415f41e2cd7f4367f6e884a87bab0e65ea2`
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
[{"type": "nuclei_finding", "template": "aws-cloudfront-service", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.8\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 07:46:27 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 c8efc826694be10245262237f60d9356.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: lbUVGDxPfZQeG5tOC6KXRKz5vaqE_GWa9KO8eTkxNXii2Qg2jddNZw==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"

...[truncated 374 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `bc5323f9ef09a7d9cb5436c6ab9320ffe135657776c2ad02967144aa096987dd`
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
[{"type": "nuclei_finding", "template": "ssl-dns-names", "matched_at": "qosmos.qnulabs.com:443", "url": "qosmos.qnulabs.com", "request": null, "response": null, "extracted_results": ["console.qosmos.qnulabs.com", "qosmos.qnulabs.com"]}]
```
**Artifact SHA-256 Hash**: `acdfcd00f2bd5bb27ecb026653188ae409ae97fa91f75027ad1ad0c2b87b8e68`
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
[{"type": "nuclei_finding", "template": "waf-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "POST / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11) AppleWebKit/601.1.27 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/601.1.27\r\nConnection: close\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\n_=<script>alert(1)</script>", "response": "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 1053\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html\r\nDate: Mon, 31 Aug 2026 07:43:18 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: CloudFront\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVia: 1.1 2b3ab58ed924be93a90ce05215a5fa06.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: fAgcfmIMnLy6JGVLKSuVgZh06EglMQ3Td-JITsgD2ZojdEs7c495Mg==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Cache: Error from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<HTML><HEAD><META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=iso-8859-1\">\n<TITLE>ERROR: The request could not be satisfied</TITLE>\n</HEAD><BODY>\n<H1>403 ERROR</H1>\n<H2>The request could not be satisfied.</H2>\n<HR noshade size=\"1px\">\nThis distribution is not configured to allow the HTTP request method that was used for this request. The distribution supports only cachable requests.\nWe can't connect to the server for this app or website at this time. There might be too much traffic or a configuration error. Try again later, or contact the app or website owner.\n<BR clear=\"all\">\nIf you provide content to customers through CloudFront, you can find steps to troubleshoot and help prevent this error by reviewing the CloudFront documentation.\n<BR clear=\"all\">\n<HR noshade size=\"1px\">\n<PRE>\nGenerated by cloudfront (CloudFront)\nRequest ID: fAgcfmIMnLy6JGVLKSuVgZh06EglMQ3Td-JITsgD2ZojdEs7c495Mg==\n</PRE>\n<ADDRESS>\n</ADDRESS>\n</BODY></HTML>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:waf-detect"], "baseline_status": 200, "baseline_len": 2934}}]
```
**Artifact SHA-256 Hash**: `7851306b009559b089a21d72b9e54d0078b7c4c7d6dfd1ae8c7e1feff1910719`
**Chain of Custody ID**: `no-audit-event`

---

### 9. Detect Amazon-S3 Bucket
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
[{"type": "nuclei_finding", "template": "s3-detect", "matched_at": "https://qosmos.qnulabs.com/%c0", "url": "https://qosmos.qnulabs.com/", "request": "GET /%c0 HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 07:46:16 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 ae32fd87bf2e0f90ef9d9827402cd17e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: WZ4XvMEUFIMMmRhGus29bz5Ba1I90S3LasvxBQhSG21IYNdcDJbG1Q==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" cros

...[truncated 541 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `bc5d8acc5f94113d1c3c6575871c99f84c682d1c0b006918c05b87ef385681e9`
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
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.8\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 07:46:27 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 c8efc826694be10245262237f60d9356.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: lbUVGDxPfZQeG5tOC6KXRKz5vaqE_GWa9KO8eTkxNXii2Qg2jddNZw==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets

...[truncated 548 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `98440c3e7be978eb6a1a1c5505415725815967329216f91f5a7f274cb171e21e`
**Chain of Custody ID**: `no-audit-event`

---

### 11. AWS Service - Detect
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
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) ConnectPC Safari/537.36 Browser\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 07:46:41 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 c8efc826694be10245262237f60d9356.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: nJg3cqrU0qfB18u-92tfQPQt41JUmgU9JElr5rMa8yTQGJaLVetFig==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin s

...[truncated 533 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `b99501377fcccd11355fa5e436d2a60b7497689add7b8d2d1d72744f4072f9f4`
**Chain of Custody ID**: `no-audit-event`

---

### 12. Wappalyzer Technology Detection
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
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 07:46:41 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 ae32fd87bf2e0f90ef9d9827402cd17e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: B5SOFcM58_W5k3P33bqmg8cnO9vBnPqc5TEn1UfowQlMFmtSNvQOPg==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"m

...[truncated 555 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `b2cac58f5b2d2f84761367ff224ec42cae953bae7ae4a6e2a147302731b4f159`
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
[{"type": "nuclei_finding", "template": "dns-saas-service-detection", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 63614\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n", "response": ";; opcode: QUERY, status: NOERROR, id: 63614\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n; EDE: 10 (RRSIGs Missing): (for DNSKEY qnulabs.com., id = 58432)\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t600\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\n", "extracted_results": ["dzvhrea2cko08.cloudfront.net"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "qosmos.qnulabs.com:80", "scoped_endpoints": ["qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `4009432db80c06e6752f425b5a094b014c70c43af4070d8baa22c59cb03812a1`
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
[{"type": "nuclei_finding", "template": "nameserver-fingerprint", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 24040\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n", "response": ";; opcode: QUERY, status: NOERROR, id: 24040\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n; EDE: 10 (RRSIGs Missing): (for DNSKEY qnulabs.com., id = 58432)\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t600\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-1482.awsdns-57.org.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-1546.awsdns-01.co.uk.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-250.awsdns-31.com.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-877.awsdns-45.net.\n", "extracted_results": ["ns-1482.awsdns-57.org.", "ns-1546.awsdns-01.co.uk.", "ns-250.awsdns-31.com.", "ns-877.awsdns-45.net."], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "qosmos.qnulabs.com:80", "scoped_endpoints": ["qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `d5a7209908341f87da5ba29c1ec3da8228365f3599787910a53cdca6497af155`
**Chain of Custody ID**: `no-audit-event`

---
