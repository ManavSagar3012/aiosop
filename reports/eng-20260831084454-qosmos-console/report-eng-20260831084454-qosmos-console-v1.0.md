# CONFIDENTIAL / CLIENT-SENSITIVE
# Executive Summary
**Engagement ID:** eng-20260831084454-qosmos-console
**Date Generated:** 2026-08-31
**Version:** v1.0

## Risk Narrative
**CONFIDENTIAL**

**Executive Risk Narrative — Engagement eng-20260831084454-qosmos-console**

The security assessment of the Qosmos console asset identified a total of 28 findings, all classified as informational in severity. No critical, high, medium, or low severity vulnerabilities were confirmed during this engagement, indicating that the assessed asset does not present evidence of immediately exploitable weaknesses or material risk requiring urgent remediation. The informational findings are concentrated in areas of web application hardening and configuration hygiene, including the absence of recommended HTTP security headers (such as Content-Security-Policy and Strict-Transport-Security), missing Subresource Integrity attributes on loaded scripts, and TLS version detection results. While none of these constitute vulnerabilities on their own, they represent gaps against industry hardening baselines that could increase exposure if combined with future defects or changes in the threat landscape.

From a strategic perspective, the findings also illuminate the asset's cloud footprint, with detections confirming the use of AWS bucket storage and AWS CloudFront as the delivery mechanism. This is consistent with a modern, managed infrastructure posture, though it underscores the importance of maintaining rigorous cloud configuration governance — including bucket access policies, CDN security settings, and header enforcement at the edge — as the primary control surface for this asset. We recommend that the organization treat the 28 informational findings as a defense-in-depth roadmap: implementing security headers and Subresource Integrity are low-effort, high-value improvements that reduce the blast radius of potential client-side attacks, and periodic re-assessment is advised to ensure the posture remains stable as the console evolves. Overall, the current risk posture of the assessed asset is assessed as low, with no findings requiring executive escalation at this time.

---
*Classification: CONFIDENTIAL — Distribution restricted to engagement stakeholders.*

## Assessment Overview
- **Total Assets Discovered:** 1
- **Total Endpoints Mapped:** 0
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
**Engagement ID:** eng-20260831084454-qosmos-console

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
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 08:57:03 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 58ae4e39408a6d0a576d70c9f855b9e4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: DN5VM8sP_w2TUZ18NrWHSx5_PRo-AHzUuY-IFlyXDDr2XQAh9aoAZw==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n

...[truncated 418 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `f3e699774b2dae6ea74c06d2f938adf5a5b1f27b9326364bacd09a31a5f0936f`
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
[{"type": "nuclei_finding", "template": "missing-sri", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.5\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 08:56:52 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 a422243977730e4226bf3bb970b6f900.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: jkXTehw1GDe8d1CqfT8P7fBjmYOW7D-oOz2RYHKvyoKf45lnXay2Lw==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-BfWKxZb

...[truncated 681 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `3069544440949af83c3c9fd09d680354677eb16f13e4304d25810ae77d2b9f3c`
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
[{"type": "nuclei_finding", "template": "aws-bucket-service", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 08:56:43 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 677944308fd1609f92564a7dd6155d3a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 2x17oPQ0voml04aL4EPgQxxAmXbWvSQT5WsdK5Dddo18mQgSGLSJgQ==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script typ

...[truncated 405 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a21cf680e67dd5c9e5b00f24a03ffd50af261240a054f52387ec7901f1ea0fb0`
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
[{"type": "nuclei_finding", "template": "aws-cloudfront-service", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 08:56:43 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 677944308fd1609f92564a7dd6155d3a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 2x17oPQ0voml04aL4EPgQxxAmXbWvSQT5WsdK5Dddo18mQgSGLSJgQ==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script

...[truncated 409 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `4417eb5072f37bab1f4c1cf3bcdb60a9f90997ffc2d79f80cb69d1c991c647e4`
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
[{"type": "nuclei_finding", "template": "waf-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "POST / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/15.4 Safari/537.36\r\nConnection: close\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\n_=<script>alert(1)</script>", "response": "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 1053\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html\r\nDate: Mon, 31 Aug 2026 08:53:58 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: CloudFront\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVia: 1.1 e4295438197bf68d0320eda27ae28684.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 90zW8vI0sm_WpYxHLE8AGA3lU2J4j9wJzPra1hrrz_55DzjX4Upq_Q==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Cache: Error from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<HTML><HEAD><META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=iso-8859-1\">\n<TITLE>ERROR: The request could not be satisfied</TITLE>\n</HEAD><BODY>\n<H1>403 ERROR</H1>\n<H2>The request could not be satisfied.</H2>\n<HR noshade size=\"1px\">\nThis distribution is not configured to allow the HTTP request method that was used for this request. The distribution supports only cachable requests.\nWe can't connect to the server for this app or website at this time. There might be too much traffic or a configuration error. Try again later, or contact the app or website owner.\n<BR clear=\"all\">\nIf you provide content to customers through CloudFront, you can find steps to troubleshoot and help prevent this error by reviewing the CloudFront documentation.\n<BR clear=\"all\">\n<HR noshade size=\"1px\">\n<PRE>\nGenerated by cloudfront (CloudFront)\nRequest ID: 90zW8vI0sm_WpYxHLE8AGA3lU2J4j9wJzPra1hrrz_55DzjX4Upq_Q==\n</PRE>\n<ADDRESS>\n</ADDRESS>\n</BODY></HTML>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:waf-detect"], "baseline_status": 200, "baseline_len": 2934}}]
```
**Artifact SHA-256 Hash**: `4e20889c8b24e605963b84be693ff276271d50b0afffd361f72fdf39be9df077`
**Chain of Custody ID**: `no-audit-event`

---

### 9. Weak Content Security Policy - Detect
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
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 08:56:43 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 677944308fd1609f92564a7dd6155d3a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 2x17oPQ0voml04aL4EPgQxxAmXbWvSQT5WsdK5Dddo18mQgSGLSJgQ==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\

...[truncated 583 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `9e06381ff295a76095d43eadd6db1316dd74157c0a6c82d6d72f796b35295d6e`
**Chain of Custody ID**: `no-audit-event`

---

### 10. Wappalyzer Technology Detection
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
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 08:56:56 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 9b9a018decad95c15ed845eed6156ac4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 9Cz1XSgsChmAseAa6ZLbL5IrDzFmNYLqN5EKaQthE154Dt_7tDnLSQ==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" cr

...[truncated 545 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `fb59894047edff7b35f05ef61d9d1cb51b2857bc5ec2a8e3ebf88a29ab69130c`
**Chain of Custody ID**: `no-audit-event`

---

### 11. Detect Amazon-S3 Bucket
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
[{"type": "nuclei_finding", "template": "s3-detect", "matched_at": "https://qosmos.qnulabs.com/%c0", "url": "https://qosmos.qnulabs.com/", "request": "GET /%c0 HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.2; rv:140.0.) Gecko/20100101 Firefox/140.0.\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 08:57:02 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 88ead6d8e1c453e4323dff19e8e052dc.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: ncQVQBOI6QQgrifQqwi0PmexhawuvA5_BbKeF5Gwh6in1mm-DaonBg==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-BfWK

...[truncated 509 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `f50bff9f829a6a9685fda9169c3bed6762009c9114b4f89395a1125f4eb53e87`
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
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 08:57:03 GMT\r\nEtag: W/\"ddd64413f55fd19977f1a0e8cfe114df\"\r\nLast-Modified: Thu, 27 Aug 2026 07:01:26 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 58ae4e39408a6d0a576d70c9f855b9e4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: DN5VM8sP_w2TUZ18NrWHSx5_PRo-AHzUuY-IFlyXDDr2XQAh9aoAZw==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: 6I.ZEXeC5nZuiqfIpuiT1ZPfvJ91e2Gi\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"mo

...[truncated 553 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `b46232bd19534c5147a5cd4a850b9296fcb4674dccc2a26bf3e3907e1a28aeb8`
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
[{"type": "nuclei_finding", "template": "nameserver-fingerprint", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 36886\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n", "response": ";; opcode: QUERY, status: NOERROR, id: 36886\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 512\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t314\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-1546.awsdns-01.co.uk.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-250.awsdns-31.com.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-877.awsdns-45.net.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-1482.awsdns-57.org.\n", "extracted_results": ["ns-1546.awsdns-01.co.uk.", "ns-250.awsdns-31.com.", "ns-877.awsdns-45.net.", "ns-1482.awsdns-57.org."], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "qosmos.qnulabs.com:80", "scoped_endpoints": ["qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `83758486fa9fad0cb96a4b7c137cc50965122fa6d0983f8cb22657176b1f707e`
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
[{"type": "nuclei_finding", "template": "dns-saas-service-detection", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 40786\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n", "response": ";; opcode: QUERY, status: NOERROR, id: 40786\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 512\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t599\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\n", "extracted_results": ["dzvhrea2cko08.cloudfront.net"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "qosmos.qnulabs.com:80", "scoped_endpoints": ["qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `91feb66183530c498ba2c710e4902b5a40a13d0cd8926fbfe41167be96b3e771`
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
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 09:01:27 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 e44070691669fda7111d97fca7fa71ea.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: K4mMu9YZQ9erRIXeB-bP4DVFuAtFBKJzF1oMANGfVDlEDB_TOh1feQ==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `c16e6da04c871bf4159ae39b7f22044f2fd6ad91992397c7a4c590e0d817d19e`
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
[{"type": "nuclei_finding", "template": "missing-sri", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 09:01:52 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 ccb163695642c564a3fe181a890f291e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: mGuHuVs8DSz1Q1kz7cg7co1nC4nwVEuBI2BttiPJV3Zd9uypNNU98w==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": ["https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap", "https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap"]}]
```
**Artifact SHA-256 Hash**: `af3833871959fd1e49afab1890efb075315f58e7cedecc6df3c81230549ea36d`
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
[{"type": "nuclei_finding", "template": "aws-bucket-service", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 09:01:39 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 7ed0f11cd9e6d93d10fc13ad67472fba.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: wALNjCSUVHaJ6hnRdogC2n55wkAR5BBFaICD3X8l_2akXTUcWUOWHw==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `d95bc5262583e7cdccb31cf2ecc45aa307505bbcd00e1d7cb8bcc74e0c9e6206`
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
[{"type": "nuclei_finding", "template": "aws-cloudfront-service", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 09:01:39 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 7ed0f11cd9e6d93d10fc13ad67472fba.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: wALNjCSUVHaJ6hnRdogC2n55wkAR5BBFaICD3X8l_2akXTUcWUOWHw==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `078af565a494eed9945b9b9a6d519fb41f4d423d895375b1eb42522129de3025`
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
[{"type": "nuclei_finding", "template": "ssl-dns-names", "matched_at": "console.qosmos.qnulabs.com:443", "url": "console.qosmos.qnulabs.com", "request": null, "response": null, "extracted_results": ["console.qosmos.qnulabs.com", "qosmos.qnulabs.com"]}]
```
**Artifact SHA-256 Hash**: `67929b7260dc0ab58193663327c53a89afbe91f25cd17b304d6e3ef98fa0d91d`
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
[{"type": "nuclei_finding", "template": "waf-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "POST / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh, Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15\r\nConnection: close\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\n_=<script>alert(1)</script>", "response": "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 1053\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html\r\nDate: Mon, 31 Aug 2026 08:58:35 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: CloudFront\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVia: 1.1 ba6f9394ac9da7a0725d181cca442332.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: pbX5xf6_18w_FLKAY7unJVB2JHMyjcW0dhnlbYW1QsEvTHWxUQFTww==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Cache: Error from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<HTML><HEAD><META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=iso-8859-1\">\n<TITLE>ERROR: The request could not be satisfied</TITLE>\n</HEAD><BODY>\n<H1>403 ERROR</H1>\n<H2>The request could not be satisfied.</H2>\n<HR noshade size=\"1px\">\nThis distribution is not configured to allow the HTTP request method that was used for this request. The distribution supports only cachable requests.\nWe can't connect to the server for this app or website at this time. There might be too much traffic or a configuration error. Try again later, or contact the app or website owner.\n<BR clear=\"all\">\nIf you provide content to customers through CloudFront, you can find steps to troubleshoot and help prevent this error by reviewing the CloudFront documentation.\n<BR clear=\"all\">\n<HR noshade size=\"1px\">\n<PRE>\nGenerated by cloudfront (CloudFront)\nRequest ID: pbX5xf6_18w_FLKAY7unJVB2JHMyjcW0dhnlbYW1QsEvTHWxUQFTww==\n</PRE>\n<ADDRESS>\n</ADDRESS>\n</BODY></HTML>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:waf-detect", "matched_response_indistinguishable_from_catch_all_baseline"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `16047120d9200addc8fc20355d390fd70ccab48443511580913d8da8f7cebc12`
**Chain of Custody ID**: `no-audit-event`

---

### 23. AWS Service - Detect
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
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 09:01:27 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 e44070691669fda7111d97fca7fa71ea.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: K4mMu9YZQ9erRIXeB-bP4DVFuAtFBKJzF1oMANGfVDlEDB_TOh1feQ==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:aws-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `3363e1928ff183f699555c5345fbbc00bc70a723629b47625847deab9c0c5ab2`
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
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 09:01:31 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 ba3b49bb8e3b79790364c0eb5cd21ab8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: BCQsV0ll8nnoUSXs0aurKb8JUsuRjKjsGZZUuYNLJFjctigspKsAPg==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:tech-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `3523e2c03d042ade6ca1064d3960e61164d1622491335eb121bad1366956b4e8`
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
[{"type": "nuclei_finding", "template": "s3-detect", "matched_at": "https://console.qosmos.qnulabs.com/%c0", "url": "https://console.qosmos.qnulabs.com/", "request": "GET /%c0 HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 09:01:34 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 098f2d53656d4f3f90dbbcb090ba0150.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: -6DknrP-VdTVbAJ_h9RIEAeEsrWs9toGVl4mVu_385mJOA5hY-tMWg==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:s3-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `65445504eca527dcff743331577c226bc408c57af455618b37a2e824ec280a86`
**Chain of Custody ID**: `no-audit-event`

---

### 26. Weak Content Security Policy - Detect
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
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 09:01:39 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 7ed0f11cd9e6d93d10fc13ad67472fba.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: wALNjCSUVHaJ6hnRdogC2n55wkAR5BBFaICD3X8l_2akXTUcWUOWHw==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": ["frame-ancestors 'self'"], "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:weak-csp-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `65bf026fff38435d40aebfd7d80aaa51e92855a758c94f097261749b10266eef`
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
[{"type": "nuclei_finding", "template": "dns-saas-service-detection", "matched_at": "console.qosmos.qnulabs.com", "url": "console.qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 36294\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t CNAME\n", "response": ";; opcode: QUERY, status: NOERROR, id: 36294\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 512\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t CNAME\n\n;; ANSWER SECTION:\nconsole.qosmos.qnulabs.com.\t352\tIN\tCNAME\td17s1sh6h7yidz.cloudfront.net.\n", "extracted_results": ["d17s1sh6h7yidz.cloudfront.net"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "console.qosmos.qnulabs.com:80", "scoped_endpoints": ["console.qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `0475caaecb339d0c9ed49fdbdbcbb8875c606eaf1d04a8f50cb70dac414e7817`
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
[{"type": "nuclei_finding", "template": "nameserver-fingerprint", "matched_at": "console.qosmos.qnulabs.com", "url": "console.qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 24397\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t NS\n", "response": ";; opcode: QUERY, status: NOERROR, id: 24397\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n; EDE: 10 (RRSIGs Missing): (for DNSKEY qnulabs.com., id = 58432)\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t NS\n\n;; ANSWER SECTION:\nconsole.qosmos.qnulabs.com.\t600\tIN\tCNAME\td17s1sh6h7yidz.cloudfront.net.\nd17s1sh6h7yidz.cloudfront.net.\t172800\tIN\tNS\tns-1037.awsdns-01.org.\nd17s1sh6h7yidz.cloudfront.net.\t172800\tIN\tNS\tns-1869.awsdns-41.co.uk.\nd17s1sh6h7yidz.cloudfront.net.\t172800\tIN\tNS\tns-407.awsdns-50.com.\nd17s1sh6h7yidz.cloudfront.net.\t172800\tIN\tNS\tns-978.awsdns-58.net.\n", "extracted_results": ["ns-1037.awsdns-01.org.", "ns-1869.awsdns-41.co.uk.", "ns-407.awsdns-50.com.", "ns-978.awsdns-58.net."], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "console.qosmos.qnulabs.com:80", "scoped_endpoints": ["console.qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `142ed98d6cb36cb55460ec35b97bac713b0646dd708a510e56971815984c6a30`
**Chain of Custody ID**: `no-audit-event`

---
