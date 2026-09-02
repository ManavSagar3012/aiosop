# CONFIDENTIAL / CLIENT-SENSITIVE
# Executive Summary
**Engagement ID:** eng-20260831190145-qosmos-authconsole-audit
**Date Generated:** 2026-08-31
**Version:** v1.0

## Risk Narrative
**CONFIDENTIAL**

# Executive Risk Narrative — Qosmos Auth Console Security Assessment
**Engagement Reference:** eng-20260831190145-qosmos-authconsole-audit

---

The security assessment of the Qosmos authentication console environment encompassed two in-scope assets and seven identified network endpoints, producing a total of 37 findings. Notably, the assessment surfaced no findings at the Critical, High, Medium, or Low severity tiers; all 37 observations were classified as Informational. From a residual risk perspective, this indicates that the assessment methodology did not identify exploitable vulnerabilities, misconfigurations with direct security impact, or conditions requiring urgent remediation within the assessed scope. The absence of elevated-severity findings suggests a sound baseline security posture for the authentication console and its supporting infrastructure at the time of testing.

While the findings carry no immediate risk rating, their thematic composition warrants attention as part of ongoing hardening efforts. The observations cluster around four areas: missing HTTP security response headers (e.g., content security and transport security controls), the absence of Subresource Integrity protections on third-party resources, TLS version detection across endpoints, and detection of AWS S3 bucket storage and CloudFront content delivery services in use. Individually, these are not vulnerabilities; collectively, they represent a reduction in defense-in-depth and an increase in the environmental visibility available to a prospective adversary conducting reconnaissance. Given the authentication console's role as an identity assurance touchpoint, we recommend the organization track these items as a hardening backlog — prioritizing security header implementation and subresource integrity on user-facing endpoints — and incorporate them into the next configuration review cycle rather than treating them as remediation-urgent work.

---

**CONFIDENTIAL** — Distribution restricted to engagement stakeholders and authorized security personnel.

## Assessment Overview
- **Total Assets Discovered:** 2
- **Total Endpoints Mapped:** 7
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
**Engagement ID:** eng-20260831190145-qosmos-authconsole-audit

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
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:08:04 GMT\r\nEtag: W/\"6a2fd3835fb33e220d402d551a383be7\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:07 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 858e093a81e040a22e5ad8df08a476f4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: J5ZXI--yjtBqTh8k-TC8HYX14GvplVXwVftZdutAEFHPzF2EH_o7tg==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: QdIZuVP41ejxpQWvQo2IU4MQwrHk_SN8\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index

...[truncated 361 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `d4ab02848b2ed8215dd62c5b10595125ffd197f9338ccb23e625b3d11ed2570f`
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
[{"type": "nuclei_finding", "template": "missing-sri", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux i686; rv:1.9.5.20) Gecko/ Firefox/3.6.17\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:07:45 GMT\r\nEtag: W/\"6a2fd3835fb33e220d402d551a383be7\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:07 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 7c2e3497eab88620d1c48081581e768c.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: os18IVg5GBUuKyKWeAyzAIT0SWsvxRGtguQfm-kgvdmo8a-67Wzs9g==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: QdIZuVP41ejxpQWvQo2IU4MQwrHk_SN8\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-CdcMO1Un.js\"></script>

...[truncated 665 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `3f25fd7abbedb136aa3961860523f6bb3a2b494e0008136f761de9f6c4951fbe`
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
[{"type": "nuclei_finding", "template": "aws-bucket-service", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:07:35 GMT\r\nEtag: W/\"6a2fd3835fb33e220d402d551a383be7\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:07 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 2f82407142437ea3fdcb3ad82224118e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: vaqX5gH3xpL1P69tVgdu594I7Cx2HD15ro3LsWodBqL1A3GLPcK_7w==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: QdIZuVP41ejxpQWvQo2IU4MQwrHk_SN8\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script ty

...[truncated 406 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `c49a6829e3db5538e1bca2dbd5681fd7e3d0ebf8c2fde1a3f898449e9bc5286d`
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
[{"type": "nuclei_finding", "template": "aws-cloudfront-service", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:07:35 GMT\r\nEtag: W/\"6a2fd3835fb33e220d402d551a383be7\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:07 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 2f82407142437ea3fdcb3ad82224118e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: vaqX5gH3xpL1P69tVgdu594I7Cx2HD15ro3LsWodBqL1A3GLPcK_7w==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: QdIZuVP41ejxpQWvQo2IU4MQwrHk_SN8\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <scrip

...[truncated 410 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a72d6995249ed88f1f0e3f6666a9ef2cc8f98f2d31f4c816ce5e05114d57b6a0`
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
[{"type": "nuclei_finding", "template": "waf-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "POST / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36\r\nConnection: close\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\n_=<script>alert(1)</script>", "response": "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 1053\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html\r\nDate: Mon, 31 Aug 2026 19:04:42 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: CloudFront\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVia: 1.1 c8efc826694be10245262237f60d9356.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: TSbhzZGiZgwDYLJwAYSVZNoLl0KRDeZJGwjqH3y-I2ShSSyBFRbs_w==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Cache: Error from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<HTML><HEAD><META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=iso-8859-1\">\n<TITLE>ERROR: The request could not be satisfied</TITLE>\n</HEAD><BODY>\n<H1>403 ERROR</H1>\n<H2>The request could not be satisfied.</H2>\n<HR noshade size=\"1px\">\nThis distribution is not configured to allow the HTTP request method that was used for this request. The distribution supports only cachable requests.\nWe can't connect to the server for this app or website at this time. There might be too much traffic or a configuration error. Try again later, or contact the app or website owner.\n<BR clear=\"all\">\nIf you provide content to customers through CloudFront, you can find steps to troubleshoot and help prevent this error by reviewing the CloudFront documentation.\n<BR clear=\"all\">\n<HR noshade size=\"1px\">\n<PRE>\nGenerated by cloudfront (CloudFront)\nRequest ID: TSbhzZGiZgwDYLJwAYSVZNoLl0KRDeZJGwjqH3y-I2ShSSyBFRbs_w==\n</PRE>\n<ADDRESS>\n</ADDRESS>\n</BODY></HTML>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:waf-detect"], "baseline_status": 200, "baseline_len": 2934}}]
```
**Artifact SHA-256 Hash**: `e43592c55b2963ca26cba556fbd364d10929f33c6cb1e99d9c2bc73d79e31bdb`
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
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:07:35 GMT\r\nEtag: W/\"6a2fd3835fb33e220d402d551a383be7\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:07 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 2f82407142437ea3fdcb3ad82224118e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: vaqX5gH3xpL1P69tVgdu594I7Cx2HD15ro3LsWodBqL1A3GLPcK_7w==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: QdIZuVP41ejxpQWvQo2IU4MQwrHk_SN8\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=

...[truncated 584 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a46d20ab4d67f894d888e791380f65e5cf1e25805c6e34b74c23853c2b38fa41`
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
[{"type": "nuclei_finding", "template": "s3-detect", "matched_at": "https://qosmos.qnulabs.com/%c0", "url": "https://qosmos.qnulabs.com/", "request": "GET /%c0 HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Fedora; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:07:48 GMT\r\nEtag: W/\"6a2fd3835fb33e220d402d551a383be7\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:07 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 58ae4e39408a6d0a576d70c9f855b9e4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: cJOsrSDnxGt9lVYzIq4ft7QJ_zICf-dANvOihGS6rUjUXmUoQ8K27Q==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: QdIZuVP41ejxpQWvQo2IU4MQwrHk_SN8\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" cro

...[truncated 542 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `3caf3bc57a041b40fa8a919077cafab798646a2b02f78a05cf3468c272514f03`
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
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:08:04 GMT\r\nEtag: W/\"6a2fd3835fb33e220d402d551a383be7\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:07 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 858e093a81e040a22e5ad8df08a476f4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: J5ZXI--yjtBqTh8k-TC8HYX14GvplVXwVftZdutAEFHPzF2EH_o7tg==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: QdIZuVP41ejxpQWvQo2IU4MQwrHk_SN8\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-CdcMO1Un.js\"></sc

...[truncated 496 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `69869ad431b7585c2e3859ef82a5ef67454f54b4f421d8bc3d16a92fcc71320d`
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
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:08:08 GMT\r\nEtag: W/\"6a2fd3835fb33e220d402d551a383be7\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:07 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 3de19640cfebf523522177e2f7051db8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: YwcyV8ppBEEI7i2vxZ6Px1VluEqpOpGED9_SqJZ7TDTQFdtpPhCeEA==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: QdIZuVP41ejxpQWvQo2IU4MQwrHk_SN8\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-CdcMO1U

...[truncated 508 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `2b10f27dc6f0fa38535e6d57b9ed68ee3b5f427784fa54d4d6e1216e384f7200`
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
[{"type": "nuclei_finding", "template": "dns-saas-service-detection", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 51360\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n", "response": ";; opcode: QUERY, status: NOERROR, id: 51360\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 512\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t600\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\n", "extracted_results": ["dzvhrea2cko08.cloudfront.net"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "qosmos.qnulabs.com:80", "scoped_endpoints": ["qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `3e3bf377e84605f06fb5136aefe01b10c4149d6f699173e8d065d938a5d1b116`
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
[{"type": "nuclei_finding", "template": "nameserver-fingerprint", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 36182\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n", "response": ";; opcode: QUERY, status: NOERROR, id: 36182\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n; EDE: 10 (RRSIGs Missing): (for DNSKEY qnulabs.com., id = 58432)\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t600\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-1482.awsdns-57.org.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-1546.awsdns-01.co.uk.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-250.awsdns-31.com.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-877.awsdns-45.net.\n", "extracted_results": ["ns-250.awsdns-31.com.", "ns-877.awsdns-45.net.", "ns-1482.awsdns-57.org.", "ns-1546.awsdns-01.co.uk."], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "qosmos.qnulabs.com:80", "scoped_endpoints": ["qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `8e06575068cfe01650be90aa466286191d81226a5522c9c338928cd5b13b1ee0`
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
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Knoppix; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:15:39 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 43b154ec7ecff79d396132662af9c9a4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 3UTGc5fZEumeXEMB-r67yCIA2JMmK06Eao8j2XAvGsvFwjODO42_4A==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `10ec8834a73cd69e62d5ca7ef3f34d40d8feb8c40efec02dc9042ffab2cb1388`
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
[{"type": "nuclei_finding", "template": "missing-sri", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:15:39 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 416707a2d89685fb7e540ca52534b2bc.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 58uddOqT0cvUBE9FgBIfTPfkyR5EzurxWuY0bYdrt1x7pQIjIJY4mQ==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": ["https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap", "https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap"]}]
```
**Artifact SHA-256 Hash**: `4267e0555e92e28156145cc3431d2fda7fa6b32d6106b78ce313db23cf0dff93`
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
[{"type": "nuclei_finding", "template": "aws-bucket-service", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:14:55 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 8ba9ea38e425686fc9c844ebae37e2c8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: _UDntklTOjIe8Y0KTggG4vbmzlgq1N5AuYuD6QSmqraiPQd1upfC2A==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `b7b2a79d861f37dd049d9a2670d788c566aa604433e8342a07619e5d60084cf7`
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
[{"type": "nuclei_finding", "template": "aws-cloudfront-service", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:14:55 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 8ba9ea38e425686fc9c844ebae37e2c8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: _UDntklTOjIe8Y0KTggG4vbmzlgq1N5AuYuD6QSmqraiPQd1upfC2A==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `d644e3c594c2bed146ad2ae34f99a065ebcc89899a7d8afae135374d70ea766e`
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
[{"type": "nuclei_finding", "template": "waf-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "POST / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0.1 Safari/605.1.15\r\nConnection: close\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\n_=<script>alert(1)</script>", "response": "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 1053\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html\r\nDate: Mon, 31 Aug 2026 19:11:27 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: CloudFront\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVia: 1.1 ba3b49bb8e3b79790364c0eb5cd21ab8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: BwwPPRRp-J70Qnmon-PitXQKDqha3qYTzJSOO3stLamkrwR8i0yV5w==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Cache: Error from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<HTML><HEAD><META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=iso-8859-1\">\n<TITLE>ERROR: The request could not be satisfied</TITLE>\n</HEAD><BODY>\n<H1>403 ERROR</H1>\n<H2>The request could not be satisfied.</H2>\n<HR noshade size=\"1px\">\nThis distribution is not configured to allow the HTTP request method that was used for this request. The distribution supports only cachable requests.\nWe can't connect to the server for this app or website at this time. There might be too much traffic or a configuration error. Try again later, or contact the app or website owner.\n<BR clear=\"all\">\nIf you provide content to customers through CloudFront, you can find steps to troubleshoot and help prevent this error by reviewing the CloudFront documentation.\n<BR clear=\"all\">\n<HR noshade size=\"1px\">\n<PRE>\nGenerated by cloudfront (CloudFront)\nRequest ID: BwwPPRRp-J70Qnmon-PitXQKDqha3qYTzJSOO3stLamkrwR8i0yV5w==\n</PRE>\n<ADDRESS>\n</ADDRESS>\n</BODY></HTML>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:waf-detect", "matched_response_indistinguishable_from_catch_all_baseline"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `50dc9a549dc90e4cdc3e729c61dd99c6e40e417c747024c462ee332338d8974a`
**Chain of Custody ID**: `no-audit-event`

---

### 23. Detect Amazon-S3 Bucket
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
[{"type": "nuclei_finding", "template": "s3-detect", "matched_at": "https://console.qosmos.qnulabs.com/%c0", "url": "https://console.qosmos.qnulabs.com/", "request": "GET /%c0 HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:14:51 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 8c01bb988e27b4929e8704da99750b3e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: nfeufHKQBNMIKz3ta-n_FjssCc1ef5atl9c1uDpB72AQI9Snk2pvlw==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:s3-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `834701f5fd64d966909452e62834501984141d584f844f0ae709cb14afb45ff6`
**Chain of Custody ID**: `no-audit-event`

---

### 24. Weak Content Security Policy - Detect
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
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:14:55 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 8ba9ea38e425686fc9c844ebae37e2c8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: _UDntklTOjIe8Y0KTggG4vbmzlgq1N5AuYuD6QSmqraiPQd1upfC2A==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": ["frame-ancestors 'self'"], "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:weak-csp-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `75db91f67cf3d4ae98c7c7db84f216d0ef145c2e5ef429b86909bdb636937fc3`
**Chain of Custody ID**: `no-audit-event`

---

### 25. AWS Service - Detect
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
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Knoppix; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:15:39 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 43b154ec7ecff79d396132662af9c9a4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 3UTGc5fZEumeXEMB-r67yCIA2JMmK06Eao8j2XAvGsvFwjODO42_4A==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:aws-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `cb66c87fb046ada9cb726170c6a9b503fef35d5accb808bd77272937d0a8d317`
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
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://console.qosmos.qnulabs.com/", "url": "https://console.qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: console.qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Debian; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:15:45 GMT\r\nEtag: W/\"6d8dd52c305b606a75c3a44077d5df14\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:47 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 f88dad2442fcf74ce80bff34e631f7be.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: oV2xlmb3pkgF3RR9-KB8UA1DaRQvcbtBzARd0CqhuKT6BVHAYqHWvA==\r\nX-Amz-Cf-Pop: DEL51-P3\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: aaQARHBg5IbaT_0R.CHSIRVx6.kQFaG2\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <!--\n    Substituted at build time by the qosmos-csp plugin in vite.config.js, which\n    derives the policy from VITE_API_BASE_URL and VITE_KEYCLOAK_URL and refuses\n    to build without them. The console previously shipped with no policy at all\n    (audit FE-02). A sibling guard fails the build if this placeholder is ever\n    left unsubstituted, because the literal string parses as a policy of\n    unknown directives \u2014 i.e. no policy \u2014 with no error anywhere.\n  -->\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://console.qosmos.qnulabs.com https://auth.console.qosmos.qnulabs.com; frame-src 'self' https://auth.console.qosmos.qnulabs.com; img-src 'self' data: blob: https:; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | Admin Console</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&family=Inter:wght@100..900&display=swap\"\n    rel=\"stylesheet\">\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\">\n  <script type=\"module\" crossorigin src=\"/assets/index-B_biYM1u.js\"></script>\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CLlVWdaN.css\">\n</head>\n\n<body>\n  <div id=\"root\"></div>\n</body>\n\n</html>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:tech-detect"], "baseline_status": 200, "baseline_len": 1861}}]
```
**Artifact SHA-256 Hash**: `8c7057557ccb26caa85c592b1698ac07ba92cb77a5174dbb41c8970ee76b6157`
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
[{"type": "nuclei_finding", "template": "nameserver-fingerprint", "matched_at": "console.qosmos.qnulabs.com", "url": "console.qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 20497\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t NS\n", "response": ";; opcode: QUERY, status: NOERROR, id: 20497\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n; EDE: 10 (RRSIGs Missing): (for DNSKEY qnulabs.com., id = 58432)\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t NS\n\n;; ANSWER SECTION:\nconsole.qosmos.qnulabs.com.\t600\tIN\tCNAME\td17s1sh6h7yidz.cloudfront.net.\nd17s1sh6h7yidz.cloudfront.net.\t172800\tIN\tNS\tns-1037.awsdns-01.org.\nd17s1sh6h7yidz.cloudfront.net.\t172800\tIN\tNS\tns-1869.awsdns-41.co.uk.\nd17s1sh6h7yidz.cloudfront.net.\t172800\tIN\tNS\tns-407.awsdns-50.com.\nd17s1sh6h7yidz.cloudfront.net.\t172800\tIN\tNS\tns-978.awsdns-58.net.\n", "extracted_results": ["ns-1037.awsdns-01.org.", "ns-1869.awsdns-41.co.uk.", "ns-407.awsdns-50.com.", "ns-978.awsdns-58.net."], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "console.qosmos.qnulabs.com:80", "scoped_endpoints": ["console.qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `4d26dee024dbcdf2c12de134fd9b0b4b99e0c9e54f2a20303918679020b5a2db`
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
[{"type": "nuclei_finding", "template": "dns-saas-service-detection", "matched_at": "console.qosmos.qnulabs.com", "url": "console.qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 41912\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t CNAME\n", "response": ";; opcode: QUERY, status: NOERROR, id: 41912\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n; EDE: 10 (RRSIGs Missing): (for DNSKEY qnulabs.com., id = 58432)\n\n;; QUESTION SECTION:\n;console.qosmos.qnulabs.com.\tIN\t CNAME\n\n;; ANSWER SECTION:\nconsole.qosmos.qnulabs.com.\t600\tIN\tCNAME\td17s1sh6h7yidz.cloudfront.net.\n", "extracted_results": ["d17s1sh6h7yidz.cloudfront.net"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "console.qosmos.qnulabs.com:80", "scoped_endpoints": ["console.qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `283e5a9e379c2b14be95a3ab9738775a3d5e0bcce4f8b7b3f3503b3b1504b771`
**Chain of Custody ID**: `no-audit-event`

---

### 29. Missing Subresource Integrity
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
[{"type": "nuclei_finding", "template": "missing-sri", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:17:15 GMT\r\nEtag: W/\"6a2fd3835fb33e220d402d551a383be7\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:07 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 516afc70a3b3f2e68dd4cbe530530dd4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: j0eZqFsBKvrX_3BfEZCZIB2jWfg0Z3ywgxBfwXUQMLfsleVzwZ6PXQ==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: QdIZuVP41ejxpQWvQo2IU4MQwrHk_SN8\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" cross

...[truncated 715 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `50976b37b23c6466103ff937d0d2a48015600fa52e198eda83dd6aa50cd6cef4`
**Chain of Custody ID**: `no-audit-event`

---

### 30. TLS Version - Detect
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

### 31. Detect websites using AWS bucket storage
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
[{"type": "nuclei_finding", "template": "aws-bucket-service", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:17:22 GMT\r\nEtag: W/\"6a2fd3835fb33e220d402d551a383be7\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:07 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 ae32fd87bf2e0f90ef9d9827402cd17e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: hRpM0ry5ZEujviUc3LBS8-8GjRlg0Mh4AB6ZaPrTseleSbBRp3nn0Q==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: QdIZuVP41ejxpQWvQo2IU4MQwrHk_SN8\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/

...[truncated 366 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `35b18d3ddf6ceb016b22c6391d1fa3418d73921bdb27a437ed93f8438c649afe`
**Chain of Custody ID**: `no-audit-event`

---

### 32. AWS Cloudfront service detection
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
[{"type": "nuclei_finding", "template": "aws-cloudfront-service", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:17:22 GMT\r\nEtag: W/\"6a2fd3835fb33e220d402d551a383be7\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:07 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 ae32fd87bf2e0f90ef9d9827402cd17e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: hRpM0ry5ZEujviUc3LBS8-8GjRlg0Mh4AB6ZaPrTseleSbBRp3nn0Q==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: QdIZuVP41ejxpQWvQo2IU4MQwrHk_SN8\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/ass

...[truncated 370 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `ad96b1f5df1e96d7e5ff4fd049441ee20ee78573ea07ff6510d09d77a2ccba69`
**Chain of Custody ID**: `no-audit-event`

---

### 33. WAF Detection
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
[{"type": "nuclei_finding", "template": "waf-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "POST / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Knoppix; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36\r\nConnection: close\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\n_=<script>alert(1)</script>", "response": "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 1053\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html\r\nDate: Mon, 31 Aug 2026 19:14:12 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: CloudFront\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVia: 1.1 8bb7a45ec0a3584d9cf23932864d835c.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: Qbi1g2PpNOMdq-PS4XqmUy1ZuLK9X1HpAer2z8RltPg5knNNQJv_lw==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Cache: Error from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<HTML><HEAD><META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=iso-8859-1\">\n<TITLE>ERROR: The request could not be satisfied</TITLE>\n</HEAD><BODY>\n<H1>403 ERROR</H1>\n<H2>The request could not be satisfied.</H2>\n<HR noshade size=\"1px\">\nThis distribution is not configured to allow the HTTP request method that was used for this request. The distribution supports only cachable requests.\nWe can't connect to the server for this app or website at this time. There might be too much traffic or a configuration error. Try again later, or contact the app or website owner.\n<BR clear=\"all\">\nIf you provide content to customers through CloudFront, you can find steps to troubleshoot and help prevent this error by reviewing the CloudFront documentation.\n<BR clear=\"all\">\n<HR noshade size=\"1px\">\n<PRE>\nGenerated by cloudfront (CloudFront)\nRequest ID: Qbi1g2PpNOMdq-PS4XqmUy1ZuLK9X1HpAer2z8RltPg5knNNQJv_lw==\n</PRE>\n<ADDRESS>\n</ADDRESS>\n</BODY></HTML>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:waf-detect"], "baseline_status": 200, "baseline_len": 2934}}]
```
**Artifact SHA-256 Hash**: `265d83142ccf15ad9050f18afd496144bd70725c0ac42b8d165bea99d8eedcb1`
**Chain of Custody ID**: `no-audit-event`

---

### 34. Detect Amazon-S3 Bucket
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
[{"type": "nuclei_finding", "template": "s3-detect", "matched_at": "https://qosmos.qnulabs.com/%c0", "url": "https://qosmos.qnulabs.com/", "request": "GET /%c0 HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Mobile/15E148 Safari/604.1\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:17:20 GMT\r\nEtag: W/\"6a2fd3835fb33e220d402d551a383be7\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:07 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 858e093a81e040a22e5ad8df08a476f4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: PLvM5FNS0q0trOyOKRRCqzZ3_uA3aiwhlCChv7_yyAsqQa2579aw0A==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: QdIZuVP41ejxpQWvQo2IU4MQwrHk_SN8\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n 

...[truncated 570 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `0e43f5c7a84ceaffc70a7e406fc4fd82f6066416965c29ab490c8a52c716d51e`
**Chain of Custody ID**: `no-audit-event`

---

### 35. Weak Content Security Policy - Detect
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
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com/", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 19:17:22 GMT\r\nEtag: W/\"6a2fd3835fb33e220d402d551a383be7\"\r\nLast-Modified: Mon, 31 Aug 2026 08:57:07 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 ae32fd87bf2e0f90ef9d9827402cd17e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: hRpM0ry5ZEujviUc3LBS8-8GjRlg0Mh4AB6ZaPrTseleSbBRp3nn0Q==\r\nX-Amz-Cf-Pop: DEL54-P8\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: QdIZuVP41ejxpQWvQo2IU4MQwrHk_SN8\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('consent', 'default', {ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied'});\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net https://pagead2.googlesyndication.com; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-qE3dqAT89u2BJjDElSzJg1ThsUwKcGJ2IG5FyhCXCZo='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/ind

...[truncated 544 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `861ddccb4940edeb50a83888be2b64917ef4812f9caccf29226af2052f237c9c`
**Chain of Custody ID**: `no-audit-event`

---

### 36. DNS SaaS Service Detection
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
[{"type": "nuclei_finding", "template": "dns-saas-service-detection", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 23139\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n", "response": ";; opcode: QUERY, status: NOERROR, id: 23139\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n; EDE: 10 (RRSIGs Missing): (for DNSKEY qnulabs.com., id = 58432)\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t600\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\n", "extracted_results": ["dzvhrea2cko08.cloudfront.net"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "qosmos.qnulabs.com:80", "scoped_endpoints": ["qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `701b30c324825636adfd2c2c3e0bcb8f0a019f8fea5862f05b7729c770c943ff`
**Chain of Custody ID**: `no-audit-event`

---

### 37. NS Record Detection
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
[{"type": "nuclei_finding", "template": "nameserver-fingerprint", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 53004\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n", "response": ";; opcode: QUERY, status: NOERROR, id: 53004\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 512\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t600\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-1482.awsdns-57.org.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-877.awsdns-45.net.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-250.awsdns-31.com.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-1546.awsdns-01.co.uk.\n", "extracted_results": ["ns-1482.awsdns-57.org.", "ns-877.awsdns-45.net.", "ns-250.awsdns-31.com.", "ns-1546.awsdns-01.co.uk."], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "qosmos.qnulabs.com:80", "scoped_endpoints": ["qosmos.qnulabs.com:443"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `02db1ee63683921fcf5862401a0280016c86c9573ff2055a4a2ad991260a8ec5`
**Chain of Custody ID**: `no-audit-event`

---
