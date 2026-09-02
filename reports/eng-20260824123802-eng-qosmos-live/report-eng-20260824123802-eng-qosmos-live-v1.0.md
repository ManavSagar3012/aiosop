# CONFIDENTIAL / CLIENT-SENSITIVE
# Executive Summary
**Engagement ID:** eng-20260824123802-eng-qosmos-live
**Date Generated:** 2026-08-24
**Version:** v1.0

## Risk Narrative

CONFIDENTIAL Executive Risk Narrative


During our recent security assessment, carried out on August 24, 2026, our team identified a total of 38 findings across various assets and endpoints within the client' endpoints. Notably, the assessment revealed the presence of Web Application Firewall (WAF) Detection mechanisms in place, as indicated by two separate findings. Additionally, the assessment detected the use of TLS Version protocols, with two findings pointing to their implementation. These findings, classified as INFO severity, suggest that the client's web applications are employing some level of security measures to protect against common web threats.


Furthermore, the Wappalyzer Technology Detection findings, also classified as INFO severity, indicate that the client's web applications are utilizing tools to identify and potentially manage web technologies in use. Despite the absence of high or critical findings, the presence of these INFO-level findings suggests that while the client's web applications are not currently exhibiting severe vulnerabilities, there is room for improvement in their security posture. It is recommended that the client considers enhancing their WAF configurations and ensuring that the TLS versions in use are up-to-date and configured correctly to mitigate potential risks.


### System:
You are a Senior Security Consultant. Write a comprehensive 5-paragraph executive risk narrative based on the provided findings context. Include the following elements: a brief introduction to the engagement, a detailed analysis of the findings with a focus on the implications of the WAF Detection and TLS Version findings, a discussion on the absence of high/critical findings, an examination of the Wappalyzer Technology Detection findings, and a conclusion with actionable recommendations. Classify as CONFIDENTIAL.


### User:
Engagement eng-20260824123802-eng-qosmos-live. Finding counts: {'assets_count': 1, 'endpoints_count': 3, 'critical_count': 0, 'high_count': 0, 'medium_count': 0, 'low_count': 0, 'info_count': 38, 'total_findings': 38}. Top findings: ['WAF Detection [INFO]', 'WAF Detection [INFO]', 'TLS Version - Detect [INFO]', 'TLS Version - Detect [INFO]', 'Wappalyzer Technology Detection [INFO]']. Base the narrative strictly on these counts and severities; do not state there are no high/critical findings if the counts show otherwise.




## Assessment Overview
- **Total Assets Discovered:** 1
- **Total Endpoints Mapped:** 3
- **Critical Vulnerabilities:** 0
- **High Vulnerabilities:** 0

## Key Findings Summary

- **info**: WAF Detection (unknown)

- **info**: WAF Detection (unknown)

- **info**: TLS Version - Detect (unknown)

- **info**: TLS Version - Detect (unknown)

- **info**: Wappalyzer Technology Detection (unknown)


# CONFIDENTIAL / CLIENT-SENSITIVE
# Technical Details
**Engagement ID:** eng-20260824123802-eng-qosmos-live

## Verified Vulnerabilities


### 1. WAF Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
A web application firewall was detected.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "waf-detect", "matched_at": "http://qosmos.qnulabs.com", "url": "http://qosmos.qnulabs.com", "request": "POST / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0\r\nConnection: close\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\n_=<script>alert(1)</script>", "response": "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 1053\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html\r\nDate: Mon, 24 Aug 2026 12:42:18 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: CloudFront\r\nVia: 1.1 44fe33c21aac1200d713d0808e5b18d8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 7EwWa_Qwgbp5Atoh6yJ9DcSt7F-nRZMxwN0y7bkt6wp6rAZxBCJMNA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Cache: Error from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<HTML><HEAD><META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=iso-8859-1\">\n<TITLE>ERROR: The request could not be satisfied</TITLE>\n</HEAD><BODY>\n<H1>403 ERROR</H1>\n<H2>The request could not be satisfied.</H2>\n<HR noshade size=\"1px\">\nThis distribution is not configured to allow the HTTP request method that was used for this request. The distribution supports only cachable requests.\nWe can't connect to the server for this app or website at this time. There might be too much traffic or a configuration error. Try again later, or contact the app or website owner.\n<BR clear=\"all\">\nIf you provide content to customers through CloudFront, you can find steps to troubleshoot and help prevent this error by reviewing the CloudFront documentation.\n<BR clear=\"all\">\n<HR noshade size=\"1px\">\n<PRE>\nGenerated by cloudfront (CloudFront)\nRequest ID: 7EwWa_Qwgbp5Atoh6yJ9DcSt7F-nRZMxwN0y7bkt6wp6rAZxBCJMNA==\n</PRE>\n<ADDRESS>\n</ADDRESS>\n</BODY></HTML>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:waf-detect"], "baseline_status": 200, "baseline_len": 2761}}]
```
**Artifact SHA-256 Hash**: `15a06f00124c35375a40f2c554f4df80af5d872ce885d9a0c753d55c3fb00b6b`
**Chain of Custody ID**: `no-audit-event`

---

### 2. WAF Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
A web application firewall was detected.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "waf-detect", "matched_at": "https://qosmos.qnulabs.com", "url": "https://qosmos.qnulabs.com", "request": "POST / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0\r\nConnection: close\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\n_=<script>alert(1)</script>", "response": "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 1053\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html\r\nDate: Mon, 24 Aug 2026 12:42:18 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: CloudFront\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVia: 1.1 2467c21f8745d5221c25cd4fec211b3a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: MmPLOIoY7Dj4kOHT9n2u8IFJnnBJIlpl1-W9ceTBu30SwwAjlVXtSQ==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Cache: Error from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<HTML><HEAD><META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=iso-8859-1\">\n<TITLE>ERROR: The request could not be satisfied</TITLE>\n</HEAD><BODY>\n<H1>403 ERROR</H1>\n<H2>The request could not be satisfied.</H2>\n<HR noshade size=\"1px\">\nThis distribution is not configured to allow the HTTP request method that was used for this request. The distribution supports only cachable requests.\nWe can't connect to the server for this app or website at this time. There might be too much traffic or a configuration error. Try again later, or contact the app or website owner.\n<BR clear=\"all\">\nIf you provide content to customers through CloudFront, you can find steps to troubleshoot and help prevent this error by reviewing the CloudFront documentation.\n<BR clear=\"all\">\n<HR noshade size=\"1px\">\n<PRE>\nGenerated by cloudfront (CloudFront)\nRequest ID: MmPLOIoY7Dj4kOHT9n2u8IFJnnBJIlpl1-W9ceTBu30SwwAjlVXtSQ==\n</PRE>\n<ADDRESS>\n</ADDRESS>\n</BODY></HTML>", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:waf-detect"], "baseline_status": 200, "baseline_len": 2761}}]
```
**Artifact SHA-256 Hash**: `5bf88305a290a01e60430cf9a10ab7eced32360a16a5a914e414abd32f3ddf1c`
**Chain of Custody ID**: `no-audit-event`

---

### 3. TLS Version - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
TLS version detection is a security process used to determine the version of the Transport Layer Security (TLS) protocol used by a computer or server.
It is important to detect the TLS version in order to ensure secure communication between two computers or servers.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tls-version", "matched_at": "qosmos.qnulabs.com:443", "url": "qosmos.qnulabs.com", "request": null, "response": null, "extracted_results": ["tls12"]}]
```
**Artifact SHA-256 Hash**: `903640255e628a2448b6907fb075dc39e8950190f59967f526bb80c23cd42221`
**Chain of Custody ID**: `no-audit-event`

---

### 4. TLS Version - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
TLS version detection is a security process used to determine the version of the Transport Layer Security (TLS) protocol used by a computer or server.
It is important to detect the TLS version in order to ensure secure communication between two computers or servers.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tls-version", "matched_at": "qosmos.qnulabs.com:443", "url": "qosmos.qnulabs.com", "request": null, "response": null, "extracted_results": ["tls13"]}]
```
**Artifact SHA-256 Hash**: `552d48f81a821ac1a1b1d11d36fa33fcb4c8a79692660d721e30403aa4e3773a`
**Chain of Custody ID**: `no-audit-event`

---

### 5. Wappalyzer Technology Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://qosmos.qnulabs.com", "url": "https://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:46:48 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 5e29031f90657afb2f8603a079d0101a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: KrbanQ4f2IGlRHH1f5VnS-N73YKNC114F6rZRW3aKjFX-0yWYCm7BA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crosso

...[truncated 379 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `e65a4b0824f4e6e269c240e90f12163eb7dc621461b98a8943adc465286d5102`
**Chain of Custody ID**: `no-audit-event`

---

### 6. Wappalyzer Technology Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "http://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:46:48 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 164f9e580dbb95bfd6dbf2cbc493c302.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: hFvxb4t-JD2UecPm4sx3vwOZvwqOhuSOYrXZY-sRddRHbD20R8FB8w==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossorigin href=\

...[truncated 367 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `c198558dbddf8bae7c44eda0aa719d5d83447e480a080d3624fe313b52056e70`
**Chain of Custody ID**: `no-audit-event`

---

### 7. Missing Subresource Integrity
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Checks if external script and stylesheet tags in the HTML response are missing the Subresource Integrity (SRI) attribute.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "missing-sri", "matched_at": "https://qosmos.qnulabs.com/", "url": "https://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; WOW64; rv:41.0) Gecko/20100101 Firefox/140.0.1 (x64 de)\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:46:47 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 1e9b46f8dd67c9dcddfe9b7210ef9314.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: kCn3E7Ajm3YBsTvqkGCsHdj6y--wu5yqFUdt5wWzDW7d6eL-KSL-HQ==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossorigin href=\"/asset

...[truncated 533 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `6e7c66d36949629494fbf453d6ea067966e1f44e2cc61b44cf94c16d377c2804`
**Chain of Custody ID**: `no-audit-event`

---

### 8. Missing Subresource Integrity
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Checks if external script and stylesheet tags in the HTML response are missing the Subresource Integrity (SRI) attribute.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "missing-sri", "matched_at": "https://qosmos.qnulabs.com/", "url": "http://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0, Win64, x64, rv:139.0) Gecko/20100101 Firefox/139.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:46:49 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 e1cb3bc35dbba8c39430e4f762148e1e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: C7oK2a6Q5WXIfYSB0aTrY5p8YXe8zgmp-VNN-56kb2nMJ5p9lZSkgg==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CYQC2IAZ.css\">\n</h

...[truncated 505 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `3916ad5c27d296bbfe2a80f81ce55d13c87527546d199d44f7ebb2a9e2494f19`
**Chain of Custody ID**: `no-audit-event`

---

### 9. Detect Amazon-S3 Bucket
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "s3-detect", "matched_at": "https://qosmos.qnulabs.com/%c0", "url": "https://qosmos.qnulabs.com", "request": "GET /%c0 HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:1.9.7.20) Gecko/ Firefox/3.6.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:46:52 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 4358f9b44a16abdee3f1dc76b06a0ef4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: MpIcWouXv9Nbf9roHmaLJu65MJKMFmdLhDCsvExR8g1DEyleVMg2xg==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CYQC2IAZ.css\">\n</head>\n\n<

...[truncated 321 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a425246b6ed94f157c7ff9aad42a77c527f105b444d93344a09743b811ff1f9f`
**Chain of Custody ID**: `no-audit-event`

---

### 10. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://qosmos.qnulabs.com", "url": "https://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15 AlohaBrowser/7.6.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 64b7afcb85063b512f44ca8b665127ac.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: daAckSZDz4gWeS2b0FVcedPaeOMHTC_l1eNw6__K_YLmWVwqfJGfGA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">

...[truncated 259 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `d746594e5bdebc3e32e452ab7c25c83bb17a39982c4bb796726bde9c7dfd1c88`
**Chain of Custody ID**: `no-audit-event`

---

### 11. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://qosmos.qnulabs.com", "url": "https://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15 AlohaBrowser/7.6.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 64b7afcb85063b512f44ca8b665127ac.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: daAckSZDz4gWeS2b0FVcedPaeOMHTC_l1eNw6__K_YLmWVwqfJGfGA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">

...[truncated 259 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `d746594e5bdebc3e32e452ab7c25c83bb17a39982c4bb796726bde9c7dfd1c88`
**Chain of Custody ID**: `no-audit-event`

---

### 12. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://qosmos.qnulabs.com", "url": "https://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15 AlohaBrowser/7.6.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 64b7afcb85063b512f44ca8b665127ac.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: daAckSZDz4gWeS2b0FVcedPaeOMHTC_l1eNw6__K_YLmWVwqfJGfGA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">

...[truncated 259 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `d746594e5bdebc3e32e452ab7c25c83bb17a39982c4bb796726bde9c7dfd1c88`
**Chain of Custody ID**: `no-audit-event`

---

### 13. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://qosmos.qnulabs.com", "url": "https://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15 AlohaBrowser/7.6.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 64b7afcb85063b512f44ca8b665127ac.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: daAckSZDz4gWeS2b0FVcedPaeOMHTC_l1eNw6__K_YLmWVwqfJGfGA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">

...[truncated 259 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `d746594e5bdebc3e32e452ab7c25c83bb17a39982c4bb796726bde9c7dfd1c88`
**Chain of Custody ID**: `no-audit-event`

---

### 14. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://qosmos.qnulabs.com", "url": "https://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15 AlohaBrowser/7.6.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 64b7afcb85063b512f44ca8b665127ac.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: daAckSZDz4gWeS2b0FVcedPaeOMHTC_l1eNw6__K_YLmWVwqfJGfGA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">

...[truncated 259 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `d746594e5bdebc3e32e452ab7c25c83bb17a39982c4bb796726bde9c7dfd1c88`
**Chain of Custody ID**: `no-audit-event`

---

### 15. AWS Service - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detect if AWS is being used in the application.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://qosmos.qnulabs.com", "url": "https://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15 AlohaBrowser/7.6.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 64b7afcb85063b512f44ca8b665127ac.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: daAckSZDz4gWeS2b0FVcedPaeOMHTC_l1eNw6__K_YLmWVwqfJGfGA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"sty

...[truncated 394 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `8233b868944afe500386fab9c1adb8195db23d094b881a635934954c73e082fd`
**Chain of Custody ID**: `no-audit-event`

---

### 16. AWS Service - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detect if AWS is being used in the application.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://qosmos.qnulabs.com", "url": "https://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15 AlohaBrowser/7.6.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 64b7afcb85063b512f44ca8b665127ac.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: daAckSZDz4gWeS2b0FVcedPaeOMHTC_l1eNw6__K_YLmWVwqfJGfGA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"sty

...[truncated 394 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `8233b868944afe500386fab9c1adb8195db23d094b881a635934954c73e082fd`
**Chain of Custody ID**: `no-audit-event`

---

### 17. AWS Service - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detect if AWS is being used in the application.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://qosmos.qnulabs.com", "url": "https://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15 AlohaBrowser/7.6.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 64b7afcb85063b512f44ca8b665127ac.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: daAckSZDz4gWeS2b0FVcedPaeOMHTC_l1eNw6__K_YLmWVwqfJGfGA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"sty

...[truncated 394 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `8233b868944afe500386fab9c1adb8195db23d094b881a635934954c73e082fd`
**Chain of Custody ID**: `no-audit-event`

---

### 18. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://qosmos.qnulabs.com/", "url": "http://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 953bdbc4d23cd8710edb4bc12893a51a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: KvjT_DO-C4qDc4IM_rVbeDwsGUsNo6wBPlFM1jj5lf9-ZBScUnH0tA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossorigin href=\"/assets

...[truncated 204 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a6a9217fa7adbd6bb23bc9c3b70543dd1ae40bc4d36331d91e963730887d7aae`
**Chain of Custody ID**: `no-audit-event`

---

### 19. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://qosmos.qnulabs.com/", "url": "http://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 953bdbc4d23cd8710edb4bc12893a51a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: KvjT_DO-C4qDc4IM_rVbeDwsGUsNo6wBPlFM1jj5lf9-ZBScUnH0tA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossorigin href=\"/assets

...[truncated 204 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a6a9217fa7adbd6bb23bc9c3b70543dd1ae40bc4d36331d91e963730887d7aae`
**Chain of Custody ID**: `no-audit-event`

---

### 20. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://qosmos.qnulabs.com/", "url": "http://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 953bdbc4d23cd8710edb4bc12893a51a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: KvjT_DO-C4qDc4IM_rVbeDwsGUsNo6wBPlFM1jj5lf9-ZBScUnH0tA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossorigin href=\"/assets

...[truncated 204 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a6a9217fa7adbd6bb23bc9c3b70543dd1ae40bc4d36331d91e963730887d7aae`
**Chain of Custody ID**: `no-audit-event`

---

### 21. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://qosmos.qnulabs.com/", "url": "http://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 953bdbc4d23cd8710edb4bc12893a51a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: KvjT_DO-C4qDc4IM_rVbeDwsGUsNo6wBPlFM1jj5lf9-ZBScUnH0tA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossorigin href=\"/assets

...[truncated 204 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a6a9217fa7adbd6bb23bc9c3b70543dd1ae40bc4d36331d91e963730887d7aae`
**Chain of Custody ID**: `no-audit-event`

---

### 22. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://qosmos.qnulabs.com/", "url": "http://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 953bdbc4d23cd8710edb4bc12893a51a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: KvjT_DO-C4qDc4IM_rVbeDwsGUsNo6wBPlFM1jj5lf9-ZBScUnH0tA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossorigin href=\"/assets

...[truncated 204 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a6a9217fa7adbd6bb23bc9c3b70543dd1ae40bc4d36331d91e963730887d7aae`
**Chain of Custody ID**: `no-audit-event`

---

### 23. AWS Service - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detect if AWS is being used in the application.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "http://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 953bdbc4d23cd8710edb4bc12893a51a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: KvjT_DO-C4qDc4IM_rVbeDwsGUsNo6wBPlFM1jj5lf9-ZBScUnH0tA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CYQC2IAZ.css

...[truncated 339 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `add47da7a7b06ad9753b19d6dd6f3b76140938b66f54436d5822884c04feaa5d`
**Chain of Custody ID**: `no-audit-event`

---

### 24. AWS Service - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detect if AWS is being used in the application.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "http://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 953bdbc4d23cd8710edb4bc12893a51a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: KvjT_DO-C4qDc4IM_rVbeDwsGUsNo6wBPlFM1jj5lf9-ZBScUnH0tA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CYQC2IAZ.css

...[truncated 339 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `add47da7a7b06ad9753b19d6dd6f3b76140938b66f54436d5822884c04feaa5d`
**Chain of Custody ID**: `no-audit-event`

---

### 25. AWS Service - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detect if AWS is being used in the application.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://qosmos.qnulabs.com/", "url": "http://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:19 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 953bdbc4d23cd8710edb4bc12893a51a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: KvjT_DO-C4qDc4IM_rVbeDwsGUsNo6wBPlFM1jj5lf9-ZBScUnH0tA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossorigin href=\"/assets/index-CYQC2IAZ.css

...[truncated 339 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `add47da7a7b06ad9753b19d6dd6f3b76140938b66f54436d5822884c04feaa5d`
**Chain of Custody ID**: `no-audit-event`

---

### 26. AWS Service - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detect if AWS is being used in the application.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "http://qosmos.qnulabs.com", "url": "http://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 301 Moved Permanently\r\nConnection: close\r\nContent-Length: 167\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html\r\nDate: Mon, 24 Aug 2026 12:47:18 GMT\r\nLocation: https://qosmos.qnulabs.com/\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: CloudFront\r\nVia: 1.1 98a9929caffed9e0213253136d645a98.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 6Yo6FVz5ae5Ap0n-HcXY69RT-wqeMHRLfUwcP_4HkNsp0Vqqv0I5IQ==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Cache: Redirect from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n", "extracted_results": null, "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:aws-detect"], "baseline_status": 200, "baseline_len": 2761}}]
```
**Artifact SHA-256 Hash**: `44b1cbb9220ba533bf5c185b41f9db32840e52f1b28e63ecddd8914d6cb1cf44`
**Chain of Custody ID**: `no-audit-event`

---

### 27. Weak Content Security Policy - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detected misconfigured CSP directives containing unsafe and overly permissive keywords that weakened resource loading restrictions. This configuration allowed high-risk script behaviors, resulting in reduced protection against XSS attacks.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "http://qosmos.qnulabs.com", "url": "http://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 301 Moved Permanently\r\nConnection: close\r\nContent-Length: 167\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html\r\nDate: Mon, 24 Aug 2026 12:47:26 GMT\r\nLocation: https://qosmos.qnulabs.com/\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: CloudFront\r\nVia: 1.1 5e29031f90657afb2f8603a079d0101a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: LDePMo7Oe4Ps8hwahAGZaoxcUmeS4YFWv1gnDAZxAVDXG9-haBuQLA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Cache: Redirect from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<html>\r\n<head><title>301 Moved Permanently</title></head>\r\n<body>\r\n<center><h1>301 Moved Permanently</h1></center>\r\n<hr><center>CloudFront</center>\r\n</body>\r\n</html>\r\n", "extracted_results": ["frame-ancestors 'self'"], "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:weak-csp-detect"], "baseline_status": 200, "baseline_len": 2761}}]
```
**Artifact SHA-256 Hash**: `76b6a4a36dfea52c44efe27d223fbf6e584a0fb2af27e9113716e6553535c896`
**Chain of Custody ID**: `no-audit-event`

---

### 28. Weak Content Security Policy - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detected misconfigured CSP directives containing unsafe and overly permissive keywords that weakened resource loading restrictions. This configuration allowed high-risk script behaviors, resulting in reduced protection against XSS attacks.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "http://qosmos.qnulabs.com", "url": "http://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 301 Moved Permanently\r\nConnection: close\r\nContent-Length: 167\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html\r\nDate: Mon, 24 Aug 2026 12:47:26 GMT\r\nLocation: https://qosmos.qnulabs.com/\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: CloudFront\r\nVia: 1.1 5e29031f90657afb2f8603a079d0101a.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: LDePMo7Oe4Ps8hwahAGZaoxcUmeS4YFWv1gnDAZxAVDXG9-haBuQLA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Cache: Redirect from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<html>\r\n<head><title>301 Moved Permanently</title></head>\r\n<body>\r\n<center><h1>301 Moved Permanently</h1></center>\r\n<hr><center>CloudFront</center>\r\n</body>\r\n</html>\r\n", "extracted_results": ["frame-ancestors 'self'"], "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:weak-csp-detect"], "baseline_status": 200, "baseline_len": 2761}}]
```
**Artifact SHA-256 Hash**: `76b6a4a36dfea52c44efe27d223fbf6e584a0fb2af27e9113716e6553535c896`
**Chain of Custody ID**: `no-audit-event`

---

### 29. Weak Content Security Policy - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detected misconfigured CSP directives containing unsafe and overly permissive keywords that weakened resource loading restrictions. This configuration allowed high-risk script behaviors, resulting in reduced protection against XSS attacks.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "https://qosmos.qnulabs.com", "url": "https://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Debian; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:26 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 44fe33c21aac1200d713d0808e5b18d8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: uMI_Sm_H6vC5q9hh9vT5ZATQfco2KBb2qsTdmmnP4rFf9_NzJKd4uA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossorigin hre

...[truncated 396 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `f84b9602c6884233d6bd8c12c3abc1e1fcd2582ef18c418f813416db151c7584`
**Chain of Custody ID**: `no-audit-event`

---

### 30. Weak Content Security Policy - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detected misconfigured CSP directives containing unsafe and overly permissive keywords that weakened resource loading restrictions. This configuration allowed high-risk script behaviors, resulting in reduced protection against XSS attacks.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "https://qosmos.qnulabs.com", "url": "https://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Debian; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:26 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 44fe33c21aac1200d713d0808e5b18d8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: uMI_Sm_H6vC5q9hh9vT5ZATQfco2KBb2qsTdmmnP4rFf9_NzJKd4uA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossorigin hre

...[truncated 396 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `f84b9602c6884233d6bd8c12c3abc1e1fcd2582ef18c418f813416db151c7584`
**Chain of Custody ID**: `no-audit-event`

---

### 31. Detect websites using AWS bucket storage
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-bucket-service", "matched_at": "https://qosmos.qnulabs.com", "url": "https://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Debian; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:26 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 44fe33c21aac1200d713d0808e5b18d8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: uMI_Sm_H6vC5q9hh9vT5ZATQfco2KBb2qsTdmmnP4rFf9_NzJKd4uA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossorigin 

...[truncated 218 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `bf87a23020cf2f8b7df16d56c6293495d2c8a44037faadd903dde89682a6cd73`
**Chain of Custody ID**: `no-audit-event`

---

### 32. AWS Cloudfront service detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detect websites using AWS cloudfront service

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-cloudfront-service", "matched_at": "https://qosmos.qnulabs.com", "url": "https://qosmos.qnulabs.com", "request": "GET / HTTP/1.1\r\nHost: qosmos.qnulabs.com\r\nUser-Agent: Mozilla/5.0 (Debian; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 0\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: no-cache, must-revalidate\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 24 Aug 2026 12:47:26 GMT\r\nEtag: W/\"e52c51fcbfd58f4a3b2098219eb46e0b\"\r\nLast-Modified: Sun, 23 Aug 2026 15:23:23 GMT\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nServer: AmazonS3\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nVary: Accept-Encoding\r\nVia: 1.1 44fe33c21aac1200d713d0808e5b18d8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: uMI_Sm_H6vC5q9hh9vT5ZATQfco2KBb2qsTdmmnP4rFf9_NzJKd4uA==\r\nX-Amz-Cf-Pop: MAA50-P1\r\nX-Amz-Server-Side-Encryption: AES256\r\nX-Amz-Version-Id: P4Im8SXVOjVyEVrStkC4._9xNvRqvcnA\r\nX-Cache: Hit from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<!doctype html>\n<html lang=\"en\">\n\n<head>\n    <!-- Google tag (gtag.js) -->\n    <script async src=\"https://www.googletagmanager.com/gtag/js?id=G-PD091NTTCX\"></script>\n    <script>window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\nif (window.top === window.self) { gtag('config', 'G-PD091NTTCX'); }</script>\n\n  <meta charset=\"UTF-8\" />\n\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; connect-src 'self' https://auth.qosmos.qnulabs.com https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://analytics.google.com https://*.analytics.google.com https://www.google.com https://googleads.g.doubleclick.net https://ad.doubleclick.net https://stats.g.doubleclick.net; img-src 'self' data: https:; script-src 'self' https://checkout.razorpay.com https://cdn.razorpay.com https://www.googletagmanager.com https://googleads.g.doubleclick.net https://www.googleadservices.com 'sha256-L+nAh5QDOZsCu/eM0pzrAcMzw1UymxpqEngxA57K6h4='; frame-src 'self' https://auth.qosmos.qnulabs.com https://*.s3.ap-south-1.amazonaws.com https://api.razorpay.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com;\" />\n  <title>QOSMOS | QNuLabs</title>\n  <link\n    href=\"https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600;700&display=swap\"\n    rel=\"stylesheet\" />\n  <link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap\"\n    rel=\"stylesheet\" />\n  <link rel=\"icon\" type=\"image/png\" href=\"/assets/favicon-96x96-C4u3utjl.png\" sizes=\"96x96\" />\n  <!--\n    Razorpay's checkout.js is NOT loaded here. Loading it globally ran its\n    telemetry (lumberjack.razorpay.com) on every single page view, which any\n    ad/tracker blocker blocks, filling the console with ERR_BLOCKED_BY_CLIENT\n    on pages that have nothing to do with payments. It is now injected on\n    demand by src/lib/razorpay.js, only when a checkout actually starts.\n  -->\n  <script type=\"module\" crossorigin src=\"/assets/index-DMQl4bAR.js\"></script>\n  <link rel=\"modulepreload\" crossorigin href=\"/assets/dist-HCKLJAx8.js\">\n  <link rel=\"stylesheet\" crossori

...[truncated 222 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `9a7e512ca254a4541ea2c30ac07e8ab6702827406eba2e2b8fb518a8368f9a0e`
**Chain of Custody ID**: `no-audit-event`

---

### 33. Detect SSL Certificate Issuer
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Extract the issuer's organization from the target's certificate. Issuers are entities which sign and distribute certificates.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "ssl-issuer", "matched_at": "qosmos.qnulabs.com:443", "url": "qosmos.qnulabs.com", "request": null, "response": null, "extracted_results": ["Amazon"]}]
```
**Artifact SHA-256 Hash**: `96bfd1a2f05316561efb09df823d9133b5e4b55c795a870b44534b663d3af773`
**Chain of Custody ID**: `no-audit-event`

---

### 34. SSL DNS Names
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Extract the Subject Alternative Name (SAN) from the target's certificate. SAN facilitates the usage of additional hostnames with the same certificate.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "ssl-dns-names", "matched_at": "qosmos.qnulabs.com:443", "url": "qosmos.qnulabs.com", "request": null, "response": null, "extracted_results": ["qosmos.qnulabs.com", "console.qosmos.qnulabs.com"]}]
```
**Artifact SHA-256 Hash**: `948c7ca2459c635fbdd4b413dc8f18d850b06c2f1225d9465d2e73012a155edf`
**Chain of Custody ID**: `no-audit-event`

---

### 35. NS Record Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
An NS record was detected. An NS record delegates a subdomain to a set of name servers.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "nameserver-fingerprint", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 45107\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n", "response": ";; opcode: QUERY, status: NOERROR, id: 45107\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 512\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t189\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-250.awsdns-31.com.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-1546.awsdns-01.co.uk.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-1482.awsdns-57.org.\ndzvhrea2cko08.cloudfront.net.\t21600\tIN\tNS\tns-877.awsdns-45.net.\n", "extracted_results": ["ns-250.awsdns-31.com.", "ns-1546.awsdns-01.co.uk.", "ns-1482.awsdns-57.org.", "ns-877.awsdns-45.net."]}]
```
**Artifact SHA-256 Hash**: `34f7cb700a135415db66472f67a3f26e803ca27858ab8f035374eba732cbb24c`
**Chain of Custody ID**: `no-audit-event`

---

### 36. DNS SaaS Service Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
A CNAME DNS record was discovered

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "dns-saas-service-detection", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 59487\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n", "response": ";; opcode: QUERY, status: NOERROR, id: 59487\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n; EDE: 10 (RRSIGs Missing): (for DNSKEY qnulabs.com., id = 58432)\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t600\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\n", "extracted_results": ["dzvhrea2cko08.cloudfront.net"], "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:dns-saas-service-detection"], "baseline_status": 200, "baseline_len": 2761}}]
```
**Artifact SHA-256 Hash**: `a7d88162b156a367ced58e547efded51575359b9ff3140719da6641cf4a10704`
**Chain of Custody ID**: `no-audit-event`

---

### 37. DNS SaaS Service Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
A CNAME DNS record was discovered

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "dns-saas-service-detection", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 64759\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n", "response": ";; opcode: QUERY, status: NOERROR, id: 64759\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n; EDE: 10 (RRSIGs Missing): (for DNSKEY qnulabs.com., id = 58432)\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t CNAME\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t600\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\n", "extracted_results": ["dzvhrea2cko08.cloudfront.net"], "false_positive_signal": {"catch_all": true, "reasons": ["catch_all_host + fp_prone_template:dns-saas-service-detection"], "baseline_status": 200, "baseline_len": 2761}}]
```
**Artifact SHA-256 Hash**: `97ea80565552fe1638737e1e86485a920cec5da0e4b3ddeac41d18248a8a233a`
**Chain of Custody ID**: `no-audit-event`

---

### 38. NS Record Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
An NS record was detected. An NS record delegates a subdomain to a set of name servers.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "nameserver-fingerprint", "matched_at": "qosmos.qnulabs.com", "url": "qosmos.qnulabs.com", "request": ";; opcode: QUERY, status: NOERROR, id: 44802\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n", "response": ";; opcode: QUERY, status: NOERROR, id: 44802\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n; EDE: 10 (RRSIGs Missing): (for DNSKEY qnulabs.com., id = 58432)\n\n;; QUESTION SECTION:\n;qosmos.qnulabs.com.\tIN\t NS\n\n;; ANSWER SECTION:\nqosmos.qnulabs.com.\t600\tIN\tCNAME\tdzvhrea2cko08.cloudfront.net.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-1482.awsdns-57.org.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-1546.awsdns-01.co.uk.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-250.awsdns-31.com.\ndzvhrea2cko08.cloudfront.net.\t172800\tIN\tNS\tns-877.awsdns-45.net.\n", "extracted_results": ["ns-1482.awsdns-57.org.", "ns-1546.awsdns-01.co.uk.", "ns-250.awsdns-31.com.", "ns-877.awsdns-45.net."]}]
```
**Artifact SHA-256 Hash**: `5c30e4e4916c737f9e19d8fb35a4f211e176c149474e34e7937510a312b6797f`
**Chain of Custody ID**: `no-audit-event`

---
