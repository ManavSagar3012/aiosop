# CONFIDENTIAL / CLIENT-SENSITIVE
# Executive Summary
**Engagement ID:** eng-20260703122439-phasegate-verify-175438
**Date Generated:** 2026-07-03
**Version:** v1.0

## Risk Narrative
**CONFIDENTIAL**

**Executive Risk Narrative – PhaseGate Verification Engagement (eng-20260703122439)**

This PhaseGate verification engagement assessed one (1) digital asset encompassing three (3) endpoints. The assessment did not identify any critical or high-severity vulnerabilities. However, two distinct security observations were documented that warrant management attention and remediation planning.

The primary findings include: (1) Wildcard DNS Configuration was detected on the assessed asset, which may facilitate subdomain enumeration risks or potential subdomain takeover scenarios if associated resources are decommissioned; and (2) the Apache Casbin MCP Gateway interface was found accessible with default login credentials, presenting an authentication bypass vector if left unmitigated. While these findings do not represent immediate critical exposure, the default credential finding in particular represents a well-known attack vector that could be exploited opportunistically. We recommend implementing DNS record hygiene practices to restrict wildcard configurations where unnecessary, and enforcing credential management policies to eliminate default credentials on the Casbin gateway. Ongoing monitoring and periodic re-assessment will ensure these lower-severity findings do not evolve into higher-risk exposures as the asset environment matures.

## Assessment Overview
- **Total Assets Discovered:** 1
- **Total Endpoints Mapped:** 3
- **Critical Vulnerabilities:** 0
- **High Vulnerabilities:** 0

## Key Findings Summary

- **info**: Wildcard DNS Configuration - Detection (unknown)

- **info**: Wildcard DNS Configuration - Detection (unknown)

- **high**: Apache Casbin MCP Gateway - Default Login (unknown)

- **info**: WAF Detection (unknown)

- **info**: WAF Detection (unknown)


# CONFIDENTIAL / CLIENT-SENSITIVE
# Technical Details
**Engagement ID:** eng-20260703122439-phasegate-verify-175438

## Verified Vulnerabilities


### 1. Wildcard DNS Configuration - Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
A wildcard DNS configuration was detected. Wildcard DNS records can resolve all subdomains to the same IP address, which may indicate a catch-all configuration.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "wildcard-dns-detect", "matched_at": "3FzdrDMdDQzrDR8I6VmJrEbCUJT-3FzdrDMdDQzrDR8I6VmJrEbCUJT.uat-bugbounty.nonprod.syfe.com", "url": "uat-bugbounty.nonprod.syfe.com", "request": ";; opcode: QUERY, status: NOERROR, id: 39997\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;3FzdrDMdDQzrDR8I6VmJrEbCUJT-3FzdrDMdDQzrDR8I6VmJrEbCUJT.uat-bugbounty.nonprod.syfe.com.\tIN\t A\n", "response": ";; opcode: QUERY, status: NOERROR, id: 39997\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 512\n\n;; QUESTION SECTION:\n;3FzdrDMdDQzrDR8I6VmJrEbCUJT-3FzdrDMdDQzrDR8I6VmJrEbCUJT.uat-bugbounty.nonprod.syfe.com.\tIN\t A\n\n;; ANSWER SECTION:\n3FzdrDMdDQzrDR8I6VmJrEbCUJT-3FzdrDMdDQzrDR8I6VmJrEbCUJT.uat-bugbounty.nonprod.syfe.com.\t60\tIN\tCNAME\td2uz6yy7bd3xp8.cloudfront.net.\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tA\t18.164.246.94\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tA\t18.164.246.80\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tA\t18.164.246.129\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tA\t18.164.246.119\n", "extracted_results": ["18.164.246.94", "18.164.246.80", "18.164.246.129", "18.164.246.119"]}]
```
**Artifact SHA-256 Hash**: `562cbbadac471512aaa4e13ae958d5e08d148b917c26f5e20598ad480ea26d79`
**Chain of Custody ID**: `no-audit-event`

---

### 2. Wildcard DNS Configuration - Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
A wildcard DNS configuration was detected. Wildcard DNS records can resolve all subdomains to the same IP address, which may indicate a catch-all configuration.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "wildcard-dns-detect", "matched_at": "3FzdrDMdDQzrDR8I6VmJrEbCUJT-3FzdrDMdDQzrDR8I6VmJrEbCUJT.uat-bugbounty.nonprod.syfe.com", "url": "uat-bugbounty.nonprod.syfe.com", "request": ";; opcode: QUERY, status: NOERROR, id: 16386\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;3FzdrDMdDQzrDR8I6VmJrEbCUJT-3FzdrDMdDQzrDR8I6VmJrEbCUJT.uat-bugbounty.nonprod.syfe.com.\tIN\t A\n", "response": ";; opcode: QUERY, status: NOERROR, id: 16386\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n\n;; QUESTION SECTION:\n;3FzdrDMdDQzrDR8I6VmJrEbCUJT-3FzdrDMdDQzrDR8I6VmJrEbCUJT.uat-bugbounty.nonprod.syfe.com.\tIN\t A\n\n;; ANSWER SECTION:\n3FzdrDMdDQzrDR8I6VmJrEbCUJT-3FzdrDMdDQzrDR8I6VmJrEbCUJT.uat-bugbounty.nonprod.syfe.com.\t60\tIN\tCNAME\td2uz6yy7bd3xp8.cloudfront.net.\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tA\t18.164.246.129\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tA\t18.164.246.119\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tA\t18.164.246.80\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tA\t18.164.246.94\n", "extracted_results": ["18.164.246.94", "18.164.246.129", "18.164.246.119", "18.164.246.80"]}]
```
**Artifact SHA-256 Hash**: `720796ffe059a38a4536d40cd084dccd6f9353dcbc9b9050e34da1d9353b8984`
**Chain of Custody ID**: `no-audit-event`

---

### 3. Apache Casbin MCP Gateway - Default Login
- **Severity**: high
- **Type**: unknown
- **Target**: unknown

#### Description
Apache Casbin MCP Gateway server default login credentials were discovered.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "apache-casbin-mcp-gateway-default-login", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/login", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "POST /login HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0\r\nContent-Length: 45\r\nContent-Type: application/json\r\nAccept-Encoding: gzip\r\n\r\n{\"username\":\"alice\",\"password\":\"password123\"}", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: private, no-cache, no-store, max-age=0, must-revalidate\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:35:23 GMT\r\nEtag: \"zogc52dgi651j0\"\r\nServer: nginx\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nVary: Accept-Encoding\r\nVia: 1.1 aaaf201cb48fd7269941be8318333cea.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: DBnin2SkLRbElEdM3XEBlErFbv0VCnCV8kfSNXIeQrrfLq1n3ikpDA==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Powered-By: Next.js\r\n\r\n<!DOCTYPE html><html lang=\"en-sg\"><head><meta charSet=\"utf-8\" data-next-head=\"\"/><meta content=\"origin-when-cross-origin\" name=\"referrer\" data-next-head=\"\"/><meta content=\"EqOJ4Dbu-Bkysp5pVWAG8f6xr3L4wOV394fYGBgretM\" name=\"google-site-verification\" data-next-head=\"\"/><meta content=\"width=device-width, initial-scale=1, shrink-to-fit=no\" name=\"viewport\" data-next-head=\"\"/><meta content=\"#0a1e39\" name=\"theme-color\" data-next-head=\"\"/><link href=\"/manifest.json\" rel=\"manifest\" data-next-head=\"\"/><link href=\"/favicon.png\" rel=\"shortcut icon\" type=\"image/x-icon\" data-next-head=\"\"/><script async=\"\" src=\"https://www.google.com/recaptcha/enterprise.js?render=6Lc9jmIlAAAAABzWpA-bQI0fZNVhfkrdtWyOQxqU\" data-next-head=\"\"></script><script async=\"\" src=\"/zendeskNext.js\" data-next-head=\"\"></script><style type=\"text/css\" data-next-head=\"\">.fresnel-container{margin:0;padding:0;}\n@media not all and (min-width:0px) and (max-width:767.98px){.fresnel-at-sm{display:none!important;}}\n@media not all and (min-width:768px) and (max-width:1199.98px){.fresnel-at-md{display:none!important;}}\n@media not all and (min-width:1200px) and (max-width:1799.98px){.fresnel-at-xl{display:none!important;}}\n@media not all and (min-width:1800px){.fresnel-at-xxl{display:none!important;}}\n@media not all and (max-width:767.98px){.fresnel-lessThan-md{display:none!important;}}\n@media not all and (max-width:1199.98px){.fresnel-lessThan-xl{display:none!important;}}\n@media not all and (max-width:1799.98px){.fresnel-lessThan-xxl{display:none!important;}}\n@media not all and (min-width:768px){.fresnel-greaterThan-sm{display:none!important;}}\n@media not all and (min-width:1200px){.fresnel-greaterThan-md{display:none!important;}}\n@media not all and (min-width:1800px){.fresnel-greaterThan-xl{display:none!important;}}\n@media not all and (min-width:0px){.fresnel-greaterThanOrEqual-sm{display:none!important;}}\n@media not all and (min-width:768px){.fresnel-greaterThanOrEqual-md{display:none!important;}}\n@media not all and (min-width:1200px){.fresnel-greaterThanOrEqual-xl{display:none!important;}}\n@media not all and (min-width:1800px){.fresnel-greaterThanOrEqual-xxl{display:none!important;}}\n@media not all and (min-width:0px) and (max-width:767.98px){.fresnel-between-sm-md{display:none!important;}}\n@media not all and (min-width:0px) and (max-width:1199.98px){.fresnel-between-sm-xl{display:none!important;}}\n@media not all and (min-width:0px) and (max-width:1799.98px){.fresnel-between-sm-xxl{display:none!important;}}\n@media not all and (min-width:768px) and (max-width:1199.98px){.fresnel-between-md-xl{display:none!important;}}\n@media not all and (min-width:768px) and (max-width:1799.98px){.fresnel-between-md-xxl{display:none!important;}}\n@media not all and (min-width:1200px

...[truncated 260698 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `e317a07296b9ce38830c74c10fa308c372167c5bbd675700944209c43ab474ce`
**Chain of Custody ID**: `no-audit-event`

---

### 4. WAF Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
A web application firewall was detected.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "waf-detect", "matched_at": "http://uat-bugbounty.nonprod.syfe.com", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "POST / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0\r\nConnection: close\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\n_=<script>alert(1)</script>", "response": "HTTP/1.1 307 Temporary Redirect\r\nConnection: close\r\nContent-Length: 169\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Type: text/html\r\nDate: Fri, 03 Jul 2026 12:36:28 GMT\r\nLocation: https://uat-bugbounty.nonprod.syfe.com/\r\nServer: CloudFront\r\nVia: 1.1 96a4883b278fc3b22dd3ef743bde6bc8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: KPxuY8GGOr4l_tZ_aRuRKfci6Y_FKSMHYXeqnEduEnvfyh1bDvgwKA==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Redirect from cloudfront\r\nX-Content-Type-Options: nosniff\r\n\r\n<html>\r\n<head><title>307 Temporary Redirect</title></head>\r\n<body>\r\n<center><h1>307 Temporary Redirect</h1></center>\r\n<hr><center>CloudFront</center>\r\n</body>\r\n</html>\r\n", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `f86e955f3bbd189d8aee7a4f5b315e6742c69a23ca659a264d34b8d1c369cb1e`
**Chain of Custody ID**: `no-audit-event`

---

### 5. WAF Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
A web application firewall was detected.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "waf-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "POST / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:1.9.6.20) Gecko/ Firefox/3.6.1\r\nConnection: close\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\n_=<script>alert(1)</script>", "response": "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 919\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Type: text/html\r\nDate: Fri, 03 Jul 2026 12:36:30 GMT\r\nServer: CloudFront\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nVia: 1.1 0dce8ab12e84a7ddd9def0866355eec4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: HPbDhYdrSJhxlbsYo2n1tA5mHlof5DxpQT2-Y9YwFeHAZbwC4tpfGQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Error from cloudfront\r\nX-Content-Type-Options: nosniff\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<HTML><HEAD><META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=iso-8859-1\">\n<TITLE>ERROR: The request could not be satisfied</TITLE>\n</HEAD><BODY>\n<H1>403 ERROR</H1>\n<H2>The request could not be satisfied.</H2>\n<HR noshade size=\"1px\">\nRequest blocked.\nWe can't connect to the server for this app or website at this time. There might be too much traffic or a configuration error. Try again later, or contact the app or website owner.\n<BR clear=\"all\">\nIf you provide content to customers through CloudFront, you can find steps to troubleshoot and help prevent this error by reviewing the CloudFront documentation.\n<BR clear=\"all\">\n<HR noshade size=\"1px\">\n<PRE>\nGenerated by cloudfront (CloudFront)\nRequest ID: HPbDhYdrSJhxlbsYo2n1tA5mHlof5DxpQT2-Y9YwFeHAZbwC4tpfGQ==\n</PRE>\n<ADDRESS>\n</ADDRESS>\n</BODY></HTML>", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `618b8d3de22b57e47908bf8984629c41a891691cc9a36c2e195d150fb47c591b`
**Chain of Custody ID**: `no-audit-event`

---

### 6. TLS Version - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
TLS version detection is a security process used to determine the version of the Transport Layer Security (TLS) protocol used by a computer or server.
It is important to detect the TLS version in order to ensure secure communication between two computers or servers.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tls-version", "matched_at": "uat-bugbounty.nonprod.syfe.com:443", "url": "uat-bugbounty.nonprod.syfe.com", "request": null, "response": null, "extracted_results": ["tls12"]}]
```
**Artifact SHA-256 Hash**: `d0820c104d3a71737f736da61b3dcdd28149bcd9c0ff7fa77e57155fc9e8ccad`
**Chain of Custody ID**: `no-audit-event`

---

### 7. TLS Version - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
TLS version detection is a security process used to determine the version of the Transport Layer Security (TLS) protocol used by a computer or server.
It is important to detect the TLS version in order to ensure secure communication between two computers or servers.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tls-version", "matched_at": "uat-bugbounty.nonprod.syfe.com:443", "url": "uat-bugbounty.nonprod.syfe.com", "request": null, "response": null, "extracted_results": ["tls13"]}]
```
**Artifact SHA-256 Hash**: `4d37109dd5e70f93e349bbdce135c988bf9d2851954aaaf770986e7df3bb9f30`
**Chain of Custody ID**: `no-audit-event`

---

### 8. Add DOM EventListener - Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Identifies the use of JavaScript addEventListener calls in the DOM.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "addeventlistener-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11) AppleWebKit/619.23 (KHTML, like Gecko) Version/15.3.85 Safari/619.23\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9379\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f5462984cb6e-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:20 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:52 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=2jkLBjyJtHmcjHSl_bjNYgik7.IPxhGdrTlQLYtPYAE-1783082420.189464-1.0.1.1-YbPdCmR2VB9Nb0fbIioi55CwUGrxjygOCibCv.CHa.k; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 96a4883b278fc3b22dd3ef743bde6bc8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: K8B2w7MJ5GMM4lUb4a6B83WnzO-WtWvZS_t2pYd3Z4kQw77H1AUc-A==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/cs

...[truncated 193062 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `f884d2090f77f1a4569ff88ac62c1b3608fb8f48a21a804d67ddbabf5894d925`
**Chain of Custody ID**: `no-audit-event`

---

### 9. Email Extractor
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "email-extractor", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11) AppleWebKit/619.23 (KHTML, like Gecko) Version/15.3.85 Safari/619.23\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9379\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f5462984cb6e-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:20 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:52 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=2jkLBjyJtHmcjHSl_bjNYgik7.IPxhGdrTlQLYtPYAE-1783082420.189464-1.0.1.1-YbPdCmR2VB9Nb0fbIioi55CwUGrxjygOCibCv.CHa.k; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 96a4883b278fc3b22dd3ef743bde6bc8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: K8B2w7MJ5GMM4lUb4a6B83WnzO-WtWvZS_t2pYd3Z4kQw77H1AUc-A==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" inte

...[truncated 193073 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `fb1831ad9d66247f0026e11ccdad83c4ef5005528ea035a4fa9cb0d257e2098d`
**Chain of Custody ID**: `no-audit-event`

---

### 10. Weak Content Security Policy - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detected misconfigured CSP directives containing unsafe and overly permissive keywords that weakened resource loading restrictions. This configuration allowed high-risk script behaviors, resulting in reduced protection against XSS attacks.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11) AppleWebKit/619.23 (KHTML, like Gecko) Version/15.3.85 Safari/619.23\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9379\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f5462984cb6e-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:20 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:52 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=2jkLBjyJtHmcjHSl_bjNYgik7.IPxhGdrTlQLYtPYAE-1783082420.189464-1.0.1.1-YbPdCmR2VB9Nb0fbIioi55CwUGrxjygOCibCv.CHa.k; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 96a4883b278fc3b22dd3ef743bde6bc8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: K8B2w7MJ5GMM4lUb4a6B83WnzO-WtWvZS_t2pYd3Z4kQw77H1AUc-A==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" inte

...[truncated 193178 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `6f03a14045cef2186a64f39a98c2e5767a585f072845f85e5ba44d0c3fc135d0`
**Chain of Custody ID**: `no-audit-event`

---

### 11. Weak Content Security Policy - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detected misconfigured CSP directives containing unsafe and overly permissive keywords that weakened resource loading restrictions. This configuration allowed high-risk script behaviors, resulting in reduced protection against XSS attacks.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "weak-csp-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11) AppleWebKit/619.23 (KHTML, like Gecko) Version/15.3.85 Safari/619.23\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9379\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f5462984cb6e-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:20 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:52 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=2jkLBjyJtHmcjHSl_bjNYgik7.IPxhGdrTlQLYtPYAE-1783082420.189464-1.0.1.1-YbPdCmR2VB9Nb0fbIioi55CwUGrxjygOCibCv.CHa.k; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 96a4883b278fc3b22dd3ef743bde6bc8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: K8B2w7MJ5GMM4lUb4a6B83WnzO-WtWvZS_t2pYd3Z4kQw77H1AUc-A==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" inte

...[truncated 193178 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `6f03a14045cef2186a64f39a98c2e5767a585f072845f85e5ba44d0c3fc135d0`
**Chain of Custody ID**: `no-audit-event`

---

### 12. AWS Cloudfront service detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detect websites using AWS cloudfront service

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-cloudfront-service", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11) AppleWebKit/619.23 (KHTML, like Gecko) Version/15.3.85 Safari/619.23\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9379\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f5462984cb6e-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:20 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:52 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=2jkLBjyJtHmcjHSl_bjNYgik7.IPxhGdrTlQLYtPYAE-1783082420.189464-1.0.1.1-YbPdCmR2VB9Nb0fbIioi55CwUGrxjygOCibCv.CHa.k; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 96a4883b278fc3b22dd3ef743bde6bc8.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: K8B2w7MJ5GMM4lUb4a6B83WnzO-WtWvZS_t2pYd3Z4kQw77H1AUc-A==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css

...[truncated 193061 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `da5cb9eaf51dec793170d5b6841849dad40dc0339f58e2d2f0e185d4f839deaf`
**Chain of Custody ID**: `no-audit-event`

---

### 13. robots.txt endpoint prober
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "robots-txt-endpoint", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/robots.txt", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET /robots.txt HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_10_3 rv:2.0; so-DJ) AppleWebKit/533.15.6 (KHTML, like Gecko) Version/4.0.2 Safari/533.15.6\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Type: text/plain; charset=UTF-8\r\nDate: Fri, 03 Jul 2026 12:40:26 GMT\r\nServer: nginx\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nVary: Accept-Encoding\r\nVia: 1.1 d276e54ab5a1f0a1e054e54a253e8686.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: oaDpopPPDEUE2BnlrjApnYYIFkFrK1G1cHf9SocGQZDgBhdJIzF4Og==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\n\r\nUser-agent: *\nDisallow: /\n", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `7441c3c1ac420c558a9d8a5d0ebcf6c6778d9d5533eaf634109b264d3de2fc55`
**Chain of Custody ID**: `no-audit-event`

---

### 14. robots.txt file
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "robots-txt", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/robots.txt", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET /robots.txt HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (SS; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Type: text/plain; charset=UTF-8\r\nDate: Fri, 03 Jul 2026 12:40:35 GMT\r\nServer: nginx\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nVary: Accept-Encoding\r\nVia: 1.1 f58f65c11a806a22e60fa9ba6e024136.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: f8KHfiVeg-LNFL_lf1P42rYo7PXtaSxq4cz5qawMZ-sNP-mQj4ve9Q==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\n\r\nUser-agent: *\nDisallow: /\n", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `6d6ea815072a32f858b89d2915f9a13ece97e49576a2e840ae1ae7c4bb992ce3`
**Chain of Custody ID**: `no-audit-event`

---

### 15. robots.txt file
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "robots-txt", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/robots.txt", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET /robots.txt HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh: Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Type: text/plain; charset=UTF-8\r\nDate: Fri, 03 Jul 2026 12:40:35 GMT\r\nServer: nginx\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nVary: Accept-Encoding\r\nVia: 1.1 f73a7cbf2e1e78ce6ee99665c8f5cc82.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: cZzNT0Gdh64Dnx3WwuwCcPuc4hg1JPQsgPRBHShb8CrOtDozn9Fz4w==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\n\r\nUser-agent: *\nDisallow: /\n", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `5599dc2b8c8f13b9ee640eaf57997ab776fcdde6681a095a63a485a99c8655ab`
**Chain of Custody ID**: `no-audit-event`

---

### 16. Android Asset Links Configuration - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
The .well-known/assetlinks.json file was found on the target server. This file is used by Android applications to establish verified app-to-web domain associations through the Digital Asset Links protocol.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "assetlinks-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/.well-known/assetlinks.json", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET /.well-known/assetlinks.json HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Debian; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: public, max-age=0\r\nContent-Type: application/json; charset=UTF-8\r\nDate: Fri, 03 Jul 2026 12:40:35 GMT\r\nEtag: W/\"3bc-19ce39c43f8\"\r\nLast-Modified: Thu, 12 Mar 2026 19:53:15 GMT\r\nServer: nginx\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nVary: Accept-Encoding\r\nVary: Accept-Encoding\r\nVia: 1.1 d577fc82e350f4e3fb89ac31e2d02b44.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: c7RSTZj0F5okW54VgMjd3SJkSS5pcT61wkKWEuiwGZpyYTuYv3fJQg==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\n\r\n[\n  {\n    \"relation\": [\"delegate_permission/common.handle_all_urls\"],\n    \"target\": {\n      \"namespace\": \"android_app\",\n      \"package_name\": \"com.syfe\",\n      \"sha256_cert_fingerprints\": [\n        \"70:D2:35:7E:85:87:7F:8F:93:00:9C:75:9E:72:26:D9:B0:8A:98:C4:D4:76:4B:2C:C4:3E:52:7C:DD:6B:62:C7\"\n      ]\n    }\n  },\n  {\n    \"relation\": [\"delegate_permission/common.handle_all_urls\"],\n    \"target\": {\n      \"namespace\": \"android_app\",\n      \"package_name\": \"com.syfe.staging\",\n      \"sha256_cert_fingerprints\": [\n        \"FA:C6:17:45:DC:09:03:78:6F:B9:ED:E6:2A:96:2B:39:9F:73:48:F0:BB:6F:89:9B:83:32:66:75:91:03:3B:9C\"\n      ]\n    }\n  },\n  {\n    \"relation\": [\"delegate_permission/common.handle_all_urls\"],\n    \"target\": {\n      \"namespace\": \"android_app\",\n      \"package_name\": \"com.syfe.debug\",\n      \"sha256_cert_fingerprints\": [\n        \"FA:C6:17:45:DC:09:03:78:6F:B9:ED:E6:2A:96:2B:39:9F:73:48:F0:BB:6F:89:9B:83:32:66:75:91:03:3B:9C\"\n      ]\n    }\n  }\n]\n", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `6aab0357e2f8781de2bef330299081cb3c7212c6772a9d5d2f8db73aa6b189fa`
**Chain of Custody ID**: `no-audit-event`

---

### 17. Missing Subresource Integrity
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Checks if external script and stylesheet tags in the HTML response are missing the Subresource Integrity (SRI) attribute.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "missing-sri", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh, Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 9401\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f5d48b3446fc-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:43 GMT\r\nLast-Modified: Fri, 03 Jul 2026 10:04:01 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=dnnLoRFjOzO2v4PB4Q4AYhS_meegDQDRdwuakR_WPgA-1783082442.9686787-1.0.1.1-ydWHIEkCzAUd2SBriSX3wmFn5seSg3xaRg23idkP5uI; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 1e5e5b9011cc9c991b0704bf71880202.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: nxFh8e3EU4W5bTKrq8k_cDOeDC84bmXFjktLDLMitnbkLsBkUbxcAQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"s

...[truncated 193437 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `cab099bfaa62d7d8aefe50d46c5be6d1717ecfaca31313ac8af53e5cb54ad2c0`
**Chain of Custody ID**: `no-audit-event`

---

### 18. Missing Subresource Integrity
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Checks if external script and stylesheet tags in the HTML response are missing the Subresource Integrity (SRI) attribute.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "missing-sri", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.9\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 9401\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f5d4e9aacc8c-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:43 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:54 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=u03ijIgcirdB1KF1uVqrUGfQqL3cGiqu6zPyAwTPycE-1783082443.0291421-1.0.1.1-jWbXe.mhQL5.FqZmSmWGg.N0otuugVp41drGn4FF0kQ; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 d02e6230e17bdc1d6594ead12d216e02.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: SFY2-GpygEaLy4qVnoBigHyDrcwANJCr_LEuQoUzpjKO20y_PkU_wQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrit

...[truncated 193399 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `3b61c230871c1b29ceb88677575b2dd548ed95b140c85193d6fac8678f26f5c0`
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
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 9409\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6023aed117e-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:50 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:52 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=fAEjWcU9C09uSqaU7xJlwWhab5j3BNCRQ_UGNWiL3GI-1783082450.2786853-1.0.1.1-mIYepQfWYuHh.eSAf8l8owX7ppilEk9ohKb5LAXr7p4; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 193bbb3ba10e16f73ebc3630cbe35dc6.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: Lga5T8AZ-ufgzimmFzzrW_TepfP757VR6hu7JhnRi_BmHiFOLpn0Xw==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.

...[truncated 193105 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `4d27ee7fd66b2cb9ba94e49fdfe93e55f9cfd4a41cd84efc383c85693b6d08cf`
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
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 9409\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6023aed117e-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:50 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:52 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=fAEjWcU9C09uSqaU7xJlwWhab5j3BNCRQ_UGNWiL3GI-1783082450.2786853-1.0.1.1-mIYepQfWYuHh.eSAf8l8owX7ppilEk9ohKb5LAXr7p4; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 193bbb3ba10e16f73ebc3630cbe35dc6.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: Lga5T8AZ-ufgzimmFzzrW_TepfP757VR6hu7JhnRi_BmHiFOLpn0Xw==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.

...[truncated 193105 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `4d27ee7fd66b2cb9ba94e49fdfe93e55f9cfd4a41cd84efc383c85693b6d08cf`
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
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 9409\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6023aed117e-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:50 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:52 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=fAEjWcU9C09uSqaU7xJlwWhab5j3BNCRQ_UGNWiL3GI-1783082450.2786853-1.0.1.1-mIYepQfWYuHh.eSAf8l8owX7ppilEk9ohKb5LAXr7p4; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 193bbb3ba10e16f73ebc3630cbe35dc6.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: Lga5T8AZ-ufgzimmFzzrW_TepfP757VR6hu7JhnRi_BmHiFOLpn0Xw==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.

...[truncated 193105 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `4d27ee7fd66b2cb9ba94e49fdfe93e55f9cfd4a41cd84efc383c85693b6d08cf`
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
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 9409\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6023aed117e-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:50 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:52 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=fAEjWcU9C09uSqaU7xJlwWhab5j3BNCRQ_UGNWiL3GI-1783082450.2786853-1.0.1.1-mIYepQfWYuHh.eSAf8l8owX7ppilEk9ohKb5LAXr7p4; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 193bbb3ba10e16f73ebc3630cbe35dc6.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: Lga5T8AZ-ufgzimmFzzrW_TepfP757VR6hu7JhnRi_BmHiFOLpn0Xw==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.

...[truncated 193105 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `4d27ee7fd66b2cb9ba94e49fdfe93e55f9cfd4a41cd84efc383c85693b6d08cf`
**Chain of Custody ID**: `no-audit-event`

---

### 23. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 9409\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6023aed117e-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:50 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:52 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=fAEjWcU9C09uSqaU7xJlwWhab5j3BNCRQ_UGNWiL3GI-1783082450.2786853-1.0.1.1-mIYepQfWYuHh.eSAf8l8owX7ppilEk9ohKb5LAXr7p4; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 193bbb3ba10e16f73ebc3630cbe35dc6.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: Lga5T8AZ-ufgzimmFzzrW_TepfP757VR6hu7JhnRi_BmHiFOLpn0Xw==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.

...[truncated 193105 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `4d27ee7fd66b2cb9ba94e49fdfe93e55f9cfd4a41cd84efc383c85693b6d08cf`
**Chain of Custody ID**: `no-audit-event`

---

### 24. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 9409\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6023aed117e-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:50 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:52 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=fAEjWcU9C09uSqaU7xJlwWhab5j3BNCRQ_UGNWiL3GI-1783082450.2786853-1.0.1.1-mIYepQfWYuHh.eSAf8l8owX7ppilEk9ohKb5LAXr7p4; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 193bbb3ba10e16f73ebc3630cbe35dc6.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: Lga5T8AZ-ufgzimmFzzrW_TepfP757VR6hu7JhnRi_BmHiFOLpn0Xw==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.

...[truncated 193105 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `4d27ee7fd66b2cb9ba94e49fdfe93e55f9cfd4a41cd84efc383c85693b6d08cf`
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
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 9409\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6023aed117e-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:50 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:52 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=fAEjWcU9C09uSqaU7xJlwWhab5j3BNCRQ_UGNWiL3GI-1783082450.2786853-1.0.1.1-mIYepQfWYuHh.eSAf8l8owX7ppilEk9ohKb5LAXr7p4; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 193bbb3ba10e16f73ebc3630cbe35dc6.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: Lga5T8AZ-ufgzimmFzzrW_TepfP757VR6hu7JhnRi_BmHiFOLpn0Xw==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"sty

...[truncated 193086 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `709738243e0abdf9f6982b9bac92e99bb18746059a9780f3bf67c368e09525ab`
**Chain of Custody ID**: `no-audit-event`

---

### 26. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/125.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9409\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6031db3066f-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:50 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:54 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=_m7wB.10sc8strCQVbtNUzEeHof.5hSMt5dZsSVWago-1783082450.4119382-1.0.1.1-ByLxJ.OA3kO3mFkWOHir85H_uqzrwmeAejYsyKNyr8k; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 e1424dbcbfe51e4d0b1fe1627b32f01e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 1h1ha53SIEraJ7iQnABR--hqkYALnH9l9IK9oCtSyhLjWZgMBMuFxQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha3

...[truncated 193042 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `b9d7c42b533409f9dc5e15342602fe6045fa836a578fc7c1e243f117d1f7fe0e`
**Chain of Custody ID**: `no-audit-event`

---

### 27. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/125.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9409\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6031db3066f-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:50 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:54 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=_m7wB.10sc8strCQVbtNUzEeHof.5hSMt5dZsSVWago-1783082450.4119382-1.0.1.1-ByLxJ.OA3kO3mFkWOHir85H_uqzrwmeAejYsyKNyr8k; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 e1424dbcbfe51e4d0b1fe1627b32f01e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 1h1ha53SIEraJ7iQnABR--hqkYALnH9l9IK9oCtSyhLjWZgMBMuFxQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha3

...[truncated 193042 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `b9d7c42b533409f9dc5e15342602fe6045fa836a578fc7c1e243f117d1f7fe0e`
**Chain of Custody ID**: `no-audit-event`

---

### 28. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/125.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9409\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6031db3066f-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:50 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:54 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=_m7wB.10sc8strCQVbtNUzEeHof.5hSMt5dZsSVWago-1783082450.4119382-1.0.1.1-ByLxJ.OA3kO3mFkWOHir85H_uqzrwmeAejYsyKNyr8k; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 e1424dbcbfe51e4d0b1fe1627b32f01e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 1h1ha53SIEraJ7iQnABR--hqkYALnH9l9IK9oCtSyhLjWZgMBMuFxQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha3

...[truncated 193042 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `b9d7c42b533409f9dc5e15342602fe6045fa836a578fc7c1e243f117d1f7fe0e`
**Chain of Custody ID**: `no-audit-event`

---

### 29. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/125.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9409\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6031db3066f-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:50 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:54 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=_m7wB.10sc8strCQVbtNUzEeHof.5hSMt5dZsSVWago-1783082450.4119382-1.0.1.1-ByLxJ.OA3kO3mFkWOHir85H_uqzrwmeAejYsyKNyr8k; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 e1424dbcbfe51e4d0b1fe1627b32f01e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 1h1ha53SIEraJ7iQnABR--hqkYALnH9l9IK9oCtSyhLjWZgMBMuFxQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha3

...[truncated 193042 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `b9d7c42b533409f9dc5e15342602fe6045fa836a578fc7c1e243f117d1f7fe0e`
**Chain of Custody ID**: `no-audit-event`

---

### 30. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/125.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9409\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6031db3066f-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:50 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:54 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=_m7wB.10sc8strCQVbtNUzEeHof.5hSMt5dZsSVWago-1783082450.4119382-1.0.1.1-ByLxJ.OA3kO3mFkWOHir85H_uqzrwmeAejYsyKNyr8k; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 e1424dbcbfe51e4d0b1fe1627b32f01e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 1h1ha53SIEraJ7iQnABR--hqkYALnH9l9IK9oCtSyhLjWZgMBMuFxQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha3

...[truncated 193042 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `b9d7c42b533409f9dc5e15342602fe6045fa836a578fc7c1e243f117d1f7fe0e`
**Chain of Custody ID**: `no-audit-event`

---

### 31. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/125.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9409\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6031db3066f-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:50 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:54 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=_m7wB.10sc8strCQVbtNUzEeHof.5hSMt5dZsSVWago-1783082450.4119382-1.0.1.1-ByLxJ.OA3kO3mFkWOHir85H_uqzrwmeAejYsyKNyr8k; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 e1424dbcbfe51e4d0b1fe1627b32f01e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 1h1ha53SIEraJ7iQnABR--hqkYALnH9l9IK9oCtSyhLjWZgMBMuFxQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha3

...[truncated 193042 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `b9d7c42b533409f9dc5e15342602fe6045fa836a578fc7c1e243f117d1f7fe0e`
**Chain of Custody ID**: `no-audit-event`

---

### 32. AWS Service - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detect if AWS is being used in the application.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/125.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9409\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6031db3066f-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:40:50 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:54 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=_m7wB.10sc8strCQVbtNUzEeHof.5hSMt5dZsSVWago-1783082450.4119382-1.0.1.1-ByLxJ.OA3kO3mFkWOHir85H_uqzrwmeAejYsyKNyr8k; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 e1424dbcbfe51e4d0b1fe1627b32f01e.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: 1h1ha53SIEraJ7iQnABR--hqkYALnH9l9IK9oCtSyhLjWZgMBMuFxQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha384-aQha2EPqZQ1m6N2E

...[truncated 193023 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `f4a7a7c280c2a448e4a2011c4ed1fb8352fd5deb890d94a8a1453e9a5be9942f`
**Chain of Custody ID**: `no-audit-event`

---

### 33. AWS Service - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Detect if AWS is being used in the application.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aws-detect", "matched_at": "http://uat-bugbounty.nonprod.syfe.com", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/125.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 301 Moved Permanently\r\nConnection: close\r\nContent-Length: 167\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Type: text/html\r\nDate: Fri, 03 Jul 2026 12:40:50 GMT\r\nLocation: https://uat-bugbounty.nonprod.syfe.com/\r\nServer: CloudFront\r\nVia: 1.1 02aeb80d728072644f7421bc80763486.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: B06dTodzBuneoDcXlCbl-XrWPVp-gjvnPUZDnGiMus1rxSYJD4rQDg==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Redirect from cloudfront\r\nX-Content-Type-Options: nosniff\r\n\r\n", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `5251ca6aecba8c2dedb4d9ccdcb887a1d901964e37db591608ea21f04b38d6eb`
**Chain of Custody ID**: `no-audit-event`

---

### 34. Missing Cookie SameSite Strict
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Identified cookies that lacked the samesite=strict attribute, which prevented enforcement of restrictions on cross-domain cookie transmission.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "missing-cookie-samesite-strict", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9425\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6684b033f8a-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:41:06 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:29:50 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=jhOoRoHcmEhM_hltukalMSnmIsL9T9NwVonfue786n4-1783082466.6024976-1.0.1.1-QoYhmd2ydNbJfdl5EMyXo3S35VW9s2S21d1iCpo.tjk; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 47bef4917f5436b97fdfd2d01530aff4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: LD7iDqf6wcV17HnsfFIPnls_pse2H9XMIaGWXW3mjxm4e2_4wXZyXQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha384-aQ

...[truncated 193219 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `286a8ac490307637049f918ea64323d81c0c4626e77fee5f09df34fd1d602a8c`
**Chain of Custody ID**: `no-audit-event`

---

### 35. Missing Cookie SameSite Strict
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Identified cookies that lacked the samesite=strict attribute, which prevented enforcement of restrictions on cross-domain cookie transmission.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "missing-cookie-samesite-strict", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9425\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6689a96e09d-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:41:06 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:54 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=T7zLRTDA6KuhkAD3_reLJ4R9MnuhT0I2JWvudV8D51A-1783082466.6522164-1.0.1.1-W7awyFChxTUHeo.XsQwOt9DXi0HrEk5zVDoPLGLu3_s; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 118f8e0e3095ec01cc77f07b1d354dac.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: d3A3-PQy6RoulHgtw9EMgCbbOBwTvAGhLY3Irr95tUJQmaTL0bCXGA==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha384-

...[truncated 193221 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `d3774ed8ff6034a2b1af518b9c74dfa1fb3541cfde48c0f5917a6fb1002671b3`
**Chain of Custody ID**: `no-audit-event`

---

### 36. Wappalyzer Technology Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9425\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6684b033f8a-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:41:06 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:29:50 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=jhOoRoHcmEhM_hltukalMSnmIsL9T9NwVonfue786n4-1783082466.6024976-1.0.1.1-QoYhmd2ydNbJfdl5EMyXo3S35VW9s2S21d1iCpo.tjk; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 47bef4917f5436b97fdfd2d01530aff4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: LD7iDqf6wcV17HnsfFIPnls_pse2H9XMIaGWXW3mjxm4e2_4wXZyXQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12

...[truncated 193018 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `34a918a8fe067fdbb3b5e84e1e8d07e4d04b186aee253428be0e44ddd7bfbc81`
**Chain of Custody ID**: `no-audit-event`

---

### 37. Wappalyzer Technology Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9425\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6684b033f8a-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:41:06 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:29:50 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=jhOoRoHcmEhM_hltukalMSnmIsL9T9NwVonfue786n4-1783082466.6024976-1.0.1.1-QoYhmd2ydNbJfdl5EMyXo3S35VW9s2S21d1iCpo.tjk; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 47bef4917f5436b97fdfd2d01530aff4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: LD7iDqf6wcV17HnsfFIPnls_pse2H9XMIaGWXW3mjxm4e2_4wXZyXQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12

...[truncated 193018 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `34a918a8fe067fdbb3b5e84e1e8d07e4d04b186aee253428be0e44ddd7bfbc81`
**Chain of Custody ID**: `no-audit-event`

---

### 38. Wappalyzer Technology Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9425\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6684b033f8a-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:41:06 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:29:50 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=jhOoRoHcmEhM_hltukalMSnmIsL9T9NwVonfue786n4-1783082466.6024976-1.0.1.1-QoYhmd2ydNbJfdl5EMyXo3S35VW9s2S21d1iCpo.tjk; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 47bef4917f5436b97fdfd2d01530aff4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: LD7iDqf6wcV17HnsfFIPnls_pse2H9XMIaGWXW3mjxm4e2_4wXZyXQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12

...[truncated 193018 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `34a918a8fe067fdbb3b5e84e1e8d07e4d04b186aee253428be0e44ddd7bfbc81`
**Chain of Custody ID**: `no-audit-event`

---

### 39. Wappalyzer Technology Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9425\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6684b033f8a-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:41:06 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:29:50 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=jhOoRoHcmEhM_hltukalMSnmIsL9T9NwVonfue786n4-1783082466.6024976-1.0.1.1-QoYhmd2ydNbJfdl5EMyXo3S35VW9s2S21d1iCpo.tjk; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 47bef4917f5436b97fdfd2d01530aff4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: LD7iDqf6wcV17HnsfFIPnls_pse2H9XMIaGWXW3mjxm4e2_4wXZyXQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12

...[truncated 193018 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `34a918a8fe067fdbb3b5e84e1e8d07e4d04b186aee253428be0e44ddd7bfbc81`
**Chain of Custody ID**: `no-audit-event`

---

### 40. Wappalyzer Technology Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9425\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6689a96e09d-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:41:06 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:54 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=T7zLRTDA6KuhkAD3_reLJ4R9MnuhT0I2JWvudV8D51A-1783082466.6522164-1.0.1.1-W7awyFChxTUHeo.XsQwOt9DXi0HrEk5zVDoPLGLu3_s; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 118f8e0e3095ec01cc77f07b1d354dac.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: d3A3-PQy6RoulHgtw9EMgCbbOBwTvAGhLY3Irr95tUJQmaTL0bCXGA==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ

...[truncated 193020 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `ed4a8f94c2ac1c073e3bc88d4d3db485782f0e5ba38c7bf52199a35be4bc2f11`
**Chain of Custody ID**: `no-audit-event`

---

### 41. Wappalyzer Technology Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9425\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6684b033f8a-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:41:06 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:29:50 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=jhOoRoHcmEhM_hltukalMSnmIsL9T9NwVonfue786n4-1783082466.6024976-1.0.1.1-QoYhmd2ydNbJfdl5EMyXo3S35VW9s2S21d1iCpo.tjk; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 47bef4917f5436b97fdfd2d01530aff4.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: LD7iDqf6wcV17HnsfFIPnls_pse2H9XMIaGWXW3mjxm4e2_4wXZyXQ==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12

...[truncated 193018 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `34a918a8fe067fdbb3b5e84e1e8d07e4d04b186aee253428be0e44ddd7bfbc81`
**Chain of Custody ID**: `no-audit-event`

---

### 42. Wappalyzer Technology Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9425\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6689a96e09d-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:41:06 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:54 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=T7zLRTDA6KuhkAD3_reLJ4R9MnuhT0I2JWvudV8D51A-1783082466.6522164-1.0.1.1-W7awyFChxTUHeo.XsQwOt9DXi0HrEk5zVDoPLGLu3_s; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 118f8e0e3095ec01cc77f07b1d354dac.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: d3A3-PQy6RoulHgtw9EMgCbbOBwTvAGhLY3Irr95tUJQmaTL0bCXGA==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ

...[truncated 193020 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `ed4a8f94c2ac1c073e3bc88d4d3db485782f0e5ba38c7bf52199a35be4bc2f11`
**Chain of Custody ID**: `no-audit-event`

---

### 43. Wappalyzer Technology Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9425\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6689a96e09d-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:41:06 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:54 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=T7zLRTDA6KuhkAD3_reLJ4R9MnuhT0I2JWvudV8D51A-1783082466.6522164-1.0.1.1-W7awyFChxTUHeo.XsQwOt9DXi0HrEk5zVDoPLGLu3_s; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 118f8e0e3095ec01cc77f07b1d354dac.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: d3A3-PQy6RoulHgtw9EMgCbbOBwTvAGhLY3Irr95tUJQmaTL0bCXGA==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ

...[truncated 193020 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `ed4a8f94c2ac1c073e3bc88d4d3db485782f0e5ba38c7bf52199a35be4bc2f11`
**Chain of Custody ID**: `no-audit-event`

---

### 44. Wappalyzer Technology Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9425\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6689a96e09d-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:41:06 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:54 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=T7zLRTDA6KuhkAD3_reLJ4R9MnuhT0I2JWvudV8D51A-1783082466.6522164-1.0.1.1-W7awyFChxTUHeo.XsQwOt9DXi0HrEk5zVDoPLGLu3_s; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 118f8e0e3095ec01cc77f07b1d354dac.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: d3A3-PQy6RoulHgtw9EMgCbbOBwTvAGhLY3Irr95tUJQmaTL0bCXGA==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ

...[truncated 193020 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `ed4a8f94c2ac1c073e3bc88d4d3db485782f0e5ba38c7bf52199a35be4bc2f11`
**Chain of Custody ID**: `no-audit-event`

---

### 45. Wappalyzer Technology Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9425\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6689a96e09d-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:41:06 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:35:54 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=T7zLRTDA6KuhkAD3_reLJ4R9MnuhT0I2JWvudV8D51A-1783082466.6522164-1.0.1.1-W7awyFChxTUHeo.XsQwOt9DXi0HrEk5zVDoPLGLu3_s; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 118f8e0e3095ec01cc77f07b1d354dac.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: d3A3-PQy6RoulHgtw9EMgCbbOBwTvAGhLY3Irr95tUJQmaTL0bCXGA==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ

...[truncated 193020 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `ed4a8f94c2ac1c073e3bc88d4d3db485782f0e5ba38c7bf52199a35be4bc2f11`
**Chain of Custody ID**: `no-audit-event`

---

### 46. Detect Sentry Instance
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "detect-sentry", "matched_at": "https://uat-bugbounty.nonprod.syfe.com", "url": "https://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 5.1; rv:52.0) Gecko/20100101 Firefox/52.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 9435\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6a67f633c6a-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:41:16 GMT\r\nLast-Modified: Fri, 03 Jul 2026 10:20:18 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=1j9PMEuX6hAncCZzmQ5YiAtL2cUcOH9OHSM1oDtvmSg-1783082476.5524125-1.0.1.1-i7wVSbZS0oNtlghxLrRbVG6nuuW6qOQChuURFHbCrI4; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 193bbb3ba10e16f73ebc3630cbe35dc6.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: VHnF_CoKxeZ1cDlFoAhxdJT5f4UyXs1lB6iMU8wt_adIIiUi1B8U5A==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"stylesheet\" type=\"text/css\" integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEw

...[truncated 193083 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `2d6930eb5b43c75696ff312bced5d6e273ddecc1aa3fb4ff021b360611b6cb6a`
**Chain of Custody ID**: `no-audit-event`

---

### 47. Detect Sentry Instance
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "detect-sentry", "matched_at": "https://uat-bugbounty.nonprod.syfe.com/", "url": "http://uat-bugbounty.nonprod.syfe.com", "request": "GET / HTTP/1.1\r\nHost: uat-bugbounty.nonprod.syfe.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAge: 9435\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCf-Cache-Status: HIT\r\nCf-Ray: a155f6a70e98ff6d-BOM\r\nContent-Security-Policy: frame-ancestors 'self' https://*.webflow.com http://*.webflow.com http://*.webflow.io http://webflow.com https://webflow.com\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 03 Jul 2026 12:41:16 GMT\r\nLast-Modified: Fri, 03 Jul 2026 11:29:50 GMT\r\nLink: <https://cdn.prod.website-files.com>; rel=preconnect; crossorigin, <https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css>; rel=preload; as=style; crossorigin; integrity=\"sha384-aQha2EPqZQ1m6N2EEnJ12JWQIHzL2KEwBWjAFmitLQa2i4oNjrOW24FZGnfoPt+g\", <https://www.googletagmanager.com>; rel=preconnect, <https://static.zdassets.com>; rel=preconnect\r\nServer: nginx\r\nSet-Cookie: _cfuvid=ZXhqrXHi39se1.RH4lHd4c1JzkuOSh5E_nDQEtSKYqg-1783082476.6457489-1.0.1.1-rzTgzix7Pgsy3Nw.xL7rrfsKSTLnkZhC8SbGt3JajvU; HttpOnly; SameSite=None; Secure; Path=/; Domain=webflow.io\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nSurrogate-Control: max-age=432000\r\nSurrogate-Key: syfe-v4.webflow.io 64d3542964db4e6ae6de7d1d pageId:69d5de9a9e57d98e23cd52bb 6875fc5787df33dc30f5b75e\r\nVary: accept-encoding\r\nVia: 1.1 1e5e5b9011cc9c991b0704bf71880202.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Id: YFw6H30fQuCKX4JNIAIFsf8I7-lzHKdafpIPHCRXP6r8d8ZEO6GbcA==\r\nX-Amz-Cf-Pop: DEL54-P5\r\nX-Cache: Miss from cloudfront\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Lambda-Id: aaf4ab41-6120-4754-b58e-439353b5fea7\r\nX-Wf-Region: us-east-1\r\n\r\n<!DOCTYPE html><!-- Last Published: Fri Jul 03 2026 09:35:43 GMT+0000 (Coordinated Universal Time) --><html data-wf-domain=\"syfe-v4.webflow.io\" data-wf-page=\"69d5de9a9e57d98e23cd52bb\" data-wf-site=\"64d3542964db4e6ae6de7d1d\" lang=\"en\"><head><meta charset=\"utf-8\"/><link href=\"https://cdn.prod.website-files.com\" rel=\"preconnect\" crossorigin=\"anonymous\"/><title>Syfe: Invest, Trade and Save in Singapore</title><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"description\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" property=\"og:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" property=\"og:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" property=\"og:image\"/><meta content=\"Syfe: Invest, Trade and Save in Singapore\" name=\"twitter:title\"/><meta content=\"Fastest-growing MAS-regulated digital investment platform in Singapore. Invest your cash and SRS easily within minutes. Invest with any amount and start earning today.\" name=\"twitter:description\"/><meta content=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/66e14507296bdb1ed3c04bc8_Syfe%20Homepage%20Open%20Graph.png\" name=\"twitter:image\"/><meta property=\"og:type\" content=\"website\"/><meta content=\"summary_large_image\" name=\"twitter:card\"/><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"/><link href=\"https://cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d/css/syfe-v4.shared.69085ad84.min.css\" rel=\"s

...[truncated 193164 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a64344812104ac46d2c65970c8b9db4a748d2d9703b657ae2d54aa4ac27fc240`
**Chain of Custody ID**: `no-audit-event`

---

### 48. DNS SaaS Service Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
A CNAME DNS record was discovered

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "dns-saas-service-detection", "matched_at": "uat-bugbounty.nonprod.syfe.com", "url": "uat-bugbounty.nonprod.syfe.com", "request": ";; opcode: QUERY, status: NOERROR, id: 17930\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t CNAME\n", "response": ";; opcode: QUERY, status: NOERROR, id: 17930\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 512\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t CNAME\n\n;; ANSWER SECTION:\nuat-bugbounty.nonprod.syfe.com.\t60\tIN\tCNAME\td2uz6yy7bd3xp8.cloudfront.net.\n", "extracted_results": ["d2uz6yy7bd3xp8.cloudfront.net"]}]
```
**Artifact SHA-256 Hash**: `ddacb7895e7dfe7cc6c0e204de6f2b49b03465f2424470254eae1ae8f4203e79`
**Chain of Custody ID**: `no-audit-event`

---

### 49. AAAA Record - IPv6 Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
An AAAA record was detected. AAAA records are used to map domain names to IPv6 addresses.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aaaa-fingerprint", "matched_at": "uat-bugbounty.nonprod.syfe.com", "url": "uat-bugbounty.nonprod.syfe.com", "request": ";; opcode: QUERY, status: NOERROR, id: 23193\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t AAAA\n", "response": ";; opcode: QUERY, status: NOERROR, id: 23193\n;; flags: qr rd ra; QUERY: 1, ANSWER: 9, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 512\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t AAAA\n\n;; ANSWER SECTION:\nuat-bugbounty.nonprod.syfe.com.\t60\tIN\tCNAME\td2uz6yy7bd3xp8.cloudfront.net.\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:257b:c00:3:b73d:9700:93a1\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:257b:1800:3:b73d:9700:93a1\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:257b:1e00:3:b73d:9700:93a1\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:257b:e400:3:b73d:9700:93a1\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:257b:d000:3:b73d:9700:93a1\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:257b:6600:3:b73d:9700:93a1\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:257b:8400:3:b73d:9700:93a1\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:257b:8800:3:b73d:9700:93a1\n", "extracted_results": ["2600:9000:257b:6600:3:b73d:9700:93a1", "2600:9000:257b:8400:3:b73d:9700:93a1", "2600:9000:257b:8800:3:b73d:9700:93a1", "2600:9000:257b:c00:3:b73d:9700:93a1", "2600:9000:257b:1800:3:b73d:9700:93a1", "2600:9000:257b:1e00:3:b73d:9700:93a1", "2600:9000:257b:e400:3:b73d:9700:93a1", "2600:9000:257b:d000:3:b73d:9700:93a1"]}]
```
**Artifact SHA-256 Hash**: `27f3c94cef971cac717866f83ca27f359fef8639904c6609021901b30048f74f`
**Chain of Custody ID**: `no-audit-event`

---

### 50. AAAA Record - IPv6 Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
An AAAA record was detected. AAAA records are used to map domain names to IPv6 addresses.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "aaaa-fingerprint", "matched_at": "uat-bugbounty.nonprod.syfe.com", "url": "uat-bugbounty.nonprod.syfe.com", "request": ";; opcode: QUERY, status: NOERROR, id: 21822\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t AAAA\n", "response": ";; opcode: QUERY, status: NOERROR, id: 21822\n;; flags: qr rd ra; QUERY: 1, ANSWER: 9, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t AAAA\n\n;; ANSWER SECTION:\nuat-bugbounty.nonprod.syfe.com.\t60\tIN\tCNAME\td2uz6yy7bd3xp8.cloudfront.net.\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:2576:d800:3:b73d:9700:93a1\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:2576:e600:3:b73d:9700:93a1\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:2576:1200:3:b73d:9700:93a1\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:2576:fe00:3:b73d:9700:93a1\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:2576:aa00:3:b73d:9700:93a1\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:2576:2800:3:b73d:9700:93a1\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:2576:f000:3:b73d:9700:93a1\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tAAAA\t2600:9000:2576:7400:3:b73d:9700:93a1\n", "extracted_results": ["2600:9000:2576:1200:3:b73d:9700:93a1", "2600:9000:2576:fe00:3:b73d:9700:93a1", "2600:9000:2576:aa00:3:b73d:9700:93a1", "2600:9000:2576:2800:3:b73d:9700:93a1", "2600:9000:2576:f000:3:b73d:9700:93a1", "2600:9000:2576:7400:3:b73d:9700:93a1", "2600:9000:2576:d800:3:b73d:9700:93a1", "2600:9000:2576:e600:3:b73d:9700:93a1"]}]
```
**Artifact SHA-256 Hash**: `2d912fcc751648c81f5a39fc0e75c553fbbe49b40572570b658a5f282a135cf6`
**Chain of Custody ID**: `no-audit-event`

---

### 51. DNS SaaS Service Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
A CNAME DNS record was discovered

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "dns-saas-service-detection", "matched_at": "uat-bugbounty.nonprod.syfe.com", "url": "uat-bugbounty.nonprod.syfe.com", "request": ";; opcode: QUERY, status: NOERROR, id: 3377\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t CNAME\n", "response": ";; opcode: QUERY, status: NOERROR, id: 3377\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t CNAME\n\n;; ANSWER SECTION:\nuat-bugbounty.nonprod.syfe.com.\t60\tIN\tCNAME\td2uz6yy7bd3xp8.cloudfront.net.\n", "extracted_results": ["d2uz6yy7bd3xp8.cloudfront.net"]}]
```
**Artifact SHA-256 Hash**: `ffd2c8f4d700f5349bbee8cf132380baecdc548a110cce5248b3d41af115e68c`
**Chain of Custody ID**: `no-audit-event`

---

### 52. NS Record Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
An NS record was detected. An NS record delegates a subdomain to a set of name servers.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "nameserver-fingerprint", "matched_at": "uat-bugbounty.nonprod.syfe.com", "url": "uat-bugbounty.nonprod.syfe.com", "request": ";; opcode: QUERY, status: NOERROR, id: 19954\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t NS\n", "response": ";; opcode: QUERY, status: NOERROR, id: 19954\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 512\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t NS\n\n;; ANSWER SECTION:\nuat-bugbounty.nonprod.syfe.com.\t60\tIN\tCNAME\td2uz6yy7bd3xp8.cloudfront.net.\nd2uz6yy7bd3xp8.cloudfront.net.\t17691\tIN\tNS\tns-247.awsdns-30.com.\nd2uz6yy7bd3xp8.cloudfront.net.\t17691\tIN\tNS\tns-890.awsdns-47.net.\nd2uz6yy7bd3xp8.cloudfront.net.\t17691\tIN\tNS\tns-1129.awsdns-13.org.\nd2uz6yy7bd3xp8.cloudfront.net.\t17691\tIN\tNS\tns-1711.awsdns-21.co.uk.\n", "extracted_results": ["ns-247.awsdns-30.com.", "ns-890.awsdns-47.net.", "ns-1129.awsdns-13.org.", "ns-1711.awsdns-21.co.uk."]}]
```
**Artifact SHA-256 Hash**: `b09867aa5ca02d18262f9b188075748c4c157d92073ecb2d18065aa81c110bea`
**Chain of Custody ID**: `no-audit-event`

---

### 53. CAA Record
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
A CAA record was discovered. A CAA record is used to specify which certificate authorities (CAs) are allowed to issue certificates for a domain.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "caa-fingerprint", "matched_at": "uat-bugbounty.nonprod.syfe.com", "url": "uat-bugbounty.nonprod.syfe.com", "request": ";; opcode: QUERY, status: NOERROR, id: 3840\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t CAA\n", "response": ";; opcode: QUERY, status: NOERROR, id: 3840\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t CAA\n\n;; ANSWER SECTION:\nuat-bugbounty.nonprod.syfe.com.\t60\tIN\tCNAME\td2uz6yy7bd3xp8.cloudfront.net.\n\n;; AUTHORITY SECTION:\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tSOA\tns-1129.awsdns-13.org. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400\n", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `c1eca461c1df3d82573147200138cf24f04c33f1daa054a9be994f30d1bdeaca`
**Chain of Custody ID**: `no-audit-event`

---

### 54. NS Record Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
An NS record was detected. An NS record delegates a subdomain to a set of name servers.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "nameserver-fingerprint", "matched_at": "uat-bugbounty.nonprod.syfe.com", "url": "uat-bugbounty.nonprod.syfe.com", "request": ";; opcode: QUERY, status: NOERROR, id: 50579\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t NS\n", "response": ";; opcode: QUERY, status: NOERROR, id: 50579\n;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t NS\n\n;; ANSWER SECTION:\nuat-bugbounty.nonprod.syfe.com.\t60\tIN\tCNAME\td2uz6yy7bd3xp8.cloudfront.net.\nd2uz6yy7bd3xp8.cloudfront.net.\t172800\tIN\tNS\tns-1129.awsdns-13.org.\nd2uz6yy7bd3xp8.cloudfront.net.\t172800\tIN\tNS\tns-1711.awsdns-21.co.uk.\nd2uz6yy7bd3xp8.cloudfront.net.\t172800\tIN\tNS\tns-247.awsdns-30.com.\nd2uz6yy7bd3xp8.cloudfront.net.\t172800\tIN\tNS\tns-890.awsdns-47.net.\n", "extracted_results": ["ns-247.awsdns-30.com.", "ns-890.awsdns-47.net.", "ns-1129.awsdns-13.org.", "ns-1711.awsdns-21.co.uk."]}]
```
**Artifact SHA-256 Hash**: `35057439eadd6e26db83203d938c3b71a699e33da5052f4e7f706c7809e92f34`
**Chain of Custody ID**: `no-audit-event`

---

### 55. CAA Record
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
A CAA record was discovered. A CAA record is used to specify which certificate authorities (CAs) are allowed to issue certificates for a domain.

#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "caa-fingerprint", "matched_at": "uat-bugbounty.nonprod.syfe.com", "url": "uat-bugbounty.nonprod.syfe.com", "request": ";; opcode: QUERY, status: NOERROR, id: 15677\n;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t CAA\n", "response": ";; opcode: QUERY, status: NOERROR, id: 15677\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 512\n\n;; QUESTION SECTION:\n;uat-bugbounty.nonprod.syfe.com.\tIN\t CAA\n\n;; ANSWER SECTION:\nuat-bugbounty.nonprod.syfe.com.\t60\tIN\tCNAME\td2uz6yy7bd3xp8.cloudfront.net.\n\n;; AUTHORITY SECTION:\nd2uz6yy7bd3xp8.cloudfront.net.\t60\tIN\tSOA\tns-1129.awsdns-13.org. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400\n", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `9811c94da69914ed92c32545d926f2510820475af27633d281748b8571ebbabe`
**Chain of Custody ID**: `no-audit-event`

---

### 56. Detect SSL Certificate Issuer
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Extract the issuer's organization from the target's certificate. Issuers are entities which sign and distribute certificates.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "ssl-issuer", "matched_at": "uat-bugbounty.nonprod.syfe.com:443", "url": "uat-bugbounty.nonprod.syfe.com", "request": null, "response": null, "extracted_results": ["Amazon"]}]
```
**Artifact SHA-256 Hash**: `9025e4c13ae7b83117ff46fe6c5239d4130ec02b10b2989bc3d7ccbe54a6f4a0`
**Chain of Custody ID**: `no-audit-event`

---

### 57. SSL DNS Names
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Extract the Subject Alternative Name (SAN) from the target's certificate. SAN facilitates the usage of additional hostnames with the same certificate.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "ssl-dns-names", "matched_at": "uat-bugbounty.nonprod.syfe.com:443", "url": "uat-bugbounty.nonprod.syfe.com", "request": null, "response": null, "extracted_results": ["nonprod.syfe.com", "*.nonprod.syfe.com"]}]
```
**Artifact SHA-256 Hash**: `fad23b0aac99a4bcd914b6cdb2da08e3bc75f227bdb6e0f5b5713e7a8606cc24`
**Chain of Custody ID**: `no-audit-event`

---

### 58. Wildcard TLS Certificate
- **Severity**: info
- **Type**: unknown
- **Target**: unknown

#### Description
Checks a sites certificate to see if there are wildcard CN or SAN entries.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "wildcard-tls", "matched_at": "uat-bugbounty.nonprod.syfe.com:443", "url": "uat-bugbounty.nonprod.syfe.com", "request": null, "response": null, "extracted_results": ["CN: *.nonprod.syfe.com", " SAN: [*.nonprod.syfe.com nonprod.syfe.com]"]}]
```
**Artifact SHA-256 Hash**: `63810d2860634a1b34a9e727b96df5658a1062f5bfa26ee950d185449e421431`
**Chain of Custody ID**: `no-audit-event`

---
