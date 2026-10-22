# Gin & Juice Shop: bounded Burp MCP assessment

Date: 2026-10-22. Target: `https://ginandjuice.shop`, explicitly requested by
the operator. The site's home page describes it as a deliberately vulnerable
application for scanner testing: <https://ginandjuice.shop/>.

The live Burp Community process served MCP version 0.1.1 on IPv4 loopback
port 8081. Health and initialization returned 200. Testing used its actual
`send_http_request` tool for 16 sequential target GET requests, spaced apart
during probe batches. Independent Chromium validation allowed only GET
requests to this exact hostname, blocked service workers, and capped requests
at 20; it used 18 requests including page assets. No account changes, purchases,
database extraction, brute force, broad active scan or third-party callback
was performed.

## Observed target findings

### 1. Boolean SQL injection in catalog category

Endpoint: `GET /catalog`, parameter `category`.

| Input | HTTP status | Distinct product links |
| --- | --- | --- |
| `Gin` | 200 | 9 |
| `Gin' AND '1'='1` | 200 | 9 |
| `Gin' AND '1'='2` | 200 | 0 |
| True condition, second request | 200 | 9 |
| False condition, second request | 200 | 0 |

The repeated true/false differential is reproducible evidence of SQL condition
evaluation through the category input. Broader database access or write impact
was not tested. Risk assessment: high potential impact; the demonstrated effect
is manipulation of catalog query results only.

Repeat request IDs:

- True: `req-577a2c1ddb8141c381d49e248ca45aa7`.
- False: `req-c3ee283a66e04c3fb250c8f0d643322d`.

Remediation: bind category as a parameter in a prepared SQL statement and
allow only known category values. Do not concatenate it into SQL text.

### 2. Reflected XSS in catalog search JavaScript context

Endpoint: `GET /catalog`, parameter `searchTerm`.

Harmless proof input:

```text
\';window.__osopProbe=721;//
```

The response captured through Burp contained:

```javascript
var searchText = '\\';window.__osopProbe=721;//';
```

A separate live Chromium navigation to the same URL returned HTTP 200 and
confirmed `window.__osopProbe === 721`. The payload sets one harmless window
property. No cookie access, credential capture or data transmission was used.
Risk assessment: medium demonstrated reflected script execution; account
compromise was not attempted.

Remediation: avoid embedding request input in executable inline JavaScript.
Pass it through a safely serialized data channel and assign the input value
through a safe DOM API. HTML escaping alone is insufficient for this context.

## Negative checks and limits

Simple angle-bracket markers were escaped in both catalog and blog search.
This did not prevent the JavaScript-context XSS above. A product ID containing
a quote and a nonnumeric product ID both returned the same 400 response, so
those probes did not establish product-ID SQL injection. These limited tests
are not a clean bill of health for other inputs or vulnerability classes.

## MCP defect observed

An ordinary catalog search containing a single quote caused the MCP endpoint
to emit invalid JSON (`Invalid \\escape` in Python's strict JSON decoder).
The response body contains a JavaScript backslash-quote sequence, and the Java
extension's JSON construction does not escape backslashes before embedding
the body. MCP HTTP 200 and `status: success` therefore do not guarantee a valid
tool response.

The raw response was retained. A separately labelled local diagnostic repaired
invalid escapes solely to inspect the underlying response, which was HTTP 200;
it was not accepted as an authenticated AI-OSOP result. The two target findings
above also have independent, strictly parseable Burp responses. The deployed
extension still needs a proper JSON serializer and reload before this transport
defect can be considered fixed.

## AI-OSOP integration status

This proves live Burp MCP request execution and the bounded target effects
described above. It does **not** prove AI-OSOP engagement-to-report execution.
The running extension's manifest lacks bound receipts and signed observations,
lists empty parameter schemas, and advertises approval-free tools. AI-OSOP's
current Burp adapter requires independent credentials, signed scope/Flow
authority, and signed observation capabilities. Those acceptance gates were
not bypassed and these observations were not promoted into signed findings.

## Local evidence

Raw responses, HTML observations, browser verification, differential summaries
and a SHA-256 manifest are in `.runtime/burp-ginandjuice/` (ignored by Git).
The directory can contain transient public-site session/CSRF material and is
kept out of the committed report. Main evidence files:

- `differential-summary.json`
- `category-repeat-summary.json`
- `browser-validation.json`
- `catalog_quote.raw.json`
- `js_context.raw.json`
- `evidence-sha256.json`
