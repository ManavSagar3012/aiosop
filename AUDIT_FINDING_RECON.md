# AUDIT FINDING REPORT: RECONNAISSANCE & CRAWL SUBSYSTEM

**Engagement Target:** `uat-bugbounty.nonprod.syfe.com`  
**Engagement ID:** `eng-20260714135632-syfe-live-v3`  
**Auditor ID:** `ReconAuditor`  
**Date:** 2026-07-14  

---

## 1. JavaScript Endpoint Parsing Analysis

### Verification Questions & Answers
* **Did the recon agent successfully parse Javascript files for endpoints?**
  Yes. The recon agent successfully retrieved JavaScript bundles discovered during the crawl of the target application and extracted root-relative API routes and parameters using the `js_route_pattern` and `param_pattern` regular expressions. 
  
  This was verified by querying the running API's graph endpoint (`GET http://127.0.0.1:8089/engagements/eng-20260714135632-syfe-live-v3/graph`). The database contains multiple `Endpoint` nodes with the property `"source": "js_route_extraction"`.
  
* **How many endpoints were extracted from JavaScript?**
  Exactly **57 unique endpoints** were extracted via the `js_route_extraction` module and persisted in the Neo4j database as graph nodes for this engagement.

### Extracted Route Patterns
The regex patterns used in `src/ai_osop/agents/recon_agent.py` to parse the bundles are:
* **Route Extraction:** `js_route_pattern = re.compile(r"""["'`](/(?:[A-Za-z0-9_.\-]+/?)+(?:\?[^"'`\s<>]*)?)["'`]""")`
* **Parameter Extraction:** `param_pattern = re.compile(r"[?&]([a-zA-Z0-9_\-]+)=")`

### List of Extracted JavaScript Routes (57 total)
1. `/managed-portfolio`
2. `/core`
3. `/core/equity100`
4. `/core/core-growth`
5. `/core/core-balanced`
6. `/core/core-defensive`
7. `/equity-alpha`
8. `/select-themes`
9. `/select-themes/china-growth`
10. `/select-themes/esg-and-clean-energy`
11. `/select-themes/disruptive-technology`
12. `/select-themes/healthcare-innovation`
13. `/select-custom`
14. `/income-plus`
15. `/reit-plus`
16. `/graphql`
17. `/post`
18. `/post-json`
19. `/log-in`
20. `/.wf_graphql/usys/apollo`
21. `/.wf_graphql/csrf`
22. `/pendo.js`
23. `/brokerage`
24. `/brokerage/us-stocks`
25. `/brokerage/sgx`
26. `/brokerage/hkex`
27. `/brokerage/lse`
28. `/brokerage/options`
29. `/cash-management`
30. `/cash-management/cash-plus-flexi`
31. `/cash-management/cash-plus-guaranteed`
32. `/private-wealth`
33. `/syfe-for-business`
34. `/srs`
35. `/joint-accounts`
36. `/pricing`
37. `/learn`
38. `/syfe-promotions`
39. `/magazine`
40. `/financial-calculators`
41. `/about-us`
42. `/investment-strategy`
43. `/security`
44. `/media-centre`
45. `/careers`
46. `/faq`
47. `/contact-us`
48. `/login`
49. `/dashboard`
50. `/select-product`
51. `/open-store`
52. `/syfe-home`
53. `/en-hk?rp=ls`
54. `/legal`
55. `/financial-advisors`
56. `/dashboard/account-setup/personal-info`
57. `/create-account`

---

## 2. Scope Enforcement & Log Deduplication

### Scope Configuration
The defined scope for the active engagement session is strictly limited to the `uat-bugbounty.nonprod.syfe.com` domain.

### Scope Filtering Verification
* **Did the scope enforcement filter out-of-scope targets correctly?**
  Yes. In the `full_recon` task properties payload (`task-838b3107b54c`), the crawler found a total of **68 unique endpoints**, including third-party CDNs and out-of-scope subdomains:
  * `cdn.prod.website-files.com/64d3542964db4e6ae6de7d1d%2f6544eda5f000985a163a8687%2f68be81595854339f2e9f8291%2ffinsweetcomponentsconfig-1.0.12.js`
  * `cdn.prod.website-files.com/{id}/js/syfe-v4.3a1ffda2.f3e0f71ba4ae432f.js`
  * `cdn.prod.website-files.com/{id}/js/syfe-v4.709b3800.c6df7e972dd14e52.js`
  * `cdn.prod.website-files.com/{id}/js/syfe-v4.schunk.95e63651d8cb44ca.js`
  * `cdn.prod.website-files.com/{id}/js/syfe-v4.schunk.aed0e018e03ed13e.js`
  * `cdn.prod.website-files.com/{id}/js/syfe-v4.schunk.bad753b47b970d67.js`
  * `www.syfe.com/onelink-smart-script-v2.0.0.js`
  
  These **7 out-of-scope endpoints** were correctly caught and dropped by `ReconAgent._persist_endpoint`. They were **never persisted** as `Endpoint` nodes in the Neo4j database, preventing scope bleed into downstream scanning phases.

### Log Deduplication Verification
* **Are duplicate log entries successfully suppressed?**
  Yes. The log deduplication fix utilizes an instance-level set `self._rejected_scope_urls` inside `ReconAgent`. 
  
  * **Before Fix (Bug Evidence):** In a prior run of `eng-20260714091144-syfe-live-mission-v2` (recorded in `api_test.log` at timestamp `14:43:13`), the URL `https://www.syfe.com/onelink-smart-script-v2.0.0.js` was logged **at least 20 times** in the same second due to the lack of this deduplication set.
  * **After Fix:** In the active engagement `eng-20260714135632-syfe-live-v3`, there are **zero duplicate logs** in `api_dev.log` for out-of-scope rejections, confirming the log-dedup fix successfully suppressed the log noise.

---

## 3. Crawl Quality Assessment

### Crawl Completeness
The crawl quality is **High** and highly complete. It mapped a comprehensive surface of `uat-bugbounty.nonprod.syfe.com` that spans all functional areas of the app:

* **Authentication & User Management:** `/login`, `/log-in`, `/create-account`, `/dashboard/account-setup/personal-info`
* **Portfolios & Investment Products:** `/managed-portfolio`, `/core/equity100`, `/reit-plus`, `/brokerage`, `/cash-management`, `/private-wealth`, `/joint-accounts`, `/srs`
* **Data APIs & Backend Integrations:** `/graphql`, `/.wf_graphql/csrf`, `/.wf_graphql/usys/apollo`, `/post`, `/post-json`

### Crawl Hygiene & Source Breakdown
* **Total Persisted Endpoints in Neo4j Graph:** 64
* **Source Breakdown:**
  * `js_route_extraction`: 57 endpoints (89.1%)
  * `httpx` (service probing): 4 endpoints (6.3%)
  * `active_crawl` (direct page spidering): 2 endpoints (3.1%)
  * `scan_base` (target base baseline): 1 endpoint (1.5%)
* **Hygiene:** Excellent. Malformed routes (such as `/core/ https:/cdn.jsdelivr.net/...`) which previously corrupted the database were correctly rejected by the `normalize_endpoint_url` logic.
* **Downstream Readiness:** High. Parameter mapping successfully extracted query keys (such as `id`, `postId`, `loginId`, `rp`) from the JS bundles and stored them inside the graph model properties, providing high-fidelity payloads for downstream scans.

---

### Reference Telemetry & Database Records
* **Uvicorn API Port:** `127.0.0.1:8089` (active process 6996)
* **Neo4j DB Port:** `127.0.0.1:7687` (GraphMemory)
* **Audit Trail Path:** `/engagements/eng-20260714135632-syfe-live-v3/audit-log`
* **Neo4j Graph Path:** `/engagements/eng-20260714135632-syfe-live-v3/graph`
* **Reference Log Files:** `api_dev.log`, `api_test.log`

---
