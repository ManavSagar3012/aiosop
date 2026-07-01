"""
Threat Intel MCP Adapter
Fetches and caches data from NVD, CISA KEV, ExploitDB, MITRE, and Shodan.
"""

import asyncio
import csv
import io
import logging
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx

from ai_osop.core.config import settings

logger = logging.getLogger(__name__)
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"


class ThreatIntelAdapter:
    """
    Threat Intelligence enrichment layer.
    """

    def __init__(self, shodan_api_key: Optional[str] = None):
        self.shodan_api_key = shodan_api_key or settings.shodan_api_key
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = timedelta(hours=24)
        self.client = httpx.AsyncClient(timeout=10.0)
        # NVD API is strictly rate limited
        self.nvd_lock = asyncio.Semaphore(1)

    def _get_cache(self, key: str) -> Optional[Any]:
        if key in self.cache:
            entry = self.cache[key]
            if datetime.utcnow() - entry["time"] < self.cache_ttl:
                return entry["data"]
        return None

    def _set_cache(self, key: str, data: Any) -> None:
        self.cache[key] = {"time": datetime.utcnow(), "data": data}

    async def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """Fetch CVE details from NVD API."""
        cve_id = self._normalize_cve_id(cve_id)
        if not cve_id:
            return {}

        cache_key = f"cve_{cve_id}"
        cached = self._get_cache(cache_key)
        if cached:
            return cached

        async with self.nvd_lock:
            try:
                resp = await self.client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": cve_id},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("vulnerabilities"):
                        result = self._normalize_cve(data["vulnerabilities"][0]["cve"])
                        self._set_cache(cache_key, result)
                        return result
                logger.warning("NVD lookup for %s returned HTTP %s", cve_id, resp.status_code)
            except Exception as e:
                logger.warning("NVD fetch failed for %s: %s", cve_id, e)
            await asyncio.sleep(1)  # Rate limit backoff for NVD
        return {}

    def _normalize_cve_id(self, cve_id: Any) -> str:
        normalized = str(cve_id or "").strip().upper()
        if not _CVE_PATTERN.match(normalized):
            logger.warning("Ignoring invalid CVE id: %r", cve_id)
            return ""
        return normalized

    def _normalize_cve(self, cve_data: Dict) -> Dict:
        """Normalize NVD JSON format."""
        try:
            desc = cve_data.get("descriptions", [{}])[0].get("value", "")
            metrics = cve_data.get("metrics", {})
            cvss = self._extract_cvss(metrics)
            return {
                "id": cve_data.get("id"),
                "description": desc,
                "cvss": cvss,
                "published": cve_data.get("published"),
                "last_modified": cve_data.get("lastModified"),
            }
        except Exception:
            return {}

    def _extract_cvss(self, metrics: Dict[str, Any]) -> float:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric = metrics.get(key, [])
            if metric:
                return float(metric[0].get("cvssData", {}).get("baseScore", 0.0))
        return 0.0

    async def check_cisa_kev(self, cve_id: str) -> bool:
        """Check if CVE is in CISA KEV catalog."""
        cve_id = self._normalize_cve_id(cve_id)
        if not cve_id:
            return False

        cache_key = "cisa_kev"
        kev_data = self._get_cache(cache_key)
        if not kev_data:
            try:
                resp = await self.client.get(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                )
                if resp.status_code == 200:
                    kev_data = {
                        item["cveID"]: True for item in resp.json().get("vulnerabilities", [])
                    }
                    self._set_cache(cache_key, kev_data)
                else:
                    logger.warning("CISA KEV lookup returned HTTP %s", resp.status_code)
            except Exception as e:
                logger.warning("CISA KEV fetch failed: %s", e)
                kev_data = {}

        return cve_id in (kev_data or {})

    async def search_exploitdb(self, cve_id: str) -> List[Dict]:
        """Find public ExploitDB exploits mapped to a CVE.

        Fetches the ExploitDB ``files_exploits.csv`` index and returns every entry
        whose ``codes`` column references *cve_id*. Previously this method wrongly
        duplicated the NVD lookup (created its own httpx client, ignored the
        injected ``self.client``, and parsed NVD JSON), so it never returned
        exploits — a real CVE->exploit correlation gap.
        """
        cve_id = self._normalize_cve_id(cve_id)
        cache_key = f"exploitdb_{cve_id}"
        cached = self._get_cache(cache_key)
        if cached is not None:
            return cached
        try:
            resp = await self.client.get(_EXPLOITDB_CSV_URL, timeout=15.0)
            if resp.status_code != 200:
                return []
            exploits: List[Dict] = []
            reader = csv.DictReader(io.StringIO(resp.text))
            for row in reader:
                codes = {c.strip().upper() for c in re.split(r"[;,\s]+", row.get("codes", "") or "")}
                if cve_id.upper() not in codes:
                    continue
                eid = (row.get("id") or "").strip()
                exploits.append({
                    "id": eid,
                    "title": (row.get("description") or "").strip(),
                    "type": (row.get("type") or "").strip(),
                    "platform": (row.get("platform") or "").strip(),
                    "url": f"https://www.exploit-db.com/exploits/{eid}",
                    "verified": bool((row.get("date_verified") or "").strip()),
                    "source": "exploitdb",
                })
            self._set_cache(cache_key, exploits)
            return exploits
        except Exception as e:
            logger.error("ExploitDB search failed for %s: %s", cve_id, e)
        return []

    async def map_mitre_attack(self, cve_id: str, description: str) -> List[str]:
        """Map vulnerability to MITRE ATT&CK techniques based on description heuristics."""
        tactics = []
        desc_lower = description.lower()

        # Enhanced heuristic mapping
        if (
            "execution" in desc_lower
            or "rce" in desc_lower
            or "command injection" in desc_lower
            or "arbitrary code" in desc_lower
        ):
            tactics.append("TA0002")  # Execution
            tactics.append("T1059")  # Command and Scripting Interpreter

        if "privilege" in desc_lower or "escalation" in desc_lower or "root" in desc_lower:
            tactics.append("TA0004")  # Privilege Escalation
            tactics.append("T1068")  # Exploitation for Privilege Escalation

        if (
            "bypass" in desc_lower
            or "authentication" in desc_lower
            or "unauthenticated" in desc_lower
        ):
            tactics.append("TA0001")  # Initial Access
            tactics.append("T1190")  # Exploit Public-Facing Application

        if "credential" in desc_lower or "password" in desc_lower or "hash" in desc_lower:
            tactics.append("TA0006")  # Credential Access
            tactics.append("T1003")  # OS Credential Dumping

        if "sql injection" in desc_lower or "sqli" in desc_lower:
            tactics.append("TA0001")  # Initial Access
            tactics.append("T1190")  # Exploit Public-Facing Application
            tactics.append("TA0009")  # Collection (Data from Local System)

        if "cross-site scripting" in desc_lower or "xss" in desc_lower:
            tactics.append("TA0001")  # Initial Access (via watering hole or phish)
            tactics.append("T1189")  # Drive-by Compromise

        if "ssrf" in desc_lower or "server-side request forgery" in desc_lower:
            tactics.append("TA0008")  # Lateral Movement
            tactics.append("TA0007")  # Discovery (Network Service Discovery)

        # Deduplicate and return
        return list(set(tactics))

    async def enrich_asset(self, ip_or_domain: str) -> Dict[str, Any]:
        """Shodan enrichment for exposure data."""
        if not self.shodan_api_key:
            return {}

        cache_key = f"shodan_{ip_or_domain}"
        cached = self._get_cache(cache_key)
        if cached:
            return cached

        try:
            resp = await self.client.get(
                f"https://api.shodan.io/shodan/host/{ip_or_domain}",
                params={"key": self.shodan_api_key},
            )
            if resp.status_code == 200:
                data = resp.json()
                self._set_cache(cache_key, data)
                return data
        except Exception as e:
            logger.warning("Shodan enrichment failed for %s: %s", ip_or_domain, e)
        return {}

    async def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize and enrich a raw finding into a standardized threat intel object."""
        finding = dict(finding)
        cve_id = self._normalize_cve_id(finding.get("cve_id"))

        if cve_id:
            finding["cve_id"] = cve_id
            nvd_data = await self.get_cve_details(cve_id)
            finding["nvd_data"] = nvd_data
            finding["in_kev"] = await self.check_cisa_kev(cve_id)
            finding["exploits"] = await self.search_exploitdb(cve_id)
            finding["mitre_tactics"] = await self.map_mitre_attack(
                cve_id, nvd_data.get("description", "")
            )

        return finding

    async def close(self) -> None:
        await self.client.aclose()

    async def __aenter__(self) -> "ThreatIntelAdapter":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
