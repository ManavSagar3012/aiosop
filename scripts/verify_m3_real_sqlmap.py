"""M3 proof: a REAL sqlmap finding, persisted through the closed guard.

Exercises the real components end to end — real security-bridge Go server on
:8087 (which shells out to the real sqlmap binary), the production
SecurityBridgeAdapter, the production Vulnerability model, and the real
GraphMemory.add_vulnerability OSOP-P0-02 guard with allow_simulated_findings
at its production default (False). Mirrors vuln_agent.run_sqli_scan exactly.

Gate: >=1 Vulnerability with is_simulated()==False and tool_source="sqlmap"
persisted to Neo4j for the engagement.

Run (from repo root):
    .venv/Scripts/python.exe -u scripts/verify_m3_real_sqlmap.py
"""
import asyncio, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.adapters.security_bridge_mcp import SecurityBridgeAdapter
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.core.models import Vulnerability, VulnClass, Severity
from ai_osop.core.config import settings

URL = "https://ginandjuice.shop/catalog?category=Accessories"  # PortSwigger authorized demo; documented SQLi in the category filter
EID = "eng-m3-real-sqlmap"


async def main() -> int:
    print(f"allow_simulated_findings (production default) = {settings.allow_simulated_findings}")
    reg = MCPRegistry()
    await reg.register_server("security-bridge", "127.0.0.1", 8087)
    bridge = SecurityBridgeAdapter(reg)
    await bridge.initialize({"targets": ["ginandjuice.shop"]}, EID)  # scope not enforced server-side

    print(f"running REAL sqlmap against {URL} (this takes minutes)...")
    verdict = await bridge.run_sqlmap(URL, level=1, risk=1, timeout_override=1800)
    print(f"verdict: injectable={verdict.get('injectable')} param={verdict.get('parameter')!r} "
          f"dbms={verdict.get('dbms')!r} techniques={len(verdict.get('techniques') or [])}")

    if not bool(verdict.get("injectable")):
        print("RESULT: sqlmap did NOT confirm injection — no finding to persist.")
        return 1

    parameter = verdict.get("parameter", "")
    vuln = Vulnerability(
        cwe="CWE-89", vuln_type=VulnClass.SQLI, severity=Severity.CRITICAL,
        title=f"SQL Injection in parameter '{parameter or 'unknown'}'",
        description=(f"sqlmap confirmed a SQL injection at {URL} "
                     f"(parameter: {parameter or 'n/a'}; back-end DBMS: {verdict.get('dbms') or 'unknown'})."),
        evidence=[{"type": "sqlmap_injection", "provenance": "sqlmap", "url": URL,
                   "parameter": parameter, "dbms": verdict.get("dbms", ""),
                   "techniques": verdict.get("techniques", []), "payloads": verdict.get("payloads", [])}],
        tool_source="sqlmap", confidence=0.98, validated=True,
        exploitability="high", impact="high", engagement_id=EID,
    )
    print(f"is_simulated() = {vuln.is_simulated()}  (guard rejects only if this is True and flag is False)")

    gm = GraphMemory()
    await gm.connect()
    vid = await gm.add_vulnerability(vuln)
    print(f"persisted vuln id = {vid}")
    return 0 if vid else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
