import asyncio
import json
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.core.models import Vulnerability, Endpoint, Asset
from ai_osop.core.config import Severity, VulnClass

async def seed_exhaustive():
    g = GraphMemory()
    await g.connect()
    sid = "eng-20260606052129-auto-mission-1780723287"
    domain = "ginandjuice.shop"
    
    try:
        # 1. Create Base Asset
        asset = Asset(id=f"asset-{domain}", type="domain", value=domain, engagement_id=sid, source="manual", confidence=1.0)
        await g.add_asset(asset)
        
        # 2. Create Endpoints
        eps = [
            Endpoint(id="ep-login", url=f"https://{domain}/login", method="POST", asset_id=asset.id, engagement_id=sid, source="seed", confidence=1.0),
            Endpoint(id="ep-profile", url=f"https://{domain}/profile", method="GET", asset_id=asset.id, engagement_id=sid, source="seed", confidence=1.0),
            Endpoint(id="ep-webhook", url=f"https://{domain}/api/webhook", method="POST", asset_id=asset.id, engagement_id=sid, source="seed", confidence=1.0)
        ]
        for ep in eps:
            await g.add_endpoint(ep)
            
        # 3. Create Vulnerabilities
        vulns = [
            Vulnerability(
                id="v1", vuln_type=VulnClass.SQLI, severity=Severity.CRITICAL, title="SQLi", description="Test",
                evidence=[{"type": "mock"}], tool_source="vuln-agent-001", endpoint_id="ep-login", confidence=0.9, engagement_id=sid,
                impact="data_exfiltration"
            ),
            Vulnerability(
                id="v2", vuln_type=VulnClass.XSS, severity=Severity.HIGH, title="XSS", description="Test",
                evidence=[{"type": "mock"}], tool_source="vuln-agent-001", endpoint_id="ep-profile", confidence=0.9, engagement_id=sid,
                impact="session_hijacking"
            )
        ]
        
        for v in vulns:
            await g.add_vulnerability(v)
            print(f"Seeded: {v.id}")
            
    finally:
        await g.close()

if __name__ == "__main__":
    asyncio.run(seed_exhaustive())
