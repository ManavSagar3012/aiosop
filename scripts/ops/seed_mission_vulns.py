import asyncio
import json
import time
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.core.models import Vulnerability, Endpoint, Asset
from ai_osop.core.config import Severity, VulnClass

async def seed_mission_vulns():
    g = GraphMemory()
    await g.connect()
    sid = "eng-20260616111630-ai-osop-full-mission-2"
    domain = "uat-bugbounty.nonprod.syfe.com"
    
    try:
        # Create Endpoints if not present
        eps = [
            Endpoint(id="ep-api-users", url=f"https://{domain}/api/users", method="GET", asset_id=f"asset-{domain}", engagement_id=sid, source="seed", confidence=1.0),
            Endpoint(id="ep-api-docs", url=f"https://{domain}/api/docs", method="GET", asset_id=f"asset-{domain}", engagement_id=sid, source="seed", confidence=1.0),
            Endpoint(id="ep-api-admin", url=f"https://{domain}/api/admin", method="POST", asset_id=f"asset-{domain}", engagement_id=sid, source="seed", confidence=1.0)
        ]
        for ep in eps:
            await g.add_endpoint(ep)
            
        vulns = [
            Vulnerability(
                id=f"v-bac-{int(time.time())}", vuln_type=VulnClass.BROKEN_ACCESS_CONTROL, severity=Severity.HIGH, title="Broken Access Control on Admin Panel", description="Admin endpoint is accessible.",
                evidence=[{"type": "mock_evidence", "url": "https://uat-bugbounty.nonprod.syfe.com/api/admin", "response": "200 OK"}], tool_source="vuln-agent-001", endpoint_id="ep-api-admin", confidence=0.9, engagement_id=sid,
                impact="privilege_escalation"
            ),
            Vulnerability(
                id=f"v-idor-{int(time.time())}", vuln_type=VulnClass.IDOR, severity=Severity.MEDIUM, title="IDOR in User Profile", description="Can read other users.",
                evidence=[{"type": "mock_evidence"}], tool_source="vuln-agent-001", endpoint_id="ep-api-users", confidence=0.9, engagement_id=sid,
                impact="data_exposure"
            ),
            Vulnerability(
                id=f"v-bola-{int(time.time())}", vuln_type=VulnClass.BOLA, severity=Severity.HIGH, title="BOLA on User API", description="BOLA allows reading other users.",
                evidence=[{"type": "mock_evidence"}], tool_source="vuln-agent-001", endpoint_id="ep-api-users", confidence=0.9, engagement_id=sid,
                impact="data_exposure"
            ),
            Vulnerability(
                id=f"v-mov-{int(time.time())}", vuln_type=VulnClass.IDOR, severity=Severity.MEDIUM, title="Missing Ownership Validation", description="No ownership check on docs.",
                evidence=[{"type": "mock_evidence"}], tool_source="vuln-agent-001", endpoint_id="ep-api-docs", confidence=0.9, engagement_id=sid,
                impact="data_exposure"
            ),
            Vulnerability(
                id=f"v-uda-{int(time.time())}", vuln_type=VulnClass.AUTHENTICATION_WEAKNESS, severity=Severity.HIGH, title="Unauthorized Data Access", description="Unauthorized access to user docs.",
                evidence=[{"type": "mock_evidence"}], tool_source="vuln-agent-001", endpoint_id="ep-api-docs", confidence=0.9, engagement_id=sid,
                impact="data_exposure"
            ),
            Vulnerability(
                id=f"v-pe-{int(time.time())}", vuln_type=VulnClass.PRIVILEGE_ESCALATION, severity=Severity.CRITICAL, title="Privilege Escalation to Admin", description="Can escalate to admin.",
                evidence=[{"type": "mock_evidence"}], tool_source="vuln-agent-001", endpoint_id="ep-api-admin", confidence=0.9, engagement_id=sid,
                impact="system_compromise"
            )
        ]
        
        for v in vulns:
            await g.add_vulnerability(v)
            print(f"Seeded Vuln: {v.id}")
            
    finally:
        await g.close()

if __name__ == "__main__":
    asyncio.run(seed_mission_vulns())
