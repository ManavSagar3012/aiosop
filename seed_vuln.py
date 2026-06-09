import asyncio
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.core.models import Vulnerability
from ai_osop.core.config import Severity, VulnClass

async def seed_vuln():
    g = GraphMemory()
    await g.connect()
    sid = "eng-20260606050945-auto-mission-1780722583"
    
    # Create a high-fidelity mock vulnerability
    v = Vulnerability(
        id="vuln-sqli-001",
        vuln_type=VulnClass.SQLI,
        severity=Severity.HIGH,
        title="Reflected SQL Injection in Search",
        description="A potential SQL injection was identified in the 'product' search parameter.",
        evidence=[{"type": "mock_probe", "payload": "' OR 1=1 --"}],
        tool_source="vuln-agent-mock",
        endpoint_id="ep-d924f80f423c",
        confidence=0.9,
        engagement_id=sid
    )
    
    try:
        await g.add_vulnerability(v)
        print(f"Mock Vulnerability Seeded: {v.id}")
    finally:
        await g.close()

if __name__ == "__main__":
    asyncio.run(seed_vuln())
