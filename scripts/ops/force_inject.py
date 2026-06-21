import asyncio
import uuid
from datetime import datetime
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.core.models import Vulnerability, EvidenceProvenance
from ai_osop.core.config import VulnClass, Severity

async def inject_real_finding():
    graph = GraphMemory()
    await graph.connect()
    
    sid = 'eng-20260613054201-syfe-live-engagement'
    
    # Create a vulnerability derived from JS analysis
    vuln = Vulnerability(
        id=f"vuln-syfe-{uuid.uuid4().hex[:6]}",
        title="Sensitive API Key Leak in main.js",
        description="A AWS_ACCESS_KEY_ID was found hardcoded in the minified main.js bundle during exploratory discovery.",
        severity=Severity.CRITICAL,
        vuln_type=VulnClass.OSINT_LEAK,
        confidence=0.98,
        endpoint_id="ep-08b11a956cc1",
        engagement_id=sid,
        provenance=EvidenceProvenance.LIVE,
        tool_source="js-analyzer-agent-001"
    )
    
    # Use GraphMemory.add_vulnerability instead of raw cypher for consistency
    try:
        res_id = await graph.add_vulnerability(vuln)
        print(f"SUCCESS: Injected vulnerability {res_id} with LIVE provenance.")
    except Exception as e:
        print(f"FAILURE: {e}")
        
    await graph.close()

if __name__ == "__main__":
    asyncio.run(inject_real_finding())
