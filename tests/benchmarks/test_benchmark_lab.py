import asyncio
import os
import signal
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse

import pytest
import uvicorn
from fastapi.testclient import TestClient
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.config import AgentType
from ai_osop.core.validation_engine import ValidationEngine, PB_SQLI_DIFFERENTIAL, PB_AUTHZ_DIFFERENTIAL
from ai_osop.core.confidence_engine import VALIDATED, REJECTED, INCONCLUSIVE

from ai_osop.core.impact_engine import ImpactQuantificationEngine
from ai_osop.core.models import AttackChain
class MockHypothesis:
    def __init__(self, id, target, playbook, category="sqli"):
        self.id = id
        self.target = target
        self.playbook = playbook
        self.category = category
        self._scope = None

def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port

# Ground truth expected findings
TRUTH_SQLI_URL = "/api/v1/users"
TRUTH_XSS_URL = "/profile"
TRUTH_FP_URL = "/api/v1/search"
TRUTH_AUTH_URL = "/api/v1/auth/login"
TRUTH_IDOR_URL = "/api/v1/docs"

@pytest.fixture(scope="module")
def mock_server_port():
    port = get_free_port()
    env = os.environ.copy()
    
    # Start the target app
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "tests.benchmarks.mock_target:app", "--host", "127.0.0.1", "--port", str(port)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for startup
    time.sleep(2)
    yield port
    
    # Teardown
    proc.terminate()
    proc.wait(timeout=5)
@pytest.mark.asyncio
@pytest.mark.skip(reason='IMPACT-ENGINE-001: references unbuilt AttackChain(primitive_ids=...) API. Unblock when Impact Engine lands.')
async def test_benchmark_lab_validation_engine(mock_server_port):
    """
    Run the ValidationEngine against the benchmark target to score accuracy.
    """
    eng_id = f"bench-eng-{int(time.time())}"
    target_url = f"http://127.0.0.1:{mock_server_port}"
    print(f"\n[Bench] Target started at {target_url}")

    class MockConn:
        async def execute_tool(self, tool_name, parameters, timeout_override=None, **kwargs):
            if tool_name == "sqlmap":
                import httpx
                # A very crude differential check mimicking what the bridge would do
                # Send a benign payload and a true payload
                url = parameters.get("url", "")
                # Our mock target returns JSON {"data": [...]}. For FP, it returns {"results": [...]}
                try:
                    async with httpx.AsyncClient() as client:
                        res = await client.get(url)
                        # Very basic heuristic mimicking an active security bridge:
                        if res.status_code == 500:
                            return type('obj', (object,), {'result': {'message': 'injectable'}, 'status': 'success'})
                        if "results" in res.text:
                            # The search endpoint returns results, so it looks like it worked but it's parameterized
                            # A real SQLmap would realize payload didn't change logic context
                            return type('obj', (object,), {'result': {'message': 'not injectable'}, 'status': 'success'})
                        if "data" in res.text:
                            # The true SQLi returns data when injected successfully
                            return type('obj', (object,), {'result': {'message': 'injectable'}, 'status': 'success'})
                except Exception:
                    pass
                return type('obj', (object,), {'result': {'message': 'not injectable'}, 'status': 'success'})

    class MockMCPRegistry:
        def __init__(self):
            self._servers = {"security-bridge": MockConn()}
            
        async def execute_tool(self, server_id, tool_name, parameters, **kwargs):
            return await self._servers[server_id].execute_tool(tool_name, parameters)

    ve = ValidationEngine(mcp_registry=MockMCPRegistry())
    
    # 1. True Positive: SQLi
    # Inject a quote to simulate a payload
    hyp_sqli = MockHypothesis("h-sqli", f"{target_url}{TRUTH_SQLI_URL}?username=admin'", PB_SQLI_DIFFERENTIAL)
    out_sqli = await ve.validate(hyp_sqli)
    
    # 2. False Positive Trap: Search Endpoint
    # Inject a quote, but the endpoint handles it safely
    hyp_fp = MockHypothesis("h-fp", f"{target_url}{TRUTH_FP_URL}?q=item'", PB_SQLI_DIFFERENTIAL)
    out_fp = await ve.validate(hyp_fp)
    
    # 3. Authz/IDOR Attack Chain Validation
    hyp_idor = MockHypothesis("h-idor", f"{target_url}{TRUTH_IDOR_URL}/2", PB_AUTHZ_DIFFERENTIAL)
    # Supply dual contexts for the engine
    hyp_idor.auth_a = {"headers": {"Authorization": "Bearer token_for_admin"}}
    hyp_idor.auth_b = {"headers": {"Authorization": "Bearer token_for_guest"}}
    out_idor = await ve.validate(hyp_idor)
    
    print("\n--- BENCHMARK RESULTS ---")
    print(f"Discovery Recall (SQLi): {'PASS' if out_sqli.validation_state == VALIDATED else 'FAIL'} (Got {out_sqli.validation_state})")
    print(f"FP Trap Rejected       : {'PASS' if out_fp.validation_state == REJECTED else 'FAIL'} (Got {out_fp.validation_state})")
    print(f"Authz/IDOR Validated   : {'PASS' if out_idor.validation_state == VALIDATED else 'FAIL'} (Got {out_idor.validation_state})")
    
    assert out_sqli.validation_state == VALIDATED, "Engine failed to validate true SQLi"
    assert out_fp.validation_state == REJECTED, "Engine failed to reject false positive SQLi trap"
    assert out_idor.validation_state == VALIDATED, "Engine failed to validate IDOR/Authz escalation"
    assert out_idor.validation_state == VALIDATED, "Engine failed to validate IDOR/Authz escalation"
    
    # 4. Impact Quantification Engine
    print("\n[Bench] Testing Impact Quantification Engine...")
    chain = AttackChain(
        engagement_id=eng_id,
        primitive_ids=["prim-sqli", "prim-idor"],
        title="SQLi to IDOR Chain",
        description="Found SQLi then exploited IDOR to steal admin tokens."
    )
    
    # Mock graph memory to return fake nodes for the chain
    async def mock_run_read_query(cypher, params):
        return [
            {"p": {"title": "Reflected XSS", "description": "Steals session tokens", "type": "Vulnerability"}},
            {"p": {"title": "Session Hijack", "description": "Uses stolen token to access admin panel", "type": "Vulnerability"}},
            {"p": {"title": "API Token Theft", "description": "Extracts production AWS keys from admin dashboard", "type": "Vulnerability"}}
        ]
    gm.run_read_query = mock_run_read_query
    
    impact_engine = ImpactQuantificationEngine(gm)
    impact_result = await impact_engine.quantify_chain_impact(chain.id)
    
    print(f"Impact CVSS     : {impact_result.get('cvss_vector')}")
    print(f"Impact Score    : {impact_result.get('cvss_score')}")
    print(f"Impact Severity : {impact_result.get('severity')}")
    print(f"Impact Narrative: {impact_result.get('narrative')}")
    
    assert "CVSS:" in impact_result.get("cvss_vector", ""), "Missing CVSS vector"
    assert impact_result.get("cvss_score", 0.0) > 0.0, "Missing CVSS score"
    assert len(impact_result.get("narrative", "")) > 10, "Missing business narrative"
