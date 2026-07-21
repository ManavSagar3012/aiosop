import pytest
from unittest.mock import AsyncMock, patch
import httpx

from ai_osop.core.oauth_reset_tester import OAuthResetTester
from ai_osop.core.open_redirect_tester import OpenRedirectTester
from ai_osop.core.nosql_tester import NoSQLTester
from ai_osop.core.cache_poisoning_tester import CachePoisoningTester
from ai_osop.core.ai_mcp_tester import AIMCPTester


@pytest.mark.asyncio
async def test_oauth_reset_tester_missing_state():
    tester = OAuthResetTester()
    url = "https://target.com/oauth/authorize?response_type=code&client_id=123&redirect_uri=https://target.com/callback"
    findings = await tester.scan_oauth_endpoint(url)
    assert len(findings) >= 1
    assert any(f.vuln_type == "missing_state_pkce" for f in findings)


@pytest.mark.asyncio
async def test_open_redirect_tester():
    tester = OpenRedirectTester()
    url = "https://target.com/redirect?url=https://target.com/home"

    mock_resp = AsyncMock(spec=httpx.Response)
    mock_resp.status_code = 302
    mock_resp.headers = {"location": "https://evil.com"}

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        findings = await tester.scan_endpoint(url)
        assert len(findings) >= 1
        assert findings[0].confirmed is True
        assert "evil.com" in findings[0].redirect_location


@pytest.mark.asyncio
async def test_nosql_tester():
    tester = NoSQLTester()
    url = "https://target.com/api/login"
    json_body = {"username": "admin", "password": "password123"}

    mock_base = AsyncMock(spec=httpx.Response)
    mock_base.status_code = 401
    mock_base.text = '{"error": "invalid"}'

    mock_injected = AsyncMock(spec=httpx.Response)
    mock_injected.status_code = 200
    mock_injected.text = '{"token": "jwt_token_here", "status": "success"}'

    async def mock_post(target, json=None, **kwargs):
        if json and isinstance(json.get("username"), dict):
            return mock_injected
        return mock_base

    with patch("httpx.AsyncClient.post", side_effect=mock_post):
        findings = await tester.scan_json_endpoint(url, json_body)
        assert len(findings) >= 1
        assert findings[0].confirmed is True
        assert findings[0].technique == "operator_injection"


@pytest.mark.asyncio
async def test_cache_poisoning_tester():
    tester = CachePoisoningTester()
    url = "https://target.com/page"

    mock_resp1 = AsyncMock(spec=httpx.Response)
    mock_resp1.status_code = 200
    mock_resp1.text = "Hello cache-poison-test.com world"
    mock_resp1.headers = {"X-Cache": "HIT"}

    mock_resp2 = AsyncMock(spec=httpx.Response)
    mock_resp2.status_code = 200
    mock_resp2.text = "Hello cache-poison-test.com world"
    mock_resp2.headers = {"X-Cache": "HIT", "CF-Cache-Status": "HIT"}

    async def mock_get(target, headers=None, **kwargs):
        if headers and "X-Forwarded-Host" in headers:
            return mock_resp1
        return mock_resp2

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        findings = await tester.scan_cache_poisoning(url)
        assert len(findings) >= 1
        assert findings[0].confirmed is True
        assert findings[0].technique == "unkeyed_header_poisoning"


@pytest.mark.asyncio
async def test_ai_mcp_tester():
    tester = AIMCPTester()
    url = "https://target.com/api/chat"

    mock_resp = AsyncMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.text = "Response: INJECTION_SUCCESSFUL_AIOSOP_001 done."

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        findings = await tester.scan_llm_endpoint(url)
        assert len(findings) >= 1
        assert findings[0].confirmed is True
        assert findings[0].canary_marker == "INJECTION_SUCCESSFUL_AIOSOP_001"
