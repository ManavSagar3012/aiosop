from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.adapters.threat_intel_mcp import ThreatIntelAdapter


@pytest.fixture
def mock_httpx_client():
    with patch("httpx.AsyncClient") as mock_client:
        client_instance = AsyncMock()
        mock_client.return_value = client_instance
        yield client_instance


@pytest.mark.asyncio
async def test_cve_lookup_and_cache(mock_httpx_client):
    adapter = ThreatIntelAdapter()
    adapter.client = mock_httpx_client

    # Mock NVD response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [{"value": "Log4j RCE vulnerability"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]},
                }
            }
        ]
    }

    # httpx.AsyncClient.get returns an awaitable that resolves to a Response
    async def mock_get(*args, **kwargs):
        return mock_response

    mock_httpx_client.get.side_effect = mock_get

    result = await adapter.get_cve_details("CVE-2021-44228")

    assert result["id"] == "CVE-2021-44228"
    assert result["cvss"] == 10.0

    # Second call should hit cache, not the client
    result2 = await adapter.get_cve_details("CVE-2021-44228")
    assert result2["cvss"] == 10.0
    mock_httpx_client.get.assert_called_once()


@pytest.mark.asyncio
async def test_enrich_finding(mock_httpx_client):
    adapter = ThreatIntelAdapter()
    adapter.client = mock_httpx_client

    # Setup mocks
    adapter.get_cve_details = AsyncMock(return_value={"description": "Execution flaw", "cvss": 9.8})
    adapter.check_cisa_kev = AsyncMock(return_value=True)
    adapter.search_exploitdb = AsyncMock(return_value=[{"id": "123"}])

    finding = {"cve_id": "CVE-2024-1234"}

    enriched = await adapter.enrich_finding(finding)

    assert enriched["nvd_data"]["cvss"] == 9.8
    assert enriched["in_kev"] is True
    assert len(enriched["exploits"]) == 1
    assert "TA0002" in enriched["mitre_tactics"]  # Mapped from 'Execution'


@pytest.mark.asyncio
async def test_invalid_cve_is_not_fetched(mock_httpx_client):
    adapter = ThreatIntelAdapter()
    adapter.client = mock_httpx_client

    result = await adapter.get_cve_details("not-a-cve")

    assert result == {}
    mock_httpx_client.get.assert_not_called()


@pytest.mark.asyncio
async def test_exploitdb_csv_search_returns_matching_cves(mock_httpx_client):
    adapter = ThreatIntelAdapter()
    adapter.client = mock_httpx_client

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = (
        "id,file,description,date,author,type,platform,port,date_verified,codes,tags,"
        "aliases,screenshot_url,application_url,source_url\n"
        "50592,exploits/linux/remote/50592.py,Apache Log4j RCE,2021-12-13,Researcher,"
        "remote,java,0,,CVE-2021-44228,,,,,\n"
    )

    async def mock_get(*args, **kwargs):
        return mock_response

    mock_httpx_client.get.side_effect = mock_get

    exploits = await adapter.search_exploitdb("CVE-2021-44228")

    assert exploits == [
        {
            "id": "50592",
            "title": "Apache Log4j RCE",
            "type": "remote",
            "platform": "java",
            "url": "https://www.exploit-db.com/exploits/50592",
            "verified": False,
            "source": "exploitdb",
        }
    ]
