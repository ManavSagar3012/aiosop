"""Tests for the sqlmap confirmation layer and its escalation into the
generalized SQLi path.

These do NOT shell out to real sqlmap (that's covered by live verification
scripts); they lock in the parser contract and the escalation wiring so a future
change can't silently (a) misparse a verdict or (b) mint a fake sqlmap finding.
"""
import pytest

from ai_osop.core import sqlmap_confirm as sc


# --------------------------------------------------------------------------- #
# parser contract                                                             #
# --------------------------------------------------------------------------- #
_POSITIVE_LOG = """
sqlmap identified the following injection point(s):
---
Parameter: category (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: category=Gifts' AND 1=1-- -
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: category=Gifts' AND SLEEP(5)-- -
---
back-end DBMS: MySQL >= 5.0.12
"""


def test_extract_positive_verdict():
    v = sc._extract(_POSITIVE_LOG)
    assert v["injectable"] is True
    assert v["parameter"] == "category (GET)"
    assert v["dbms"].startswith("MySQL")
    assert "boolean-based blind" in v["techniques"]
    assert "time-based blind" in v["techniques"]


def test_parse_stdout_negative():
    v = sc._parse_stdout("all tested parameters do not appear to be injectable")
    assert v["injectable"] is False
    assert v["parameter"] == ""
    assert v["techniques"] == []


def test_parse_stdout_requires_corroborating_signal():
    # A stray "Parameter:" with no injection markers must NOT read as injectable.
    v = sc._parse_stdout("Parameter: q\nnothing else here")
    assert v["injectable"] is False


@pytest.mark.asyncio
async def test_confirm_returns_false_when_binary_missing(monkeypatch):
    monkeypatch.setattr(sc, "sqlmap_available", lambda: False)
    v = await sc.sqlmap_confirm("http://x.test/?q=1", param="q")
    assert v["injectable"] is False
    assert "not found" in v.get("error", "")


# --------------------------------------------------------------------------- #
# escalation wiring in run_generalized_sqli                                   #
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_escalation_mints_real_sqlmap_finding(monkeypatch):
    """When the oracle flags a point and sqlmap confirms, the persisted finding
    must be tool_source=sqlmap and is_simulated()==False (a real observation)."""
    import ai_osop.core.deterministic_scan as ds

    ep = {
        "url": "http://t.test/rest/products/search?q=x",
        "method": "GET", "query_keys": ["q"], "parameters": [],
        "has_body": False, "path": "/rest/products/search", "body_schema_keys": [],
    }

    async def fake_eps(_gm, _eid):
        return [ep]

    async def fake_error_based(_c, _url, param=None):
        return {"technique": "error_based", "endpoint": ep["url"], "parameter": "q",
                "payload": "q='", "confidence": 1.0}

    async def fake_time_blind(*a, **k):
        return None

    async def fake_login_bypass(*a, **k):
        return None

    async def fake_confirm(url, **kw):
        return {"injectable": True, "parameter": "q (GET)", "dbms": "PostgreSQL",
                "techniques": ["error-based"], "payloads": ["PG error-based"], "raw_tail": ""}

    captured = {}

    class _GM:
        async def add_vulnerability(self, v):
            captured["v"] = v
            return "vid-1"

    monkeypatch.setattr(ds, "_discovered_endpoints", fake_eps)
    monkeypatch.setattr("ai_osop.core.sqli_oracle.detect_error_based", fake_error_based)
    monkeypatch.setattr("ai_osop.core.sqli_oracle.detect_time_blind", fake_time_blind)
    monkeypatch.setattr("ai_osop.core.sqli_oracle.detect_login_bypass", fake_login_bypass)
    monkeypatch.setattr("ai_osop.core.sqlmap_confirm.sqlmap_available", lambda: True)
    monkeypatch.setattr("ai_osop.core.sqlmap_confirm.sqlmap_confirm", fake_confirm)

    persisted, _examined = await ds.run_generalized_sqli(
        "eng-x", _GM(), per_check_timeout=2.0, confirm_with_sqlmap=True,
    )
    assert len(persisted) == 1
    v = captured["v"]
    assert v.tool_source == "sqlmap"
    assert v.is_simulated() is False
    assert v.severity.value == "critical"
    assert any(e.get("provenance") == "sqlmap" for e in v.evidence)


@pytest.mark.asyncio
async def test_no_escalation_falls_back_to_oracle_finding(monkeypatch):
    """When sqlmap does NOT confirm, the finding stays the oracle finding
    (tool_source=deterministic_scan_generalized) — never fabricated as sqlmap."""
    import ai_osop.core.deterministic_scan as ds

    ep = {
        "url": "http://t.test/rest/products/search?q=x",
        "method": "GET", "query_keys": ["q"], "parameters": [],
        "has_body": False, "path": "/rest/products/search", "body_schema_keys": [],
    }

    async def fake_eps(_gm, _eid):
        return [ep]

    async def fake_error_based(_c, _url, param=None):
        return {"technique": "error_based", "endpoint": ep["url"], "parameter": "q",
                "payload": "q='", "confidence": 1.0}

    async def fake_none(*a, **k):
        return None

    async def fake_confirm(url, **kw):
        return {"injectable": False, "parameter": "", "dbms": "", "techniques": [], "payloads": []}

    captured = {}

    class _GM:
        async def add_vulnerability(self, v):
            captured["v"] = v
            return "vid-2"

    monkeypatch.setattr(ds, "_discovered_endpoints", fake_eps)
    monkeypatch.setattr("ai_osop.core.sqli_oracle.detect_error_based", fake_error_based)
    monkeypatch.setattr("ai_osop.core.sqli_oracle.detect_time_blind", fake_none)
    monkeypatch.setattr("ai_osop.core.sqli_oracle.detect_login_bypass", fake_none)
    monkeypatch.setattr("ai_osop.core.sqlmap_confirm.sqlmap_available", lambda: True)
    monkeypatch.setattr("ai_osop.core.sqlmap_confirm.sqlmap_confirm", fake_confirm)

    persisted, _ = await ds.run_generalized_sqli(
        "eng-y", _GM(), per_check_timeout=2.0, confirm_with_sqlmap=True,
    )
    assert len(persisted) == 1
    assert captured["v"].tool_source == "deterministic_scan_generalized"
