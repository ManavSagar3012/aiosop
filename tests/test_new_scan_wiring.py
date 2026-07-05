"""Wiring tests for the four newly-dispatchable detection engines in the vuln
agent: file_upload_scan, prototype_pollution_scan, websocket_scan, saml_scan.

Offline & deterministic: each tester class is monkeypatched with a fake whose
run() returns a caller-chosen list of result objects. We assert that a CONFIRMED
result mints exactly one validated Vulnerability with the right tool_source, and
that a NON-confirmed result mints nothing (no false positives).
"""

import asyncio
from types import SimpleNamespace

import ai_osop.core.file_upload_tester as fu_mod
import ai_osop.core.prototype_pollution_tester as pp_mod
import ai_osop.core.websocket_tester as ws_mod
import ai_osop.core.saml_tester as saml_mod
from ai_osop.agents.vuln_agent import VulnAnalysisAgent


def _capture(store, v):
    store.append(v)
    async def _ok():
        return None
    return _ok()


def _agent(captured):
    a = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    a.findings = {}
    a.ctx = SimpleNamespace(
        current_task=SimpleNamespace(engagement_id="eng-new"),
        graph_memory=SimpleNamespace(add_vulnerability=lambda v: _capture(captured, v)),
    )
    return a


def _fake_tester_class(results):
    """Return a class that ignores its ctor args and whose run() yields `results`."""
    class _Fake:
        def __init__(self, *args, **kwargs):
            pass

        async def run(self):
            return list(results)

    return _Fake


# --------------------------------------------------------------------------- #
# file_upload_scan
# --------------------------------------------------------------------------- #
def test_file_upload_confirmed_mints(monkeypatch):
    captured = []
    agent = _agent(captured)
    confirmed = SimpleNamespace(
        technique="php_ext", confirmed=True, detail="served as application/x-httpd-php",
        marker="OSOP123", filename="x.php", retrieval_url="http://t/uploads/x.php",
        served_content_type="application/x-httpd-php", evidence={"upload_status": 200},
    )
    monkeypatch.setattr(fu_mod, "FileUploadTester", _fake_tester_class([confirmed]))
    res = asyncio.run(agent._execute_file_upload_scan(
        {"upload_url": "http://t/upload", "engagement_id": "eng-new"}))
    assert res["confirmed"] is True and res["findings_count"] == 1
    v = captured[0]
    assert v.validated is True and v.tool_source == "file_upload_scan"
    assert v.cwe == "CWE-434"


def test_file_upload_unconfirmed_no_finding(monkeypatch):
    captured = []
    agent = _agent(captured)
    nope = SimpleNamespace(
        technique="php_ext", confirmed=False, detail="not served",
        marker="OSOP123", filename="x.php", retrieval_url="", served_content_type="",
        evidence={},
    )
    monkeypatch.setattr(fu_mod, "FileUploadTester", _fake_tester_class([nope]))
    res = asyncio.run(agent._execute_file_upload_scan(
        {"upload_url": "http://t/upload", "engagement_id": "eng-new"}))
    assert res["confirmed"] is False and res["findings_count"] == 0
    assert captured == []


# --------------------------------------------------------------------------- #
# prototype_pollution_scan
# --------------------------------------------------------------------------- #
def test_prototype_pollution_confirmed_mints(monkeypatch):
    captured = []
    agent = _agent(captured)
    confirmed = SimpleNamespace(
        technique="reflected_property", confirmed=True,
        detail="inherited property observed in payload-free probe",
        gadget="__proto__", evidence={"marker_key": "osop"},
    )
    monkeypatch.setattr(pp_mod, "PrototypePollutionTester", _fake_tester_class([confirmed]))
    res = asyncio.run(agent._execute_prototype_pollution_scan(
        {"pollute_url": "http://t/merge", "engagement_id": "eng-new"}))
    assert res["confirmed"] is True and res["findings_count"] == 1
    v = captured[0]
    assert v.validated is True and v.tool_source == "prototype_pollution_scan"
    assert v.cwe == "CWE-1321"


def test_prototype_pollution_unconfirmed_no_finding(monkeypatch):
    captured = []
    agent = _agent(captured)
    nope = SimpleNamespace(
        technique="reflected_property", confirmed=False, detail="not confirmed",
        gadget="__proto__", evidence={},
    )
    monkeypatch.setattr(pp_mod, "PrototypePollutionTester", _fake_tester_class([nope]))
    res = asyncio.run(agent._execute_prototype_pollution_scan(
        {"pollute_url": "http://t/merge", "engagement_id": "eng-new"}))
    assert res["confirmed"] is False and res["findings_count"] == 0
    assert captured == []


# --------------------------------------------------------------------------- #
# websocket_scan
# --------------------------------------------------------------------------- #
def test_websocket_confirmed_mints(monkeypatch):
    captured = []
    agent = _agent(captured)
    confirmed = SimpleNamespace(
        technique="cswsh", confirmed=True,
        detail="foreign Origin + victim cookies returned authed data",
        evidence={"origin": "https://evil.test"},
    )
    monkeypatch.setattr(ws_mod, "WebSocketTester", _fake_tester_class([confirmed]))
    res = asyncio.run(agent._execute_websocket_scan(
        {"url": "wss://t/ws", "engagement_id": "eng-new"}))
    assert res["confirmed"] is True and res["findings_count"] == 1
    v = captured[0]
    assert v.validated is True and v.tool_source == "websocket_scan"
    assert v.cwe == "CWE-1385"


def test_websocket_unconfirmed_no_finding(monkeypatch):
    captured = []
    agent = _agent(captured)
    nope = SimpleNamespace(technique="cswsh", confirmed=False, detail="rejected", evidence={})
    monkeypatch.setattr(ws_mod, "WebSocketTester", _fake_tester_class([nope]))
    res = asyncio.run(agent._execute_websocket_scan(
        {"url": "wss://t/ws", "engagement_id": "eng-new"}))
    assert res["confirmed"] is False and res["findings_count"] == 0
    assert captured == []


# --------------------------------------------------------------------------- #
# saml_scan
# --------------------------------------------------------------------------- #
def test_saml_confirmed_mints(monkeypatch):
    captured = []
    agent = _agent(captured)
    confirmed = SimpleNamespace(
        technique="xml_signature_wrapping", confirmed=True,
        detail="ACS granted a session for the attacker identity",
        attacker_identity="osop-attacker@evil.test", evidence={"status": 302},
        tampered_response="",
    )
    monkeypatch.setattr(saml_mod, "SAMLTester", _fake_tester_class([confirmed]))
    res = asyncio.run(agent._execute_saml_scan(
        {"acs_url": "http://t/acs", "saml_response": "<Response/>", "engagement_id": "eng-new"}))
    assert res["confirmed"] is True and res["findings_count"] == 1
    v = captured[0]
    assert v.validated is True and v.tool_source == "saml_scan"
    assert v.cwe == "CWE-347"


def test_saml_unconfirmed_no_finding(monkeypatch):
    captured = []
    agent = _agent(captured)
    nope = SimpleNamespace(
        technique="unsigned_assertion", confirmed=False, detail="rejected",
        attacker_identity="osop-attacker@evil.test", evidence={}, tampered_response="",
    )
    monkeypatch.setattr(saml_mod, "SAMLTester", _fake_tester_class([nope]))
    res = asyncio.run(agent._execute_saml_scan(
        {"acs_url": "http://t/acs", "saml_response": "<Response/>", "engagement_id": "eng-new"}))
    assert res["confirmed"] is False and res["findings_count"] == 0
    assert captured == []
