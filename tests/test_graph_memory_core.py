"""Unit tests for ai_osop.memory.graph_memory that run without a live Neo4j.

Seam: instantiate GraphMemory (its __init__ never connects) and inject a
MagicMock driver whose session returns a FakeResult. Tests assert the exact
Cypher text contains the clauses we depend on (MERGE shape, dedup key,
UNWIND), the params dict content, the deterministic id/host derivations, the
pure dedup/nuclei-guard helpers, and the documented error-swallowing safe
defaults. Nothing here touches a real database.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from unittest.mock import AsyncMock, MagicMock, patch

from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.core.models import (
    Asset,
    Endpoint,
    Vulnerability,
    Workflow,
    WorkflowStep,
    WorkflowTransition,
    Hypothesis,
    BusinessInvariant,
    Exploit,
)
from ai_osop.core.enums import VulnClass, Severity


# --------------------------------------------------------------------------- #
# Fakes / factories
# --------------------------------------------------------------------------- #


class FakeResult:
    """Minimal stand-in for neo4j.AsyncResult covering the API GraphMemory uses."""

    def __init__(self, records=None, record=None):
        self._records = list(records or [])
        self._record = record
        self.consumed = False
        self._idx = 0

    async def single(self): return self._record
    async def data(self): return list(self._records)
    async def consume(self):
        self.consumed = True
        return MagicMock()
    def __aiter__(self):
        self._idx = 0
        return self
    async def __anext__(self):
        if self._idx >= len(self._records): raise StopAsyncIteration
        r = self._records[self._idx]; self._idx += 1; return r


def make_session(result=None):
    if result is None: result = FakeResult()
    s = MagicMock(); s.run = AsyncMock(return_value=result); return s


def make_gm(result=None, session=None):
    """Return (GraphMemory, session) with a mocked async driver attached."""
    gm = GraphMemory()
    if session is None: session = make_session(result)
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=False)
    driver = MagicMock(); driver.close = AsyncMock(); driver.session = MagicMock(return_value=ctx)
    gm._driver = driver
    return gm, session


def _vuln(**kw):
    defaults = dict(vuln_type=VulnClass.SQLI, severity=Severity.HIGH,
                    title="SQL Injection", description="d", tool_source="sqlmap",
                    confidence=0.9, engagement_id="eng-1")
    defaults.update(kw); return Vulnerability(**defaults)


# --------------------------------------------------------------------------- #
# Constructor: must never connect
# --------------------------------------------------------------------------- #

def test_constructor_does_not_connect_and_hooks_default_to_none():
    gm = GraphMemory()
    assert gm._driver is None
    assert gm.findings_knowledge is None
    assert gm.primitive_ledger is None
    assert gm.calibration_engine is None
    assert gm.coordination_bus is None


# --------------------------------------------------------------------------- #
# _vulnerability_dedup_key: canonical content-based hash
# --------------------------------------------------------------------------- #

def test_dedup_key_deterministic_for_identical_input():
    assert GraphMemory._vulnerability_dedup_key(_vuln()) == GraphMemory._vulnerability_dedup_key(_vuln())


def test_dedup_key_is_sha256_hex():
    k = GraphMemory._vulnerability_dedup_key(_vuln())
    assert isinstance(k, str) and len(k) == 64 and all(c in "0123456789abcdef" for c in k)


def test_dedup_key_differs_when_title_differs():
    assert GraphMemory._vulnerability_dedup_key(_vuln(title="SQL Injection")) != GraphMemory._vulnerability_dedup_key(_vuln(title="XSS Reflected"))


def test_dedup_key_scoped_per_engagement():
    v = _vuln(); v.engagement_id = "eng-2"
    assert GraphMemory._vulnerability_dedup_key(_vuln()) != GraphMemory._vulnerability_dedup_key(v)


def test_dedup_key_uses_evidence_template_and_matched_at_when_present():
    v = _vuln(evidence=[{"template": "tpl-1", "matched_at": "https://x/api"}])
    identity = {"engagement_id": "eng-1", "tool_source": "sqlmap", "template": "tpl-1", "location": "https://x/api"}
    expected = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert GraphMemory._vulnerability_dedup_key(v) == expected


def test_dedup_key_falls_back_to_lowercase_stripped_title_and_location_precedence():
    v = _vuln(title="  SQL Injection  ", evidence=[{"url": "https://x/"}])
    identity = {"engagement_id": "eng-1", "tool_source": "sqlmap", "template": "sql injection", "location": "https://x/"}
    expected = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert GraphMemory._vulnerability_dedup_key(v) == expected


# --------------------------------------------------------------------------- #
# _apply_nuclei_spa_persistence_guard
# --------------------------------------------------------------------------- #

def test_nuclei_guard_applies_only_to_nuclei():
    sig = [{"false_positive_signal": {"status_only_match": True, "spa_response": True}}]
    v = _vuln(tool_source="sqlmap", confidence=0.9, evidence=sig)
    GraphMemory._apply_nuclei_spa_persistence_guard(v); assert v.confidence == 0.9


def test_nuclei_guard_clamps_confidence_to_0_1_and_marks_unvalidated():
    sig = [{"false_positive_signal": {"status_only_match": True, "spa_response": True}}]
    v = _vuln(tool_source="nuclei", confidence=0.9, evidence=sig)
    GraphMemory._apply_nuclei_spa_persistence_guard(v)
    assert v.confidence == 0.1 and v.validated is False and v.exploitability == "low"


def test_nuclei_guard_min_keeps_already_low_confidence():
    sig = [{"false_positive_signal": {"status_only_match": True, "spa_response": True}}]
    v = _vuln(tool_source="nuclei", confidence=0.05, evidence=sig)
    GraphMemory._apply_nuclei_spa_persistence_guard(v); assert v.confidence == 0.05


def test_nuclei_guard_skips_when_status_only_match_is_false():
    sig = [{"false_positive_signal": {"status_only_match": False, "spa_response": True}}]
    v = _vuln(tool_source="nuclei", confidence=0.8, evidence=sig)
    GraphMemory._apply_nuclei_spa_persistence_guard(v); assert v.confidence == 0.8


# --------------------------------------------------------------------------- #
# add_asset
# --------------------------------------------------------------------------- #

async def test_add_asset_builds_merge_cypher_with_metadata_json_and_returns_db_id():
    gm, session = make_gm(FakeResult(record={"a.id": "asset-db-1"}))
    asset = Asset(type="domain", value="example.com", source="recon", confidence=0.7, metadata={"k": "v"}, engagement_id="eng-1")
    out = await gm.add_asset(asset)
    cy, params = session.run.await_args.args
    assert "MERGE (a:Asset {id: $id})" in cy
    assert params["value"] == "example.com" and params["engagement_id"] == "eng-1"
    # metadata must be JSON-serialized: Neo4j rejects raw map properties, so
    # add_asset json.dumps() it (AIOSOP-ASSET-MAPPROP). The old assertion checked
    # the raw dict — a value the live DB rejects — because this test mocks the
    # driver and never hit real Neo4j. The test name ("metadata_json") already
    # documented the intended behavior.
    assert params["metadata"] == '{"k": "v"}' and out == "asset-db-1"


# --------------------------------------------------------------------------- #
# add_endpoint
# --------------------------------------------------------------------------- #

async def test_add_endpoint_returns_db_id_when_record_present():
    gm, _ = make_gm(FakeResult(record={"id": "db-ep-1"}))
    assert await gm.add_endpoint(Endpoint(url="https://a/", engagement_id="eng-1")) == "db-ep-1"


async def test_add_endpoint_falls_back_to_model_id_when_record_is_none():
    gm, _ = make_gm(FakeResult(record=None))
    ep = Endpoint(url="https://a/", engagement_id="eng-1"); assert await gm.add_endpoint(ep) == ep.id


async def test_add_endpoint_invalidates_graph_stats_cache_for_engagement():
    gm, _ = make_gm(FakeResult(record={"id": "db-ep-1"}))
    gm._graph_stats_cache["eng-1"] = {"stale": True}
    await gm.add_endpoint(Endpoint(url="https://a/", engagement_id="eng-1"))
    assert "eng-1" not in gm._graph_stats_cache


# --------------------------------------------------------------------------- #
# add_vulnerability
# --------------------------------------------------------------------------- #

async def test_add_vulnerability_rejects_simulated_without_issuing_cypher():
    gm, session = make_gm(FakeResult())
    v = _vuln(tool_source="mock-scanner", title="fake"); out = await gm.add_vulnerability(v)
    assert out == v.id and session.run.await_count == 0


async def test_add_vulnerability_derives_host_from_evidence_url_stripping_userinfo_and_port():
    gm, session = make_gm(FakeResult(record={"id": "v-1", "created": True}))
    v = _vuln(evidence=[{"url": "https://user:pw@Example.COM:8443/a"}])
    await gm.add_vulnerability(v)
    _, params = session.run.await_args.args; assert params["host"] == "example.com"


async def test_add_vulnerability_params_include_fresh_id_dedup_key_and_enum_values():
    gm, session = make_gm(FakeResult(record={"id": "v-1", "created": True}))
    v = _vuln(); expected_dk = GraphMemory._vulnerability_dedup_key(v)
    await gm.add_vulnerability(v); cy, params = session.run.await_args.args
    assert "MERGE (v:Vulnerability {dedup_key: $dedup_key})" in cy
    assert params["dedup_key"] == expected_dk and params["id"] == v.id
    assert params["fresh_id"].startswith("vuln-") and len(params["fresh_id"]) == len("vuln-") + 12
    assert params["vuln_type"] == "sqli" and params["severity"] == "high" and params["engagement_id"] == "eng-1"


async def test_add_vulnerability_returns_persisted_id_preferring_id_then_v_id():
    gm, _ = make_gm(FakeResult(record={"id": "db-id", "created": True}))
    assert await gm.add_vulnerability(_vuln()) == "db-id"
    gm2, _ = make_gm(FakeResult(record={"v.id": "legacy-id", "created": True}))
    assert await gm2.add_vulnerability(_vuln()) == "legacy-id"


async def test_add_vulnerability_applies_nuclei_spa_guard_before_write():
    gm, session = make_gm(FakeResult(record={"id": "v-1", "created": True}))
    sig = [{"false_positive_signal": {"status_only_match": True, "spa_response": True}}]
    v = _vuln(tool_source="nuclei", confidence=0.9, evidence=sig)
    await gm.add_vulnerability(v); _, params = session.run.await_args.args
    assert params["confidence"] == 0.1 and params["validated"] is False and params["exploitability"] == "low"


async def test_add_vulnerability_notifies_findings_knowledge_only_on_create():
    gm_new, _ = make_gm(FakeResult(record={"id": "v-1", "created": True}))
    fk_new = MagicMock(); fk_new.record_finding = AsyncMock(); gm_new.findings_knowledge = fk_new
    await gm_new.add_vulnerability(_vuln()); assert fk_new.record_finding.await_count == 1
    gm_dup, _ = make_gm(FakeResult(record={"id": "v-1", "created": False}))
    fk_dup = MagicMock(); fk_dup.record_finding = AsyncMock(); gm_dup.findings_knowledge = fk_dup
    await gm_dup.add_vulnerability(_vuln()); assert fk_dup.record_finding.await_count == 0


async def test_add_vulnerability_publishes_finding_recorded_event_on_create():
    gm, _ = make_gm(FakeResult(record={"id": "db-v", "created": True}))
    bus = MagicMock(); bus.publish = AsyncMock(); gm.coordination_bus = bus
    await gm.add_vulnerability(_vuln(title="T")); args, kwargs = bus.publish.await_args
    assert args[0] == "finding.recorded" and args[1]["finding_id"] == "db-v"
    assert args[1]["engagement_id"] == "eng-1" and kwargs.get("source") == "graph_memory"


async def test_add_vulnerability_finding_knowledge_exception_is_swallowed():
    gm, _ = make_gm(FakeResult(record={"id": "v-1", "created": True}))
    fk = MagicMock(); fk.record_finding = AsyncMock(side_effect=RuntimeError("kb down")); gm.findings_knowledge = fk
    out = await gm.add_vulnerability(_vuln()); assert out == "v-1"


# --------------------------------------------------------------------------- #
# add_vulnerabilities_batch / add_endpoints_batch (UNWIND)
# --------------------------------------------------------------------------- #

async def test_add_vulnerabilities_batch_unwinds_rows_and_returns_db_ids():
    gm, session = make_gm(FakeResult(records=[{"id": "id-a", "dedup_key": "dk-a", "created": True}]))
    v1 = _vuln(title="A"); ids = await gm.add_vulnerabilities_batch([v1])
    cy, params = session.run.await_args.args
    assert "UNWIND" in cy and len(params["rows"]) == 1 and ids == ["id-a"]


async def test_add_vulnerabilities_batch_dedupes_identical_rows_in_batch():
    gm, session = make_gm(FakeResult(records=[{"id": "id-a", "dedup_key": "dk-a", "created": True}]))
    v1 = _vuln(title="A"); v2 = _vuln(title="A")
    await gm.add_vulnerabilities_batch([v1, v2]); _, params = session.run.await_args.args
    assert len(params["rows"]) == 1


async def test_add_vulnerabilities_batch_filters_simulated_and_no_query_when_all_simulated():
    gm, session = make_gm(FakeResult(records=[]))
    v_sim = _vuln(tool_source="mock-scanner", title="sim"); ids = await gm.add_vulnerabilities_batch([v_sim])
    assert ids == [] and session.run.await_count == 0


async def test_add_vulnerabilities_batch_applies_nuclei_guard_to_rows():
    sig = [{"false_positive_signal": {"status_only_match": True, "spa_response": True}}]
    vn = _vuln(tool_source="nuclei", confidence=0.9, title="T1", evidence=sig)
    dk = GraphMemory._vulnerability_dedup_key(vn)
    gm, session = make_gm(FakeResult(records=[{"id": "id-n", "dedup_key": dk, "created": True}]))
    await gm.add_vulnerabilities_batch([vn]); _, params = session.run.await_args.args
    row = params["rows"][0]; assert row["confidence"] == 0.1 and row["validated"] is False and row["exploitability"] == "low"


async def test_add_vulnerabilities_batch_notifies_findings_knowledge_only_for_created_records():
    dk = GraphMemory._vulnerability_dedup_key(_vuln(title="A"))
    gm, _ = make_gm(FakeResult(records=[{"id": "id-a", "dedup_key": dk, "created": True}]))
    fk = MagicMock(); fk.record_finding = AsyncMock(); gm.findings_knowledge = fk
    await gm.add_vulnerabilities_batch([_vuln(title="A")]); assert fk.record_finding.await_count == 1
    gm2, _ = make_gm(FakeResult(records=[{"id": "id-a", "dedup_key": dk, "created": False}]))
    fk2 = MagicMock(); fk2.record_finding = AsyncMock(); gm2.findings_knowledge = fk2
    await gm2.add_vulnerabilities_batch([_vuln(title="A")]); assert fk2.record_finding.await_count == 0


async def test_add_endpoints_batch_unwinds_rows_and_returns_ids_in_order():
    gm, session = make_gm(FakeResult(records=[{"id": "e1"}, {"id": "e2"}]))
    ep1 = Endpoint(url="http://a/", engagement_id="eng-1"); ep2 = Endpoint(url="http://b/", engagement_id="eng-1")
    ids = await gm.add_endpoints_batch([ep1, ep2]); cy, params = session.run.await_args.args
    assert "UNWIND" in cy and len(params["rows"]) == 2 and ids == ["e1", "e2"]


async def test_add_endpoints_batch_empty_list_short_circuits():
    gm, session = make_gm(FakeResult()); assert await gm.add_endpoints_batch([]) == [] and session.run.await_count == 0


# --------------------------------------------------------------------------- #
# add_exploit / validate_vulnerability
# --------------------------------------------------------------------------- #

async def test_add_exploit_returns_db_id_when_record_present():
    gm, session = make_gm(FakeResult(record={"id": "db-exploit"}))
    ex = Exploit(vuln_id="v-1", payload_id="p-1", type="poc", engagement_id="eng-1")
    assert await gm.add_exploit(ex) == "db-exploit"


async def test_add_exploit_falls_back_to_model_id_and_links_vuln_and_payload():
    gm, session = make_gm(FakeResult(record=None))
    ex = Exploit(vuln_id="v-1", payload_id="p-1", type="poc", engagement_id="eng-1"); out = await gm.add_exploit(ex)
    cy, params = session.run.await_args.args
    assert out == ex.id and params["vuln_id"] == "v-1" and params["payload_id"] == "p-1"
    assert "EXPLOITED_BY" in cy and "USES_PAYLOAD" in cy


async def test_validate_vulnerability_sets_validated_and_confidence_one():
    gm, session = make_gm(FakeResult(record={"id": "v-1", "vuln_type": "sqli", "engagement_id": "eng-1"}))
    await gm.validate_vulnerability("v-1")
    # The validate path calls session.run twice (validate + evidence check); assert
    # the FIRST call is the validated=true / confidence=1.0 write.
    cy, params = session.run.await_args_list[0].args
    assert "v.validated = true" in cy and "v.confidence = 1.0" in cy and params["vid"] == "v-1"


async def test_validate_vulnerability_records_accepted_outcome_when_calibration_engine_set():
    gm, _ = make_gm(FakeResult(record={"id": "v-1", "vuln_type": "sqli", "engagement_id": "eng-1"}))
    cal = MagicMock(); cal.record_outcome = AsyncMock(); gm.calibration_engine = cal
    await gm.validate_vulnerability("v-1"); kw = cal.record_outcome.await_args.kwargs
    assert kw["outcome"] == "accepted" and kw["finding_data"] == {"id": "v-1", "category": "sqli", "engagement_id": "eng-1"}


async def test_validate_vulnerability_skips_calibration_when_record_missing():
    gm, _ = make_gm(FakeResult(record=None)); cal = MagicMock(); cal.record_outcome = AsyncMock(); gm.calibration_engine = cal
    await gm.validate_vulnerability("v-x"); assert cal.record_outcome.await_count == 0


# --------------------------------------------------------------------------- #
# Workflow / WorkflowStep / WorkflowTransition
# --------------------------------------------------------------------------- #

async def test_add_workflow_returns_db_id_and_passes_role():
    gm, session = make_gm(FakeResult(record={"id": "wf-1"}))
    wf = Workflow(name="Login Flow", role="user", engagement_id="eng-1"); assert await gm.add_workflow(wf) == "wf-1"
    _, params = session.run.await_args.args
    assert params["name"] == "Login Flow" and params["role"] == "user" and params["engagement_id"] == "eng-1"


async def test_add_workflow_step_returns_db_id_and_copies_fields():
    gm, session = make_gm(FakeResult(record={"id": "step-1"}))
    st = WorkflowStep(workflow_id="wf-1", endpoint_id="e-1", order=2, action_type="CLICK", engagement_id="eng-1")
    assert await gm.add_workflow_step(st) == "step-1"
    _, params = session.run.await_args.args
    assert params["workflow_id"] == "wf-1" and params["endpoint_id"] == "e-1" and params["order"] == 2 and params["action_type"] == "CLICK"


async def test_add_workflow_transition_returns_db_id_and_copies_trigger():
    gm, session = make_gm(FakeResult(record={"id": "tr-1"}))
    tr = WorkflowTransition(from_step_id="s1", to_step_id="s2", trigger="click", engagement_id="eng-1")
    assert await gm.add_workflow_transition(tr) == "tr-1"
    _, params = session.run.await_args.args
    assert params["from_step_id"] == "s1" and params["to_step_id"] == "s2" and params["trigger"] == "click"


# --------------------------------------------------------------------------- #
# Hypotheses
# --------------------------------------------------------------------------- #

async def test_add_hypothesis_returns_db_id():
    gm, session = make_gm(FakeResult(record={"id": "h-1"}))
    h = Hypothesis(title="JWT weak secret", description="d", category="auth", target_id="e-1", confidence=0.7, engagement_id="eng-1")
    assert await gm.add_hypothesis(h) == "h-1"
    _, params = session.run.await_args.args
    assert params["title"] == "JWT weak secret" and params["confidence"] == 0.7


async def test_get_hypotheses_by_engagement_converts_node_to_plain_dict():
    class Node(dict): pass
    gm, _ = make_gm(FakeResult(records=[{"h": Node({"id": "h1", "confidence": 0.9})}]))
    assert await gm.get_hypotheses_by_engagement("eng-1", "eng-1-alias") == [{"id": "h1", "confidence": 0.9}]


# --------------------------------------------------------------------------- #
# BusinessInvariant / get_invariants
# --------------------------------------------------------------------------- #

async def test_add_business_invariant_persists_violated_flag_and_json_state():
    gm, session = make_gm(FakeResult(record={"id": "inv-1"}))
    bi = BusinessInvariant(id="inv-1", description="d", target_resource_type="endpoint", required_state='{"k":"v"}', violation_strategy="block", actor_constraints=["a"], engagement_id="eng-1")
    assert await gm.add_business_invariant(bi, "eng-1", is_violated=True) == "inv-1"
    _, params = session.run.await_args.args
    assert params["is_violated"] is True and params["required_state"] == '{"k":"v"}' and params["engagement_id"] == "eng-1"


async def test_get_invariants_shapes_ui_keys_and_casts_is_violated_to_bool():
    class Node(dict): pass
    gm, _ = make_gm(FakeResult(records=[{"i": Node({"id": "inv-1", "description": "d", "target_resource_type": "endpoint", "violation_strategy": "block", "is_violated": 1})}]))
    out = await gm.get_invariants("eng-1")
    assert out == [{"id": "inv-1", "description": "d", "target_resource_type": "endpoint", "violation_strategy": "block", "is_violated": True}]


# --------------------------------------------------------------------------- #
# attach_evidence_to_step
# --------------------------------------------------------------------------- #

async def test_attach_evidence_to_step_returns_db_id_and_derives_evidence_id():
    gm, session = make_gm(FakeResult(record={"id": "ev-from-db"}))
    out = await gm.attach_evidence_to_step("step-1", "screenshot", "/tmp/ev.png", "eng-1", workflow_id="wf-1", extra={"k": 1})
    expected_id = "ev-" + hashlib.sha1("step-1|/tmp/ev.png".encode()).hexdigest()[:16]
    _, params = session.run.await_args.args
    assert out == "ev-from-db" and params["id"] == expected_id and params["step_id"] == "step-1"
    assert params["type"] == "screenshot" and json.loads(params["extra"]) == {"k": 1}


async def test_attach_evidence_to_step_extra_defaults_to_empty_json_object():
    gm, session = make_gm(FakeResult(record={"id": "ev"}))
    await gm.attach_evidence_to_step("step-1", "screenshot", "/tmp/ev.png", "eng-1")
    _, params = session.run.await_args.args
    assert params["extra"] == "{}"


# --------------------------------------------------------------------------- #
# Session sync (sync_user_session / delete_user_session_node)
# --------------------------------------------------------------------------- #

async def test_sync_user_session_bearer_token_yields_bearer_cred_type_and_admin_role():
    class Sess:
        engagement_id = "eng-1"; user_label = "admin_jane"; captured_at = None; expires_at = None; bearer_token = "tok"; cookies = []
    gm, session = make_gm(FakeResult()); await gm.sync_user_session(Sess())
    _, params = session.run.await_args.args
    assert params["identity_id"] == "identity-eng-1-admin_jane" and params["session_id"] == "session-eng-1-admin_jane"
    assert params["credential_id"] == "credential-eng-1-admin_jane" and params["cred_type"] == "bearer"
    assert params["role_name"] == "admin" and params["role_id"] == "role-eng-1-admin" and params["captured_at"] is None


async def test_sync_user_session_cookies_and_non_admin_label_defaults():
    class Sess:
        engagement_id = "eng-1"; user_label = "bob"; captured_at = None; expires_at = None; bearer_token = None; cookies = [{"k": "v"}]
    gm, session = make_gm(FakeResult()); await gm.sync_user_session(Sess())
    _, params = session.run.await_args.args
    assert params["cred_type"] == "cookie" and params["role_name"] == "standard" and params["role_id"] == "role-eng-1-standard" and params["session_id"] == "session-eng-1-bob"


async def test_delete_user_session_node_sends_detach_delete_with_both_ids():
    gm, session = make_gm(FakeResult()); await gm.delete_user_session_node("eng-1", "bob")
    cy, params = session.run.await_args.args
    assert "DETACH DELETE" in cy and params == {"session_id": "session-eng-1-bob", "credential_id": "credential-eng-1-bob"}


# --------------------------------------------------------------------------- #
# Graph stats cache
# --------------------------------------------------------------------------- #

async def test_get_graph_stats_hits_cache_on_second_call():
    rec = {"endpoints": 1, "assets": 0, "vulnerabilities": 2, "exploits": 0, "workflows": 0}
    gm, session = make_gm(FakeResult(record=rec))
    assert await gm.get_graph_stats("eng-1") == rec and await gm.get_graph_stats("eng-1") == rec
    assert session.run.await_count == 1


async def test_invalidate_graph_stats_cache_forces_refetch():
    rec = {"endpoints": 1}; gm, session = make_gm(FakeResult(record=rec))
    await gm.get_graph_stats("eng-1"); await gm.invalidate_graph_stats_cache("eng-1"); await gm.get_graph_stats("eng-1")
    assert session.run.await_count == 2


async def test_get_graph_stats_returns_empty_dict_when_record_is_none():
    gm, _ = make_gm(FakeResult(record=None)); assert await gm.get_graph_stats("eng-x") == {}


# --------------------------------------------------------------------------- #
# Task lifecycle (upsert retry, task_has_spawned, claim_auto_discovery, etc.)
# --------------------------------------------------------------------------- #

async def test_upsert_task_consumes_result_and_returns_true():
    result = FakeResult(); gm, _ = make_gm(result)
    ok = await gm.upsert_task(MagicMock(id="t-1", type="map_workflow", engagement_id="eng-1",
                                        agent_type=MagicMock(value="recon"), status="pending",
                                        priority=5, payload={}, result=None,
                                        max_retries=3, timeout_seconds=60, recovery_attempts=0,
                                        parent_task_id=None, created_at=MagicMock(isoformat=lambda: "2026-08-01"),
                                        updated_at=MagicMock(isoformat=lambda: "2026-08-01")))
    assert ok is True and result.consumed is True


async def test_upsert_task_serializes_result_summary_with_json():
    result = FakeResult(); gm, session = make_gm(result)
    task = MagicMock(id="t-2", type="map_workflow", engagement_id="eng-1",
                     agent_type=MagicMock(value="recon"), status="completed",
                     priority=5, payload={}, result={"note": "log-safe"},
                     max_retries=3, timeout_seconds=60, recovery_attempts=0,
                     parent_task_id=None, created_at=MagicMock(isoformat=lambda: "2026-08-01"),
                     updated_at=MagicMock(isoformat=lambda: "2026-08-01"))
    await gm.upsert_task(task, result_summary={"found": 3}); _, params = session.run.await_args.args
    assert json.loads(params["result_summary"]) == {"found": 3}


async def test_task_has_spawned_returns_true_only_when_count_positive():
    gm1, _ = make_gm(FakeResult(record={"c": 1})); assert await gm1.task_has_spawned("t-1") is True
    gm2, _ = make_gm(FakeResult(record={"c": 0})); assert await gm2.task_has_spawned("t-1") is False
    gm3, _ = make_gm(FakeResult(record=None)); assert await gm3.task_has_spawned("t-1") is False


async def test_task_has_spawned_swallows_exceptions_and_returns_false():
    session = MagicMock(); session.run = AsyncMock(side_effect=RuntimeError("neo4j down"))
    gm, _ = make_gm(session=session); assert await gm.task_has_spawned("t-1") is False


async def test_claim_auto_discovery_returns_bool_of_is_new():
    gm1, _ = make_gm(FakeResult(record={"is_new": True})); assert await gm1.claim_auto_discovery("eng-1") is True
    gm2, _ = make_gm(FakeResult(record={"is_new": False})); assert await gm2.claim_auto_discovery("eng-1") is False
    gm3, _ = make_gm(FakeResult(record=None)); assert await gm3.claim_auto_discovery("eng-1") is False


async def test_claim_auto_discovery_swallows_exceptions_and_returns_false():
    session = MagicMock(); session.run = AsyncMock(side_effect=RuntimeError("boom"))
    gm, _ = make_gm(session=session); assert await gm.claim_auto_discovery("eng-1") is False


async def test_reset_interrupted_tasks_returns_list_of_plain_dicts_and_marks_interrupted():
    gm, session = make_gm(FakeResult(records=[{"id": "t-1", "type": "map_workflow", "engagement_id": "eng-1"}]))
    out = await gm.reset_interrupted_tasks(); cy = session.run.await_args.args[0]
    assert "status='interrupted'" in cy and "recovery_attempts" in cy
    assert out == [{"id": "t-1", "type": "map_workflow", "engagement_id": "eng-1"}]


async def test_mark_task_status_sends_id_and_status_only():
    gm, session = make_gm(FakeResult()); await gm.mark_task_status("t-9", "failed")
    _, params = session.run.await_args.args
    assert params["id"] == "t-9" and params["status"] == "failed" and isinstance(params["ts"], str)


async def test_find_incomplete_chains_returns_records_as_dicts():
    gm, _ = make_gm(FakeResult(records=[{"id": "t-2"}, {"id": "t-3"}]))
    assert await gm.find_incomplete_chains() == [{"id": "t-2"}, {"id": "t-3"}]


async def test_get_task_dependents_returns_child_ids():
    gm, session = make_gm(FakeResult(records=[{"id": "child-1"}, {"id": "child-2"}]))
    out = await gm.get_task_dependents("parent-1"); cy, params = session.run.await_args.args
    assert "SPAWNED" in cy and params["pid"] == "parent-1" and out == ["child-1", "child-2"]


async def test_get_task_dependents_swallows_exceptions_and_returns_empty_list():
    session = MagicMock(); session.run = AsyncMock(side_effect=RuntimeError("boom"))
    gm, _ = make_gm(session=session); assert await gm.get_task_dependents("t-1") == []


# --------------------------------------------------------------------------- #
# Endpoint / node lookups, export
# --------------------------------------------------------------------------- #

async def test_get_node_details_merges_type_with_props():
    class Node(dict): pass
    gm, _ = make_gm(FakeResult(record={"type": "Endpoint", "props": Node({"id": "e-1", "url": "https://a/"})}))
    assert await gm.get_node_details("e-1") == {"type": "Endpoint", "id": "e-1", "url": "https://a/"}


async def test_get_node_details_returns_none_when_record_missing():
    gm, _ = make_gm(FakeResult(record=None)); assert await gm.get_node_details("missing") is None


async def test_get_all_nodes_and_edges_dedupe_alias_ids():
    gm_n, session_n = make_gm(FakeResult(records=[{"id": "n1"}]))
    out_n = await gm_n.get_all_nodes_for_engagement("e1", "", "e1", "e2")
    _, params_n = session_n.run.await_args.args
    assert params_n["ids"] == ["e1", "e2"] and out_n == [{"id": "n1"}]

    gm_e, session_e = make_gm(FakeResult(records=[{"source": "a"}]))
    out_e = await gm_e.get_all_edges_for_engagement("e1"); _, params_e = session_e.run.await_args.args
    assert params_e["ids"] == ["e1"] and out_e == [{"source": "a"}]


async def test_get_co_occurring_vuln_classes_adds_engagement_filter_when_provided():
    gm, session = make_gm(FakeResult(records=[{"class": "xss", "count": 3}]))
    out = await gm.get_co_occurring_vuln_classes("sqli", engagement_id="eng-1"); cy, params = session.run.await_args.args
    assert "v1.engagement_id = $engagement_id" in cy and params["engagement_id"] == "eng-1" and out == [{"class": "xss", "count": 3}]

    gm2, session2 = make_gm(FakeResult(records=[])); await gm2.get_co_occurring_vuln_classes("sqli")
    cy2, params2 = session2.run.await_args.args; assert "engagement_id" not in params2


# --------------------------------------------------------------------------- #
# Pool metrics: guard branches and lifecycle
# --------------------------------------------------------------------------- #

async def test_export_pool_metrics_with_no_driver_resets_gauges():
    with patch("ai_osop.memory.graph_memory.record_neo4j_pool_metrics") as rec:
        gm = GraphMemory(); await gm._export_pool_metrics()
        assert rec.call_count >= 1 and rec.call_args_list[-1].kwargs == {}


async def test_export_pool_metrics_no_pool_attr_resets_gauges():
    with patch("ai_osop.memory.graph_memory.record_neo4j_pool_metrics") as rec:
        gm = GraphMemory(); gm._driver = MagicMock(spec=[]); await gm._export_pool_metrics()
        assert rec.call_args_list[-1].kwargs == {}


async def test_export_pool_metrics_callable_in_use_total_from_connections_ready():
    with patch("ai_osop.memory.graph_memory.record_neo4j_pool_metrics") as rec:
        gm = GraphMemory(); driver = MagicMock()
        driver._pool.in_use_connection_count = MagicMock(return_value=7)
        driver._pool.connections = {"a", "b", "c"}; driver._pool.closed = False
        gm._driver = driver; gm._initialized = True; await gm._export_pool_metrics()
        kw = rec.call_args_list[-1].kwargs; assert kw == {"in_use": 7, "total": 7, "closed": False, "ready": True}


async def test_export_pool_metrics_non_int_in_use_becomes_zero_and_closed_pool_not_ready():
    with patch("ai_osop.memory.graph_memory.record_neo4j_pool_metrics") as rec:
        gm = GraphMemory(); driver = MagicMock()
        driver._pool.in_use_connection_count = "bogus"; driver._pool.connections = None; driver._pool.closed = True
        gm._driver = driver; gm._initialized = False; await gm._export_pool_metrics()
        kw = rec.call_args_list[-1].kwargs; assert kw == {"in_use": 0, "total": 0, "closed": True, "ready": False}


async def test_pool_metrics_lifecycle_start_then_stop_cancels_task():
    gm = GraphMemory(); export_mock = AsyncMock(); gm._export_pool_metrics = export_mock
    await gm.start_pool_metrics_export(interval=0)
    for _ in range(20):
        await asyncio.sleep(0)
        if export_mock.await_count >= 1: break
    await gm.stop_pool_metrics_export()
    assert export_mock.await_count >= 1 and gm._pool_metrics_task is None and gm._pool_metrics_running is False


async def test_pool_metrics_start_is_no_op_when_already_running():
    gm = GraphMemory(); gm._export_pool_metrics = AsyncMock()
    await gm.start_pool_metrics_export(interval=0)
    first_task = gm._pool_metrics_task
    await gm.start_pool_metrics_export(interval=0)
    assert gm._pool_metrics_task is first_task; await gm.stop_pool_metrics_export()


async def test_pool_metrics_stop_when_never_started_is_safe():
    gm = GraphMemory(); await gm.stop_pool_metrics_export(); assert gm._pool_metrics_task is None
