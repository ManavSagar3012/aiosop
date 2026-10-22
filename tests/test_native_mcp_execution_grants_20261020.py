"""Native grant cryptographic and transactional adversarial regression.

No application database or external tool is accessed. Optional live DDL
qualification may be added only against an explicitly disposable PostgreSQL.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import json
import time
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from ai_osop.mcp.protocol import MCPRegistry, MCPToolDefinition, SideEffectClass
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore, MCPActionDenied
from ai_osop.memory.flow_resource_exports import make_manifest
from ai_osop.memory.native_mcp_execution_grants import (
    DOMAIN,
    NativeMCPExecutionGrantStore,
    NativeMCPGrantDenied,
    _NATIVE_BUILTIN,
    _canonical,
    _native_manifest_sha256,
    _verify,
)
from ai_osop.memory.session_memory import SessionMemory

SECRET = "native-server-proof-with-at-least-32-bytes"
SHA = "a" * 64
REQ = "req-" + "b" * 48
ACTION = "action-" + "c" * 32


def binding() -> dict:
    return {
        "engagement_id": "eng-durable",
        "flow_id": "flow-current",
        "revision": 6,
        "version": 3,
        "authorization_id": "signed-3",
        "authorization_sha256": SHA,
    }


class Result:
    def __init__(self, one=None, rows=None):
        self.one = one
        self.rows = rows

    def mappings(self):
        return self

    def one_or_none(self):
        return self.one

    def scalar_one_or_none(self):
        return self.one

    def scalar_one(self):
        return self.one

    def all(self):
        return self.rows or []


class FakeDB:
    def __init__(self):
        self.dispatch = {}
        self.grants = {}
        self.events = []
        self.dispatched_event = True
        self.clock = int(time.time())
        self.fail_cas = False
        self.lock = asyncio.Lock()
        self.calls = []
        self.artifacts = []
        self.review = None
        self.pinned_resource = None
        self.reviewer_disabled = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    @asynccontextmanager
    async def begin(self):
        async with self.lock:
            yield self

    async def execute(self, sql, params=None):
        sql = str(sql)
        params = params or {}
        self.calls.append(sql)
        if sql.startswith("SELECT FLOOR(EXTRACT"):
            return Result(self.clock)
        if sql.startswith("SELECT * FROM flow_mcp_action_dispatches"):
            return Result(dict(self.dispatch) if self.dispatch else None)
        if sql.startswith("SELECT 1 FROM flow_mcp_action_dispatch_events"):
            return Result(1 if self.dispatched_event else None)
        if sql.startswith("SELECT payload FROM tasks"):
            return Result({"payload": {"mcp_resource_sha256": self.pinned_resource}})
        if sql.startswith("SELECT id,flow_id,name,size_bytes,sha256"):
            return Result(rows=[dict(row) for row in self.artifacts])
        if sql.startswith("SELECT uploader_sub,reviewer_sub,reviewer_role"):
            return Result(dict(self.review) if self.review is not None else None)
        if sql.startswith("SELECT disabled FROM operator_subject_controls"):
            return Result({"disabled": self.reviewer_disabled})
        if sql.startswith("SELECT * FROM native_mcp_execution_grants"):
            row = self.grants.get(params["id"])
            return Result(dict(row) if row is not None else None)
        if sql.startswith("INSERT INTO native_mcp_execution_grants"):
            row = dict(params)
            if self.grants or row["request_id"] != REQ:
                return Result(None)
            self.grants[row["grant_id"]] = row
            return Result(row["grant_id"])
        if sql.startswith("INSERT INTO native_mcp_execution_grant_events"):
            self.events.append(dict(params))
            return Result()
        if sql.startswith("UPDATE native_mcp_execution_grants"):
            row = self.grants.get(params["id"])
            if (
                self.fail_cas
                or row is None
                or row["revision"] != params.get("revision", params.get("prior"))
                or row["status"] != "issued"
            ):
                return Result(None)
            row["revision"] += 1
            row["status"] = params.get("status", "redeemed")
            return Result(row["revision"])
        raise AssertionError("Unexpected PostgreSQL query: " + sql[:180])


def harness(monkeypatch):
    signer = Ed25519PrivateKey.generate()
    encoded = base64.b64encode(
        signer.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode()
    monkeypatch.setenv(
        "OSOP_NATIVE_MCP_GRANT_SIGNING_KEYS_JSON", json.dumps({"kid-current": encoded})
    )
    monkeypatch.setenv("OSOP_NATIVE_MCP_GRANT_ACTIVE_KID", "kid-current")
    monkeypatch.setenv("OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON", json.dumps({"recon-mcp": SECRET}))
    registry = MCPRegistry()
    definition = MCPToolDefinition.model_validate(_NATIVE_BUILTIN)
    registry._servers["recon-mcp"] = SimpleNamespace(
        server_id="recon-mcp",
        _initialized=True,
        get_circuit_state=lambda: "closed",
        _tools={"authority_status": definition},
    )
    actions = FlowMCPActionStore(SessionMemory(), registry)
    db = FakeDB()
    db.dispatch = {
        "action_id": ACTION,
        "request_id": REQ,
        "engagement_id": "eng-durable",
        "flow_id": "flow-current",
        "task_id": "task-current",
        "subtask_id": "subtask-current",
        "owner_id": "owner-current",
        "flow_revision": 6,
        "authorization_version": 3,
        "authorization_id": "signed-3",
        "authorization_sha256": SHA,
        "approval_id": "apr-current",
        "lease_id": "lease-current",
        "lease_owner_id": "worker-current",
        "server_id": "recon-mcp",
        "tool_name": "authority_status",
        "side_effect_class": "READ_ONLY",
        "declaration_sha256": actions.declaration_sha256(definition, "recon-mcp"),
        "parameters_sha256": actions.parameters_sha256({}),
        "safe_parameters": {},
        "intent_sha256": "d" * 64,
        "status": "unknown",
        "cancel_requested": False,
    }
    facts = {"authority": True, "approval": True, "lease": True}

    async def authority(_db, b, owner, *, dispatch):
        assert dispatch is True
        if not facts["authority"] or b != binding() or owner != "owner-current":
            raise MCPActionDenied(409, "Current signed Flow revoked")
        return {"scope": {"engagement_id": "eng-durable", "domains": ["owned.example"]}}

    async def approved(_db, _b, _owner, task, step, server, tool, manifest, params, effect, scope):
        if not facts["approval"] or not facts["lease"]:
            raise MCPActionDenied(403, "Independent approval or lease unavailable")
        assert (task, step, server, tool, effect) == (
            "task-current",
            "subtask-current",
            "recon-mcp",
            "authority_status",
            "READ_ONLY",
        )
        return {
            "action_id": ACTION,
            "approval_id": "apr-current",
            "lease_id": "lease-current" if facts["lease"] else "lease-replaced",
            "lease_owner_id": "worker-current",
        }

    monkeypatch.setattr(actions, "_authority", authority)
    monkeypatch.setattr(actions, "_approved_task", approved)
    monkeypatch.setattr(actions, "_sessions", lambda: lambda: db)
    return NativeMCPExecutionGrantStore(actions), db, facts


@pytest.mark.asyncio
async def test_grant_issue_redeem_one_time_and_original_dispatch_link(monkeypatch):
    store, db, _ = harness(monkeypatch)
    issued = await store.issue(binding(), "owner-current", ACTION, REQ)
    token = issued["token"]
    claim = token["claims"]
    assert issued["status"] == "issued"
    assert set(token) == {"claims", "kid", "signature"}
    assert claim["tool_name"] == "authority_status"
    assert claim["side_effect_class"] == "READ_ONLY"
    assert claim["resource_sha256"] is None
    assert claim["manifest_sha256"] == db.dispatch["declaration_sha256"]
    assert claim["manifest_sha256"] == _native_manifest_sha256("recon-mcp")
    assert claim["manifest_sha256"] != _native_manifest_sha256("other-mcp")
    assert claim["parameters_sha256"] == db.dispatch["parameters_sha256"]
    assert claim["request_id"] == REQ
    signer_token, _, _, _ = _verify(token)
    assert signer_token == claim
    assert token["signature"] == base64.urlsafe_b64encode(
        base64.urlsafe_b64decode(token["signature"] + "==")
    ).decode().rstrip("=")
    with pytest.raises(NativeMCPGrantDenied):
        await store.issue(binding(), "owner-current", ACTION, REQ)
    redeemed = await store.redeem(token, server_id="recon-mcp", server_secret=SECRET)
    assert redeemed == {
        "grant_id": issued["grant_id"],
        "request_id": REQ,
        "claim_sha256": hashlib.sha256(_canonical(claim)).hexdigest(),
        "durably_redeemed": True,
    }
    assert [event["kind"] for event in db.events] == ["issued", "redeemed"]
    assert db.grants[issued["grant_id"]]["status"] == "redeemed"
    assert db.grants[issued["grant_id"]]["revision"] == 2
    assert base64.urlsafe_b64decode(issued["native_grant_header"] + "==") == _canonical(token)
    with pytest.raises(NativeMCPGrantDenied):
        await store.redeem(token, server_id="recon-mcp", server_secret=SECRET)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"status": "reserved"},
        {"status": "finished"},
        {"status": "cancelled"},
        {"cancel_requested": True},
        {"tool_name": "nuclei_scan"},
        {"side_effect_class": "RECON_ACTIVE"},
        {"request_id": "req-" + "f" * 48},
        {"parameters_sha256": "f" * 64},
    ],
)
async def test_issue_requires_exact_original_unknown_inert_dispatch(monkeypatch, change):
    store, db, _ = harness(monkeypatch)
    db.dispatch.update(change)
    with pytest.raises(NativeMCPGrantDenied):
        await store.issue(binding(), "owner-current", ACTION, REQ)
    assert not db.grants


@pytest.mark.asyncio
async def test_missing_dispatch_event_or_signed_approval_fails_closed(monkeypatch):
    store, db, facts = harness(monkeypatch)
    db.dispatched_event = False
    with pytest.raises(NativeMCPGrantDenied):
        await store.issue(binding(), "owner-current", ACTION, REQ)
    db.dispatched_event = True
    facts["approval"] = False
    with pytest.raises(MCPActionDenied):
        await store.issue(binding(), "owner-current", ACTION, REQ)
    facts["approval"] = True
    facts["authority"] = False
    with pytest.raises(MCPActionDenied):
        await store.issue(binding(), "owner-current", ACTION, REQ)
    assert not db.events


@pytest.mark.asyncio
async def test_lease_revocation_and_manifest_swap_before_redeem(monkeypatch):
    store, db, facts = harness(monkeypatch)
    token = (await store.issue(binding(), "owner-current", ACTION, REQ))["token"]
    facts["lease"] = False
    with pytest.raises(MCPActionDenied):
        await store.redeem(token, server_id="recon-mcp", server_secret=SECRET)
    facts["lease"] = True
    db.dispatch["declaration_sha256"] = "e" * 64
    with pytest.raises(MCPActionDenied):
        await store.redeem(token, server_id="recon-mcp", server_secret=SECRET)
    assert db.grants[token["claims"]["grant_id"]]["status"] == "issued"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    [
        lambda t: t["claims"].update(tool_name="scan"),
        lambda t: t["claims"].update(lease_id="lease-other"),
        lambda t: t["claims"].update(issued_at=True),
        lambda t: t["claims"].update(expires_at=t["claims"]["issued_at"] + 61),
        lambda t: t["claims"].update(parameters_sha256="f" * 64),
        lambda t: t.update(kid="kid-other"),
        lambda t: t.update(signature="A" * 86),
        lambda t: t["claims"].update(extra_permission=True),
    ],
)
async def test_signature_or_claim_tampering_fails_without_consuming(monkeypatch, tamper):
    store, db, _ = harness(monkeypatch)
    token = (await store.issue(binding(), "owner-current", ACTION, REQ))["token"]
    tamper(token)
    with pytest.raises(MCPActionDenied):
        await store.redeem(token, server_id="recon-mcp", server_secret=SECRET)
    assert next(iter(db.grants.values()))["status"] == "issued"


@pytest.mark.asyncio
async def test_server_credentials_and_tenant_isolation(monkeypatch):
    store, db, _ = harness(monkeypatch)
    token = (await store.issue(binding(), "owner-current", ACTION, REQ))["token"]
    with pytest.raises(NativeMCPGrantDenied):
        await store.redeem(token, server_id="recon-mcp", server_secret="bad")
    with pytest.raises(NativeMCPGrantDenied):
        await store.redeem(token, server_id="other-mcp", server_secret=SECRET)
    db.grants[token["claims"]["grant_id"]]["engagement_id"] = "eng-other"
    with pytest.raises(NativeMCPGrantDenied):
        await store.redeem(token, server_id="recon-mcp", server_secret=SECRET)
    assert not any(e["kind"] == "redeemed" for e in db.events)


@pytest.mark.asyncio
async def test_revocation_unknown_and_expiry_are_terminal(monkeypatch):
    store, db, _ = harness(monkeypatch)
    token = (await store.issue(binding(), "owner-current", ACTION, REQ))["token"]
    grant_id = token["claims"]["grant_id"]
    db.clock = token["claims"]["expires_at"]
    with pytest.raises(NativeMCPGrantDenied):
        await store.redeem(token, server_id="recon-mcp", server_secret=SECRET)
    assert (await store.mark_unknown(binding(), "owner-current", grant_id))["status"] == "unknown"
    with pytest.raises(NativeMCPGrantDenied):
        await store.redeem(token, server_id="recon-mcp", server_secret=SECRET)
    assert (await store.revoke(binding(), "owner-current", grant_id))["changed"] is False
    assert [e["kind"] for e in db.events] == ["issued", "unknown"]


@pytest.mark.asyncio
async def test_cas_failure_and_concurrent_redemption(monkeypatch):
    store, db, _ = harness(monkeypatch)
    token = (await store.issue(binding(), "owner-current", ACTION, REQ))["token"]
    db.fail_cas = True
    with pytest.raises(NativeMCPGrantDenied):
        await store.redeem(token, server_id="recon-mcp", server_secret=SECRET)
    db.fail_cas = False

    async def redeem():
        try:
            return await store.redeem(token, server_id="recon-mcp", server_secret=SECRET)
        except MCPActionDenied:
            return None

    outcomes = await asyncio.gather(redeem(), redeem())
    assert len([result for result in outcomes if result is not None]) == 1
    assert [event["kind"] for event in db.events] == ["issued", "redeemed"]


@pytest.mark.asyncio
async def test_reviewed_resource_digest_must_be_task_pinned_and_current(monkeypatch):
    store, db, _ = harness(monkeypatch)
    blob = b"Verified immutable test data"
    resource = {
        "id": "artifact-" + "3" * 32,
        "flow_id": "flow-current",
        "name": "notes.txt",
        "size_bytes": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "flow_revision": 6,
        "authorization_version": 3,
        "authorization_sha256": SHA,
        "content": blob,
    }
    db.artifacts = [resource]
    manifest = make_manifest("flow-current", 6, 3, [(resource, blob)])
    digest = manifest["manifest_sha256"]
    db.review = {
        "uploader_sub": "owner-current",
        "reviewer_sub": "human-reviewer",
        "reviewer_role": "senior_operator",
        "decision": "approve",
        "artifact_sha256": resource["sha256"],
        "flow_revision": 6,
        "authorization_id": "signed-3",
        "authorization_version": 3,
        "authorization_sha256": SHA,
    }
    with pytest.raises(NativeMCPGrantDenied):
        await store.issue(binding(), "owner-current", ACTION, REQ, resource_sha256=digest)
    db.pinned_resource = digest
    db.review["decision"] = "reject"
    with pytest.raises(NativeMCPGrantDenied):
        await store.issue(binding(), "owner-current", ACTION, REQ, resource_sha256=digest)
    db.review["decision"] = "approve"
    issued = await store.issue(binding(), "owner-current", ACTION, REQ, resource_sha256=digest)
    assert issued["token"]["claims"]["resource_sha256"] == digest
    db.artifacts[0]["content"] = b"Tampered immutable test data"
    with pytest.raises(MCPActionDenied):
        await store.redeem(issued["token"], server_id="recon-mcp", server_secret=SECRET)
    assert db.grants[issued["grant_id"]]["status"] == "issued"


def test_canonical_go_interoperability_and_negative_security_cases(monkeypatch):
    store, _, _ = harness(monkeypatch)
    assert _canonical({"z": 1, "a": "é"}) == b'{"a":"\\u00e9","z":1}'
    assert DOMAIN == b"ai-osop/native-grant/v1\x00"
    with pytest.raises(NativeMCPGrantDenied):
        _canonical({"bad": float("nan")})
    monkeypatch.delenv("OSOP_NATIVE_MCP_GRANT_ACTIVE_KID")
    with pytest.raises(NativeMCPGrantDenied):
        _verify({"claims": {}, "kid": "untrusted", "signature": "A" * 86})


def test_0029_ddl_stays_separate_append_only_and_revises_0028(monkeypatch):
    """Static migration contract; intentionally never opens application PG."""
    migration = (
        Path(__file__).parents[1]
        / "migrations"
        / "versions"
        / "0029_native_mcp_execution_grants.py"
    )
    spec = importlib.util.spec_from_file_location("native_mcp_0029_test", migration)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == "0029"
    assert module.down_revision == "0028"
    operations = []

    class Recorder:
        def create_table(self, name, *items):
            operations.append(("table", name, items))

        def create_index(self, name, *args):
            operations.append(("index", name, args))

        def execute(self, statement):
            operations.append(("sql", str(statement)))

    monkeypatch.setattr(module, "op", Recorder())
    module.upgrade()
    tables = {operation[1]: operation[2] for operation in operations if operation[0] == "table"}
    assert set(tables) == {"native_mcp_execution_grants", "native_mcp_execution_grant_events"}
    from sqlalchemy import CheckConstraint, Column, UniqueConstraint

    grants = tables["native_mcp_execution_grants"]
    events = tables["native_mcp_execution_grant_events"]
    cols = {item.name: item for item in grants if isinstance(item, Column)}
    assert cols["action_id"].unique is True
    assert cols["request_id"].unique is True
    assert cols["status"].nullable is False
    assert "resource_sha256" in cols
    checks = " ".join(str(item.sqltext) for item in grants if isinstance(item, CheckConstraint))
    assert "authority_status" in checks and "READ_ONLY" in checks
    assert "expires_at-issued_at<=60" in checks
    assert any(
        isinstance(item, UniqueConstraint) and len(item._pending_colargs) == 2 for item in events
    )
    assert any(
        kind == "sql"
        and "BEFORE UPDATE OR DELETE" in statement
        and "native_mcp_execution_grant_events" in statement
        for kind, statement, *rest in operations
    )
