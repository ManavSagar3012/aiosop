"""SourceMap central signer + FastAPI and simulated-SQL one-shot qualification.

No real PostgreSQL, migration, original bytes returned over HTTP, scanners,
network fetches, containers or external target. Fake transactional behavior
is NOT a certificate of PostgreSQL row locks, durable uniqueness or 0035 DDL.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
import time
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI

from ai_osop.api.routers import native_sourcemap_source_authority as api
from ai_osop.mcp.protocol import MCPToolDefinition, MCPToolParameter, SideEffectClass
from ai_osop.memory import sourcemap_source_authority as issuer
from ai_osop.memory.flow_mcp_action_dispatch import (
    FlowMCPActionStore,
    _DIGEST_DOMAIN,
    _digest,
)
from ai_osop.memory.flow_resource_exports import make_manifest


TOKEN = "independent-sourcemap-central-service-token"
KID = "sourcemap-central-issuer"
ARTIFACT_ID = "artifact-" + "a" * 32
ACTION_ID = "action-" + "b" * 32
MAP = b'{"version":3,"sources":["src.js"],"sourcesContent":["const x=1;"]}'
SHA = hashlib.sha256(MAP).hexdigest()


def fixture_original() -> tuple[dict, dict, dict]:
    params = {"artifact_sha256": SHA}
    row = {
        "engagement_id": "eng-sourcemap-fixture",
        "flow_id": "flow-source-fixture",
        "task_id": "task-source-fixture",
        "subtask_id": "subtask-source-fixture",
        "action_id": ACTION_ID,
        "owner_id": "owner-source",
        "flow_revision": 7,
        "authorization_id": "auth-current",
        "authorization_version": 4,
        "authorization_sha256": "c" * 64,
        "approval_id": "approval-independent",
        "lease_id": "lease-active-source",
        "lease_owner_id": "agent-worker",
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        "side_effect_class": "READ_ONLY",
        "declaration_sha256": "d" * 64,
        "parameters_sha256": FlowMCPActionStore.parameters_sha256(params),
        "safe_parameters": params,
        "status": "unknown",
        "cancel_requested": False,
        "receipt_sha256": None,
    }
    binding = {
        "engagement_id": row["engagement_id"],
        "flow_id": row["flow_id"],
        "revision": row["flow_revision"],
        "version": row["authorization_version"],
        "authorization_id": row["authorization_id"],
        "authorization_sha256": row["authorization_sha256"],
    }
    intent = {
        **binding,
        **{
            name: row[name]
            for name in (
                "task_id",
                "subtask_id",
                "action_id",
                "owner_id",
                "approval_id",
                "lease_id",
                "lease_owner_id",
                "server_id",
                "tool_name",
                "side_effect_class",
                "declaration_sha256",
                "parameters_sha256",
            )
        },
    }
    row["intent_sha256"] = _digest(_DIGEST_DOMAIN, intent, 4096)
    row["request_id"] = "req-" + row["intent_sha256"][:48]
    artifact = {
        "id": ARTIFACT_ID,
        "flow_id": row["flow_id"],
        "engagement_id": row["engagement_id"],
        "owner_id": row["owner_id"],
        "name": "original-sourcemap.json",
        "size_bytes": len(MAP),
        "sha256": SHA,
        "flow_revision": row["flow_revision"],
        "authorization_version": row["authorization_version"],
        "authorization_sha256": row["authorization_sha256"],
        "content": MAP,
    }
    review = {
        "id": "review-independent",
        "artifact_id": ARTIFACT_ID,
        "flow_id": row["flow_id"],
        "engagement_id": row["engagement_id"],
        "uploader_sub": row["owner_id"],
        "reviewer_sub": "senior-distinct",
        "reviewer_role": "senior_operator",
        "decision": "approve",
        "artifact_sha256": SHA,
        "flow_revision": row["flow_revision"],
        "authorization_id": row["authorization_id"],
        "authorization_version": row["authorization_version"],
        "authorization_sha256": row["authorization_sha256"],
    }
    return row, artifact, review


def request_for(row: dict) -> dict[str, str]:
    return {
        "request_id": row["request_id"],
        "engagement_id": row["engagement_id"],
        "task_id": row["task_id"],
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        "artifact_sha256": SHA,
    }


@dataclass
class SQLResult:
    row: object = None
    scalar: object = None
    rows: object = None

    def mappings(self):
        return self

    def one_or_none(self):
        return self.row

    def all(self):
        return self.rows

    def scalar_one_or_none(self):
        return self.scalar

    def scalar_one(self):
        return self.scalar


class FakeLedger:
    def __init__(self):
        self.row, self.artifact, self.review = fixture_original()
        self.lock = asyncio.Lock()
        self.committed: dict[str, dict] = {}
        self.dispatch_event = True
        self.senior_disabled: object = False
        self.roe = {"allow_read_only": True}
        self.task_payload = {
            "resource_artifact_id": ARTIFACT_ID,
            "resource_artifact_sha256": SHA,
            "resource_authorization_sha256": self.row["authorization_sha256"],
            "resource_command_sha256": self.row["parameters_sha256"],
            "resource_manifest_sha256": make_manifest(
                self.row["flow_id"],
                self.row["flow_revision"],
                self.row["authorization_version"],
                [({k: v for k, v in self.artifact.items() if k != "content"}, MAP)],
            )["manifest_sha256"],
        }
        self.table_exists = True
        self.commit_uncertain = False
        self.now = int(time.time())


class FakePG:
    def __init__(self, ledger: FakeLedger):
        self.ledger = ledger
        self.pending = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    def begin(self):
        pg = self

        class Transaction:
            async def __aenter__(self):
                await pg.ledger.lock.acquire()
                return pg

            async def __aexit__(self, typ, exc, tb):
                try:
                    if typ is None and pg.pending is not None:
                        if pg.ledger.commit_uncertain:
                            raise RuntimeError("Ambiguous commit ACK")
                        pg.ledger.committed[pg.pending["request_id"]] = pg.pending
                finally:
                    pg.ledger.lock.release()

        return Transaction()

    async def execute(self, statement, parameters=None):
        query = str(statement)
        parameters = parameters or {}
        ledger = self.ledger
        if "FROM flow_mcp_action_dispatches WHERE request_id" in query:
            return SQLResult(
                row=(
                    copy.deepcopy(ledger.row)
                    if parameters["request"] == ledger.row["request_id"]
                    else None
                )
            )
        if "FROM flow_mcp_action_dispatch_events" in query:
            return SQLResult(scalar=1 if ledger.dispatch_event else None)
        if "SELECT roe FROM session_states" in query:
            return SQLResult(row={"roe": copy.deepcopy(ledger.roe)})
        if "SELECT payload FROM tasks" in query:
            return SQLResult(row={"payload": copy.deepcopy(ledger.task_payload)})
        if "FROM flow_artifacts WHERE" in query:
            meta = {
                key: copy.deepcopy(value)
                for key, value in ledger.artifact.items()
                if key != "content"
            }
            blob = ledger.artifact["content"]
            meta["original_bytes_len"] = len(blob)
            meta["original_bytes_sha256"] = hashlib.sha256(blob).hexdigest()
            assert "SELECT id,flow_id" in query
            assert "sha256(content)" in query
            assert "octet_length(content)" in query
            assert ",content " not in query  # Never read raw BYTEA to FastAPI.
            return SQLResult(rows=[meta])
        if "FROM flow_artifact_reviews WHERE" in query:
            return SQLResult(row=copy.deepcopy(ledger.review))
        if "FROM operator_subject_controls" in query:
            return SQLResult(scalar=ledger.senior_disabled)
        if "EXTRACT(EPOCH FROM clock_timestamp())" in query:
            return SQLResult(scalar=ledger.now)
        if "INSERT INTO native_sourcemap_source_preflights" in query:
            if not ledger.table_exists:
                raise RuntimeError("0035 table is intentionally absent")
            if parameters["request_id"] in ledger.committed or any(
                row["action_id"] == parameters["action_id"] for row in ledger.committed.values()
            ):
                return SQLResult()
            self.pending = dict(parameters)
            return SQLResult(scalar=parameters["preflight_id"])
        raise AssertionError("Unexpected fake SQL: " + query[:125])


def fake_issuer(ledger: FakeLedger, monkeypatch: pytest.MonkeyPatch):
    actions = object.__new__(FlowMCPActionStore)
    actions._sessions = lambda: lambda: FakePG(ledger)
    actions._authority = AsyncMock(
        return_value={
            "scope": {"engagement_id": ledger.row["engagement_id"], "domains": []},
        }
    )
    actions._row = AsyncMock(side_effect=lambda db, action, lock=False: copy.deepcopy(ledger.row))
    actions._same = lambda *args: None
    actions._approved_task = AsyncMock(
        return_value={
            key: ledger.row[key]
            for key in ("action_id", "approval_id", "lease_id", "lease_owner_id")
        }
    )
    definition = MCPToolDefinition(
        name="inspect_local_original_sourcemap",
        description="Original reviewed immutable SourceMap metadata",
        side_effect_class=SideEffectClass.READ_ONLY,
        requires_approval=True,
        scope_check=True,
        parameters=[
            MCPToolParameter(
                name="artifact_sha256",
                type="string",
                description="Exact original byte SHA256",
                required=True,
            )
        ],
        returns={"type": "object", "description": "Opaque source metadata"},
    )
    actions._declaration = lambda *args: definition
    actions.declaration_sha256 = lambda *args: ledger.row["declaration_sha256"]
    # The issuer now calls the ORIGINAL production 0027 SHA-only admission,
    # not a replaced test stub. SQL and Task fixtures remain explicitly simulated.
    return issuer.SourceMapSourceAuthorityStore(actions), actions


@pytest.fixture
def key(monkeypatch):
    signer = Ed25519PrivateKey.generate()
    secret = signer.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_SOURCE_SIGNING_KID", KID)
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_SIGNING_PRIVATE_KEY_B64", base64.b64encode(secret).decode()
    )
    return signer


def _verify_receipt(token: dict, signer: Ed25519PrivateKey, row: dict) -> None:
    assert set(token) == {"claims", "kid", "signature"}
    assert token["kid"] == KID
    claims = token["claims"]
    assert set(claims) == issuer.CLAIM_FIELDS
    assert claims["artifact_sha256"] == SHA
    assert claims["request_id"] == row["request_id"]
    assert claims["preflight_id"].startswith("nsp-")
    assert claims["expires_at"] - claims["issued_at"] == 10
    signer.public_key().verify(
        base64.urlsafe_b64decode(token["signature"] + "=="),
        issuer.DOMAIN + issuer.canonical(claims),
    )


@pytest.mark.asyncio
async def test_signed_original_source_one_use_and_same_manifest_sha(key, monkeypatch):
    ledger = FakeLedger()
    store, actions = fake_issuer(ledger, monkeypatch)
    result = await store.admit(request_for(ledger.row))
    _verify_receipt(result, key, ledger.row)
    manifest = make_manifest(
        ledger.row["flow_id"],
        7,
        4,
        [({k: v for k, v in ledger.artifact.items() if k != "content"}, MAP)],
    )
    assert result["claims"]["manifest_sha256"] == manifest["manifest_sha256"]
    import importlib.util
    from pathlib import Path

    native_path = Path(__file__).resolve().parents[1] / "mcp-servers/python/source_map_mcp.py"
    native_spec = importlib.util.spec_from_file_location(
        "native_sourcemap_verifier_test", native_path
    )
    assert native_spec is not None and native_spec.loader is not None
    native = importlib.util.module_from_spec(native_spec)
    native_spec.loader.exec_module(native)
    assert (
        native._source_proof(
            result,
            request_for(ledger.row),
            {
                KID: key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                ),
            },
        )
        == result["claims"]
    )
    assert len(ledger.committed) == 1
    assert actions._approved_task.await_count == 1
    with pytest.raises(issuer.SourceMapSourceDenied) as replay:
        await store.admit(request_for(ledger.row))
    assert replay.value.status == 409
    assert len(ledger.committed) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "wrong-tenant",
        "wrong-task",
        "wrong-hash",
        "cancelled",
        "settled",
        "no-event",
        "revoked-reviewer",
        "self-review",
        "review-rejected",
        "expired-lease",
        "revoked-roe",
        "stale-artifact",
        "wrong-owner",
        "stale-review",
        "wrong-task-resource-sha",
        "wrong-task-resource-id",
        "changed-intent",
        "inactive-flow",
        "wrong-approval",
        "wrong-manifest-lineage",
        "wrong-manifest-pin",
        "no-manifest-pin",
        "missing-reviewer-control",
        "wrong-original-byte-length",
    ],
)
async def test_source_denies_adversarial_original_authority(key, monkeypatch, failure):
    ledger = FakeLedger()
    store, actions = fake_issuer(ledger, monkeypatch)
    request = request_for(ledger.row)
    if failure == "wrong-tenant":
        request["engagement_id"] = "eng-foreign"
    if failure == "wrong-task":
        request["task_id"] = "task-other"
    if failure == "wrong-hash":
        request["artifact_sha256"] = "f" * 64
    if failure == "cancelled":
        ledger.row["cancel_requested"] = True
    if failure == "settled":
        ledger.row["status"] = "finished"
    if failure == "no-event":
        ledger.dispatch_event = False
    if failure == "revoked-reviewer":
        ledger.senior_disabled = True
    if failure == "self-review":
        ledger.review["reviewer_sub"] = ledger.row["owner_id"]
    if failure == "review-rejected":
        ledger.review["decision"] = "reject"
    if failure == "expired-lease":
        actions._approved_task.side_effect = RuntimeError("Current signed lease expired")
    if failure == "revoked-roe":
        ledger.roe["allow_read_only"] = False
    if failure == "stale-artifact":
        ledger.artifact["content"] = MAP + b"altered"
    if failure == "wrong-owner":
        ledger.artifact["owner_id"] = "owner-foreign"
    if failure == "stale-review":
        ledger.review["authorization_sha256"] = "0" * 64
    if failure == "wrong-task-resource-sha":
        ledger.task_payload["resource_artifact_sha256"] = "1" * 64
    if failure == "wrong-task-resource-id":
        ledger.task_payload["resource_artifact_id"] = "artifact-" + "f" * 32
    if failure == "changed-intent":
        ledger.row["intent_sha256"] = "2" * 64
    if failure == "inactive-flow":
        actions._authority.side_effect = RuntimeError("Flow revoked")
    if failure == "wrong-approval":
        actions._approved_task.return_value["approval_id"] = "approval-revoked"
    if failure == "wrong-manifest-lineage":
        ledger.artifact["flow_revision"] = 3
    if failure == "wrong-manifest-pin":
        ledger.task_payload["resource_manifest_sha256"] = "9" * 64
    if failure == "no-manifest-pin":
        del ledger.task_payload["resource_manifest_sha256"]
    if failure == "missing-reviewer-control":
        ledger.senior_disabled = None
    if failure == "wrong-original-byte-length":
        ledger.artifact["size_bytes"] -= 1
    with pytest.raises(issuer.SourceMapSourceDenied):
        await store.admit(request)
    assert ledger.committed == {}


@pytest.mark.asyncio
async def test_missing_migration_and_ambiguous_commit_ack_fail_without_receipt(key, monkeypatch):
    for absent, uncertain in ((True, False), (False, True)):
        ledger = FakeLedger()
        ledger.table_exists = not absent
        ledger.commit_uncertain = uncertain
        store, _ = fake_issuer(ledger, monkeypatch)
        with pytest.raises(issuer.SourceMapSourceDenied) as denied:
            await store.admit(request_for(ledger.row))
        assert denied.value.status == 503
        assert ledger.committed == {}


@pytest.mark.asyncio
async def test_fake_sql_concurrent_redeemers_exactly_one_receipt(key, monkeypatch):
    ledger = FakeLedger()
    store, _ = fake_issuer(ledger, monkeypatch)
    results = await asyncio.gather(
        store.admit(request_for(ledger.row)),
        store.admit(request_for(ledger.row)),
        return_exceptions=True,
    )
    assert sum(isinstance(item, dict) for item in results) == 1
    assert sum(isinstance(item, issuer.SourceMapSourceDenied) for item in results) == 1
    assert len(ledger.committed) == 1


@pytest.mark.asyncio
async def test_fastapi_dedicated_bearer_parse_and_no_source_body(key, monkeypatch):
    monkeypatch.setenv("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", TOKEN)
    monkeypatch.setenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", "native-separate-credential-do-not-reuse")
    ledger = FakeLedger()
    store, _ = fake_issuer(ledger, monkeypatch)
    monkeypatch.setattr(
        api,
        "state",
        {
            "orchestrator": SimpleNamespace(
                session_memory=object(),
                mcp_registry=object(),
            )
        },
    )
    monkeypatch.setattr(api, "FlowMCPActionStore", lambda *args: store.actions)
    app = FastAPI()
    app.include_router(api.router)
    url = "/native-sourcemap/source-preflight"
    request = request_for(ledger.row)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://issuer.test"
    ) as client:
        missing = await client.post(url, json=request)
        assert missing.status_code == 401
        native = await client.post(
            url,
            json=request,
            headers={
                "Authorization": "Bearer native-separate-credential-do-not-reuse",
            },
        )
        assert native.status_code == 403
        duplicate = await client.post(
            url,
            content=(b'{"request_id":"x","request_id":"y"}'),
            headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"},
        )
        assert duplicate.status_code == 422
        valid = await client.post(url, json=request, headers={"Authorization": "Bearer " + TOKEN})
        assert valid.status_code == 200
        _verify_receipt(valid.json(), key, ledger.row)
        assert valid.headers["cache-control"] == "no-store"
        assert MAP not in valid.content
        assert b"sourcesContent" not in valid.content
        replay = await client.post(url, json=request, headers={"Authorization": "Bearer " + TOKEN})
        assert replay.status_code == 409


def test_strict_native_source_map_wire_contract_and_signer_fail_closed(monkeypatch):
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "mcp-servers/python/source_map_mcp.py"
    spec = importlib.util.spec_from_file_location("source_map_wire_20261020", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module._SOURCE_DOMAIN == issuer.DOMAIN
    assert module._SOURCE_REQUEST == issuer.REQUEST_FIELDS
    assert module._SOURCE_CLAIMS == issuer.CLAIM_FIELDS
    for value in (
        None,
        {},
        {"request_id": "req-" + "a" * 48},
        {**request_for(fixture_original()[0]), "credential": "x"},
    ):
        with pytest.raises(issuer.SourceMapSourceDenied):
            issuer.validate_request(value)
    monkeypatch.delenv("OSOP_SOURCEMAP_SOURCE_SIGNING_PRIVATE_KEY_B64", raising=False)
    with pytest.raises(issuer.SourceMapSourceDenied) as denied:
        issuer.signer()
    assert denied.value.status == 503
