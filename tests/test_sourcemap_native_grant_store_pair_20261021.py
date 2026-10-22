"""Fail-closed grant-store qualification after schema-only SourceMap 0036.

No application DB, native process, target or provider is invoked. The signed
0027/0035 SourceMap intent has a different *Task authority* and staging source
than the Go 0029/0030 resource offer, so this store must NOT mint/redeem it.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from ai_osop.memory import native_mcp_execution_grants as native
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.flow_resource_exports import make_manifest
from ai_osop.memory.sourcemap_source_authority import SourceMapSourceAuthorityStore


GO = (
    "recon-mcp",
    "payload-mcp",
    "nuclei-mcp",
    "shodan-mcp",
    "threat-intel-mcp",
    "security-bridge",
)
SOURCE = "source-map-mcp"
INSPECT = "inspect_local_original_sourcemap"
ACTION = "action-" + "a" * 32
REQUEST = "req-" + "b" * 48


def _original(server: str, tool: str, effect: str = "READ_ONLY") -> dict[str, Any]:
    return {
        "action_id": ACTION,
        "request_id": REQUEST,
        "engagement_id": "eng-pair",
        "flow_id": "flow-pair",
        "task_id": "task-pair",
        "subtask_id": "subtask-pair",
        "owner_id": "owner-pair",
        "server_id": server,
        "tool_name": tool,
        "side_effect_class": effect,
        "status": "unknown",
        "cancel_requested": False,
        "intent_sha256": "c" * 64,
    }


def _binding() -> dict[str, Any]:
    return {
        "engagement_id": "eng-pair",
        "flow_id": "flow-pair",
        "revision": 1,
        "version": 1,
        "authorization_id": "auth-pair",
        "authorization_sha256": "d" * 64,
    }


class _NoDatabaseWrites:
    def __init__(self) -> None:
        self.reads = 0
        self.writes = 0
        self.entered = 0

    async def __aenter__(self) -> "_NoDatabaseWrites":
        self.entered += 1
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    @asynccontextmanager
    async def begin(self) -> Any:
        yield self

    async def execute(self, statement: Any, params: Any = None) -> Any:
        sql = str(statement)
        if sql.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE")):
            self.writes += 1
        else:
            self.reads += 1
        raise AssertionError("Unexpected SQL for a denied SourceMap grant: " + sql[:100])


def _signer(monkeypatch: pytest.MonkeyPatch) -> None:
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    monkeypatch.setenv("OSOP_NATIVE_MCP_GRANT_ACTIVE_KID", "kid-pair")
    monkeypatch.setenv(
        "OSOP_NATIVE_MCP_GRANT_SIGNING_KEYS_JSON",
        json.dumps({"kid-pair": base64.b64encode(raw).decode("ascii")}),
    )


@pytest.mark.parametrize("server", GO)
def test_unchanged_six_go_pairs_are_operationally_admitted(server: str) -> None:
    assert native._require_operational_pair(server, "authority_status", "READ_ONLY") is None
    assert server in native._ADMITTED_INERT_SERVERS


@pytest.mark.parametrize(
    ("server", "tool", "effect"),
    [
        (SOURCE, INSPECT, "READ_ONLY"),
        (SOURCE, "authority_status", "READ_ONLY"),
        ("recon-mcp", INSPECT, "READ_ONLY"),
        ("browser-mcp", "authority_status", "READ_ONLY"),
        ("other-mcp", "authority_status", "READ_ONLY"),
        ("recon-mcp", "authority_status", "RECON_ACTIVE"),
        (SOURCE, INSPECT, "INVASIVE_EXPLOIT"),
        ("recon-mcp", "execute", "READ_ONLY"),
        (None, "authority_status", "READ_ONLY"),
        ([], "authority_status", "READ_ONLY"),
    ],
)
def test_0036_pairing_is_not_equivalent_to_operational_grant(
    server: Any, tool: str, effect: str
) -> None:
    with pytest.raises(native.NativeMCPGrantDenied):
        native._require_operational_pair(server, tool, effect)


@pytest.mark.parametrize("server", [SOURCE, "other-mcp"])
def test_historical_inert_claim_shape_can_never_verify_unsupported_server(
    monkeypatch: pytest.MonkeyPatch, server: str
) -> None:
    # Backwards-compatible syntax is not admission. No issuer key, provider
    # or DB lookup should occur for a signed token from a disallowed pair.
    claims = {
        "version": 1,
        "grant_id": "ngr-" + "a" * 32,
        "request_id": REQUEST,
        "engagement_id": "eng-pair",
        "flow_id": "flow-pair",
        "task_id": "task-pair",
        "subtask_id": "subtask-pair",
        "action_id": ACTION,
        "server_id": server,
        "tool_name": "authority_status",
        "parameters_sha256": hashlib.sha256(b"{}").hexdigest(),
        "manifest_sha256": native._native_manifest_sha256(server),
        "authorization_version": 1,
        "authorization_sha256": "f" * 64,
        "lease_id": "lease-pair",
        "resource_sha256": None,
        "issued_at": 1234567890,
        "expires_at": 1234567900,
        "side_effect_class": "READ_ONLY",
    }
    assert native._validate_claims(claims) is claims
    monkeypatch.setattr(
        native, "_signers", lambda: (_ for _ in ()).throw(AssertionError("Signer contacted"))
    )
    with pytest.raises(
        native.NativeMCPGrantDenied,
        match="not operationally admitted|independent original resource offering",
    ):
        native._verify({"claims": claims, "kid": "kid-pair", "signature": "unused"})


@pytest.mark.asyncio
async def test_original_sourcemap_unknown_action_never_reaches_grant_dispatch_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _original(SOURCE, INSPECT)
    observed: list[bool] = []

    async def original_row(_: Any, action_id: str, *, lock: bool) -> dict[str, Any]:
        observed.append(lock)
        assert action_id == ACTION
        return row

    monkeypatch.setattr(FlowMCPActionStore, "_row", original_row)
    db = _NoDatabaseWrites()
    with pytest.raises(native.NativeMCPGrantDenied, match="independent original resource offering"):
        await native.NativeMCPExecutionGrantStore._original(db, ACTION)
    assert observed == [True]
    assert db.reads == 0 and db.writes == 0
    assert row["status"] == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize("digest", [None, "e" * 64])
async def test_sourcemap_resource_helper_must_not_skip_missing_generic_pin(
    digest: str | None,
) -> None:
    db = _NoDatabaseWrites()
    row = _original(SOURCE, INSPECT)
    with pytest.raises(native.NativeMCPGrantDenied, match="independent original resource offering"):
        await native.NativeMCPExecutionGrantStore._resources(db, row, digest)
    assert db.reads == 0 and db.writes == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("server", "tool"),
    [(SOURCE, "authority_status"), ("other-mcp", "authority_status")],
)
async def test_signed_other_original_pair_not_considered_live_after_0036(
    monkeypatch: pytest.MonkeyPatch, server: str, tool: str
) -> None:
    async def original_row(_: Any, action_id: str, *, lock: bool) -> dict[str, Any]:
        assert lock and action_id == ACTION
        return _original(server, tool)

    monkeypatch.setattr(FlowMCPActionStore, "_row", original_row)
    db = _NoDatabaseWrites()
    with pytest.raises(
        native.NativeMCPGrantDenied,
        match="not operationally admitted|independent original resource offering",
    ):
        await native.NativeMCPExecutionGrantStore._original(db, ACTION)
    assert db.writes == 0 and db.reads == 0


@pytest.mark.asyncio
async def test_even_valid_0027_sourcemap_action_cannot_mint_a_0029_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _signer(monkeypatch)
    db = _NoDatabaseWrites()
    actions = object.__new__(FlowMCPActionStore)

    async def _authority(_: Any, binding: Any, owner: Any, *, dispatch: bool) -> dict[str, Any]:
        assert binding == _binding()
        assert owner == "owner-pair" and dispatch is True
        return {"scope": {}}

    async def _row(_: Any, action_id: str, *, lock: bool) -> dict[str, Any]:
        assert action_id == ACTION and lock
        return _original(SOURCE, INSPECT)

    monkeypatch.setattr(actions, "_authority", _authority)
    monkeypatch.setattr(actions, "_sessions", lambda: lambda: db)
    monkeypatch.setattr(FlowMCPActionStore, "_row", _row)
    store = native.NativeMCPExecutionGrantStore(actions)
    with pytest.raises(native.NativeMCPGrantDenied, match="independent original resource offering"):
        await store.issue(_binding(), "owner-pair", ACTION, REQUEST, resource_sha256="f" * 64)
    assert db.entered == 1 and db.reads == 0 and db.writes == 0


def test_source_map_task_approval_and_native_offer_pin_differ() -> None:
    # A digest can agree for compliant text artifacts. That is NOT proof that
    # the original approved Task allowed native staging: the two owners/pins
    # and one-use service protocols are independent.
    data = b"console.log('reviewed benign fixture');\n"
    sha = hashlib.sha256(data).hexdigest()
    artifact = {
        "id": "artifact-" + "c" * 32,
        "name": "source.js",
        "size_bytes": len(data),
        "sha256": sha,
        "flow_id": "flow-pair",
        "flow_revision": 1,
        "authorization_version": 1,
    }
    manifest = make_manifest("flow-pair", 1, 1, [(artifact, data)])
    metadata_digest = SourceMapSourceAuthorityStore._metadata_manifest(
        "flow-pair", 1, 1, [artifact]
    )
    assert metadata_digest == manifest["manifest_sha256"]
    resource_authority = inspect.getsource(native.NativeMCPExecutionGrantStore._resources)
    source_authority = inspect.getsource(SourceMapSourceAuthorityStore._source)
    assert 'get("mcp_resource_sha256")' in resource_authority
    for required in (
        'payload.get("resource_artifact_id")',
        'payload.get("resource_manifest_sha256")',
        'payload.get("resource_authorization_sha256")',
        'payload.get("resource_command_sha256")',
        "self._original_manifest(",
    ):
        assert required in source_authority
    assert "SELECT disabled FROM operator_subject_controls" in inspect.getsource(
        SourceMapSourceAuthorityStore._original_manifest
    )
    assert "encode(sha256(content)," in inspect.getsource(
        SourceMapSourceAuthorityStore._original_manifest
    )
    assert "kind='dispatch_attempted' AND status='unknown'" in source_authority


def test_original_sourcemap_stage_is_not_0031_native_offer_permission() -> None:
    from ai_osop.memory import native_mcp_resource_delivery as delivery
    from ai_osop.orchestrator import sourcemap_original_readonly_provisioner as source_host

    assert "approved_folder_stage_plan(db, original, manifest)" in inspect.getsource(
        delivery.NativeMCPResourceDelivery.offer
    )
    host_source = inspect.getsource(source_host)
    assert "0031 native folder offer hashes are *not* SourceMap byte authority" in host_source
    assert "cannot issue a SourceMap 0035 preflight" in host_source
    assert "No INSERT, UPDATE, DELETE" in host_source
    migration = (
        Path(__file__).resolve().parents[1]
        / "migrations/versions/0036_sourcemap_native_grant_pair.py"
    )
    assert migration.read_text(encoding="utf-8").count("op.create_check_constraint(") == 2
