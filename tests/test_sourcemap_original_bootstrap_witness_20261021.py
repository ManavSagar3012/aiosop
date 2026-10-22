"""Synthetic fake-PostgreSQL qualification for first-use SourceMap precheck.

The fake SourceMapSourceAuthorityStore._source checks a synthetic original
Action record; it is NOT genuine PostgreSQL or current signed authority.
Production code invokes the actual _source, whose SQL checks immutable 0027,
Flow/Task/lease/reviewer/ROE, independently approved 0013 and 0015/0026.
This suite never issues 0035, contacts targets, or mutates application DB.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import importlib.util
import json
import os
import sys
import time
import types
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "src" / "ai_osop" / "memory" / "sourcemap_original_bootstrap_witness.py"
AUTHORITATIVE = ROOT / "src" / "ai_osop" / "memory" / "sourcemap_source_authority.py"
SHA = "a" * 64
REQ = {
    "request_id": "req-" + "f" * 48,
    "engagement_id": "eng-original",
    "task_id": "task-original",
    "server_id": "source-map-mcp",
    "tool_name": "inspect_local_original_sourcemap",
    "artifact_sha256": SHA,
}
RAW = {
    **{key: value for key, value in REQ.items() if key != "artifact_sha256"},
    "flow_id": "flow-original",
    "subtask_id": "subtask-original",
    "action_id": "action-" + "b" * 32,
    "owner_id": "owner-approved",
    "approval_id": "approval-distinct-senior",
    "lease_id": "lease-current",
    "lease_owner_id": "leaseowner-current",
    "flow_revision": 2,
    "authorization_id": "authorization-reviewed",
    "authorization_version": 3,
    "authorization_sha256": "c" * 64,
    "intent_sha256": "d" * 64,
    "declaration_sha256": "e" * 64,
    "parameters_sha256": "0" * 64,
    "status": "unknown",
    "cancel_requested": False,
    "receipt_sha256": None,
}
MANIFEST = "1" * 64


class SyntheticAuthorizationDenied(ValueError):
    pass


class FakeTxn:
    def __init__(self, db: "FakeDB") -> None:
        self.db = db

    async def __aenter__(self) -> "FakeTxn":
        self.db.log.append("BEGIN")
        self.db.in_transaction = True
        return self

    async def __aexit__(self, *_args: Any) -> None:
        self.db.in_transaction = False
        self.db.log.append("END")


class FakeDB:
    def __init__(self, owner: "FakeActions") -> None:
        self.owner = owner
        self.in_transaction = False
        self.log: list[str] = []

    async def __aenter__(self) -> "FakeDB":
        self.log.append("OPEN")
        return self

    async def __aexit__(self, *_args: Any) -> None:
        self.log.append("CLOSE")

    def begin(self) -> FakeTxn:
        return FakeTxn(self)

    async def select_readonly(self, operation: str) -> None:
        if not self.in_transaction:
            raise SyntheticAuthorizationDenied("Must be in one DB transaction")
        if operation not in ("authoritative_0027_original_current", "postgres_clock"):
            raise SyntheticAuthorizationDenied("Mutation not allowed")
        self.log.append("SELECT:" + operation)


class FakeActions:
    def __init__(self) -> None:
        self.row = copy.deepcopy(RAW)
        self.authorized_row = copy.deepcopy(RAW)
        self.manifest = MANIFEST
        self.fail_source = False
        self.now = int(time.time())
        self.dbs: list[FakeDB] = []

    def _sessions(self) -> Any:
        def session() -> FakeDB:
            db = FakeDB(self)
            self.dbs.append(db)
            return db

        return session


@pytest.fixture
def case(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    pkg = types.ModuleType("ai_osop")
    pkg.__path__ = [str(ROOT / "src" / "ai_osop")]
    memory = types.ModuleType("ai_osop.memory")
    memory.__path__ = [str(ROOT / "src" / "ai_osop" / "memory")]
    monkeypatch.setitem(sys.modules, "ai_osop", pkg)
    monkeypatch.setitem(sys.modules, "ai_osop.memory", memory)
    action_module = types.ModuleType("ai_osop.memory.flow_mcp_action_dispatch")
    action_module.FlowMCPActionStore = FakeActions
    monkeypatch.setitem(sys.modules, action_module.__name__, action_module)
    source_module = types.ModuleType("ai_osop.memory.sourcemap_source_authority")

    def validate_request(raw: Any) -> dict[str, str]:
        if (
            type(raw) is not dict
            or set(raw) != set(REQ)
            or any(type(value) is not str for value in raw.values())
            or raw["server_id"] != "source-map-mcp"
            or raw["tool_name"] != "inspect_local_original_sourcemap"
            or not raw["request_id"].startswith("req-")
            or len(raw["artifact_sha256"]) != 64
        ):
            raise SyntheticAuthorizationDenied("Invalid fake request")
        return dict(raw)

    def canonical(raw: Any) -> bytes:
        return json.dumps(
            raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")

    class FakeSource:
        def __init__(self, actions: FakeActions) -> None:
            if not isinstance(actions, FakeActions):
                raise SyntheticAuthorizationDenied("Wrong source")
            self.actions = actions

        async def _source(self, db: FakeDB, request: dict[str, str]) -> tuple[dict[str, Any], str]:
            await db.select_readonly("authoritative_0027_original_current")
            if self.actions.fail_source:
                raise SyntheticAuthorizationDenied("Synthetic current authority revoked")
            if any(self.actions.row.get(k) != request[k] for k in REQ if k != "artifact_sha256"):
                raise SyntheticAuthorizationDenied("Synthetic Action mismatch")
            if any(
                self.actions.row.get(k) != self.actions.authorized_row[k]
                for k in ("owner_id", "flow_id")
            ):
                raise SyntheticAuthorizationDenied(
                    "Synthetic Flow or owner source authority rejected"
                )
            return copy.deepcopy(self.actions.row), self.actions.manifest

        async def _now(self, db: FakeDB) -> int:
            await db.select_readonly("postgres_clock")
            return self.actions.now

        async def admit(self, _: Any) -> None:
            raise AssertionError("NEVER issue 0035 or mutate PostgreSQL")

    source_module.SourceMapSourceAuthorityStore = FakeSource
    source_module.canonical = canonical
    source_module.validate_request = validate_request
    monkeypatch.setitem(sys.modules, source_module.__name__, source_module)
    name = "ai_osop.memory.sourcemap_original_bootstrap_witness"
    spec = importlib.util.spec_from_file_location(name, FILE)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, mod)
    spec.loader.exec_module(mod)

    host_root = tmp_path / "sourcemap-originals"
    host_root.mkdir(mode=0o700)
    host_root.chmod(0o700)
    monkeypatch.setenv("OSOP_SOURCEMAP_HOST_STAGE_ROOT", str(host_root))
    signer = Ed25519PrivateKey.generate()
    passphrase = os.urandom(32)
    key_file = tmp_path / "bootstrap-signing-encrypted.pem"
    key_file.write_bytes(
        signer.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase),
        )
    )
    key_file.chmod(0o600)
    pw_file = tmp_path / "bootstrap-passphrase"
    pw_file.write_bytes(passphrase)
    pw_file.chmod(0o600)
    pub = signer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    monkeypatch.setenv(
        mod.TRUST_ENV, json.dumps({"bootstrap-signing": base64.b64encode(pub).decode()})
    )
    monkeypatch.setenv(mod.SIGNING_KID_ENV, "bootstrap-signing")
    monkeypatch.setenv(mod.SIGNING_KEY_FILE_ENV, str(key_file))
    monkeypatch.setenv(mod.SIGNING_PASSWORD_FILE_ENV, str(pw_file))
    for name in mod._OTHER_TRUST_ENVS:
        monkeypatch.delenv(name, raising=False)
    actions = FakeActions()
    return {
        "mod": mod,
        "actions": actions,
        "roots": {"bootstrap-signing": pub},
        "key_file": key_file,
        "pw_file": pw_file,
        "host_root": host_root,
    }


def attest(case: dict[str, Any], request: Any = None) -> dict[str, Any]:
    store = case["mod"].SourceMapOriginalBootstrapWitnessStore(case["actions"])
    return asyncio.run(store.attest(REQ if request is None else request))


@pytest.mark.skipif(sys.platform != "linux", reason="protected Linux host signer only")
def test_signed_encrypted_separate_source_and_one_fake_pg_tx(
    case: dict[str, Any],
) -> None:
    proof = attest(case)
    mod = case["mod"]
    actual = mod.verify_bootstrap_witness(proof, case["roots"], REQ)
    assert set(actual) == mod.CLAIM_FIELDS
    assert actual["purpose"] == "pre_0035_original_readonly_current"
    assert actual["action_id"] == RAW["action_id"]
    assert actual["intent_sha256"] == RAW["intent_sha256"]
    assert actual["authorization_sha256"] == RAW["authorization_sha256"]
    assert actual["manifest_sha256"] == MANIFEST
    assert actual["artifact_sha256"] == REQ["artifact_sha256"]
    assert actual["expires_at"] == actual["observed_at"] + 5
    assert "preflight_id" not in actual and "status_id" not in actual
    assert "pid" not in actual and "read_only" not in actual
    assert case["actions"].dbs[0].log == [
        "OPEN",
        "BEGIN",
        "SELECT:authoritative_0027_original_current",
        "SELECT:postgres_clock",
        "END",
        "CLOSE",
    ]
    assert case["key_file"].read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert not list(case["host_root"].iterdir())


@pytest.mark.skipif(sys.platform != "linux", reason="protected Linux host signer only")
@pytest.mark.parametrize(
    "field,invalid",
    [
        ("status", "succeeded"),
        ("status", "pending"),
        ("cancel_requested", True),
        ("receipt_sha256", SHA),
        ("action_id", "action-cross-tenant"),
        ("owner_id", "owner-not-authorized"),
        ("flow_id", "flow-cross-tenant"),
        ("authorization_sha256", "bad"),
        ("flow_revision", -1),
        ("authorization_version", 0),
        ("lease_id", None),
        ("parameters_sha256", "f" * 65),
    ],
)
def test_fake_current_row_inconsistency_fails_closed(
    case: dict[str, Any],
    field: str,
    invalid: Any,
) -> None:
    case["actions"].row[field] = invalid
    with pytest.raises(case["mod"].SourceMapBootstrapWitnessDenied):
        attest(case)
    assert not list(case["host_root"].iterdir())


@pytest.mark.skipif(sys.platform != "linux", reason="protected Linux host signer only")
@pytest.mark.parametrize("kind", ["revoked", "manifest_bad", "clock_past", "clock_future"])
def test_fake_authority_revocation_and_time_fail_closed(
    case: dict[str, Any],
    kind: str,
) -> None:
    if kind == "revoked":
        case["actions"].fail_source = True
    elif kind == "manifest_bad":
        case["actions"].manifest = "NOT-A-SHA"
    elif kind == "clock_past":
        case["actions"].now -= 15
    else:
        case["actions"].now += 15
    with pytest.raises(case["mod"].SourceMapBootstrapWitnessDenied):
        attest(case)
    assert case["actions"].dbs[0].log[-2:] == ["END", "CLOSE"]


@pytest.mark.skipif(sys.platform != "linux", reason="protected Linux host signer only")
def test_tamper_wrong_action_expiry_foreign_signature_and_domain(
    case: dict[str, Any],
) -> None:
    proof = attest(case)
    mod = case["mod"]
    for field, value in (
        ("owner_id", "owner-attacker"),
        ("artifact_sha256", "f" * 64),
        ("expires_at", int(time.time()) + 200),
    ):
        altered = copy.deepcopy(proof)
        altered["claims"][field] = value
        with pytest.raises(mod.SourceMapBootstrapWitnessDenied):
            mod.verify_bootstrap_witness(altered, case["roots"], REQ)
    with pytest.raises(mod.SourceMapBootstrapWitnessDenied):
        mod.verify_bootstrap_witness(proof, case["roots"], {**REQ, "task_id": "task-foreign"})
    with pytest.raises(mod.SourceMapBootstrapWitnessDenied):
        mod.verify_bootstrap_witness(proof, case["roots"], REQ, now=int(time.time()) + 10)
    with pytest.raises(mod.SourceMapBootstrapWitnessDenied):
        mod.verify_bootstrap_witness(proof, {"other-root": os.urandom(32)}, REQ)
    assert mod.BOOTSTRAP_DOMAIN != b"ai-osop/sourcemap-original-preflight/v1\x00"
    assert mod.BOOTSTRAP_DOMAIN != b"ai-osop/sourcemap-original-status/v1\x00"


@pytest.mark.skipif(sys.platform != "linux", reason="protected Linux host signer only")
@pytest.mark.parametrize(
    "kind",
    [
        "key_world",
        "password_world",
        "wrong_password",
        "unencrypted",
        "untrusted",
        "shared_root",
        "bad_key_symlink",
        "missing_password",
    ],
)
def test_host_0600_encrypted_signer_fail_closed(
    case: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    mod = case["mod"]
    if kind == "key_world":
        case["key_file"].chmod(0o644)
    elif kind == "password_world":
        case["pw_file"].chmod(0o640)
    elif kind == "wrong_password":
        case["pw_file"].write_bytes(os.urandom(32))
    elif kind == "unencrypted":
        key = Ed25519PrivateKey.generate()
        case["key_file"].write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    elif kind == "untrusted":
        monkeypatch.setenv(mod.SIGNING_KID_ENV, "unregistered")
    elif kind == "shared_root":
        monkeypatch.setenv(
            "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
            json.dumps({"reused": base64.b64encode(case["roots"]["bootstrap-signing"]).decode()}),
        )
    elif kind == "bad_key_symlink":
        shortcut = case["key_file"].parent / "fake-link.pem"
        shortcut.symlink_to(case["key_file"])
        monkeypatch.setenv(mod.SIGNING_KEY_FILE_ENV, str(shortcut))
    else:
        monkeypatch.delenv(mod.SIGNING_PASSWORD_FILE_ENV)
    with pytest.raises(mod.SourceMapBootstrapWitnessDenied):
        attest(case)
    assert case["actions"].dbs == []


@pytest.mark.skipif(sys.platform != "linux", reason="protected Linux host signer only")
def test_request_extra_ready_flag_cannot_become_permission(case: dict[str, Any]) -> None:
    with pytest.raises(SyntheticAuthorizationDenied):
        attest(case, {**REQ, "source_current": True})
    with pytest.raises(SyntheticAuthorizationDenied):
        attest(case, {**REQ, "pid": os.getpid()})
    assert case["actions"].dbs == []


def test_real_source_contract_is_pre_0035_no_mutating_admit_path(
    case: dict[str, Any],
) -> None:
    import ast

    original = AUTHORITATIVE.read_text(encoding="utf-8")
    tree = ast.parse(original)
    store = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "SourceMapSourceAuthorityStore"
    )
    source = next(
        node
        for node in store.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_source"
    )
    text = ast.get_source_segment(original, source)
    assert text is not None
    for independent_check in (
        "_authority(",
        "_approved_task(",
        "_original_manifest(",
        "_intent(",
        "flow_mcp_action_dispatches",
        "flow_mcp_action_dispatch_events",
        "session_states",
        "tasks",
        "cancel_requested",
        "unknown",
        "allow_source_map_inspection",
    ):
        assert independent_check in text
    assert "native_sourcemap_source_preflights" not in text
    assert ".admit(" not in text
    witness = FILE.read_text(encoding="utf-8")
    w_ast = ast.parse(witness)
    implementation = next(
        node
        for node in w_ast.body
        if isinstance(node, ast.ClassDef) and node.name == "SourceMapOriginalBootstrapWitnessStore"
    )
    method = next(
        node
        for node in implementation.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "attest"
    )
    body = ast.get_source_segment(witness, method)
    assert body is not None and "._source(" in body and "._now(" in body
    assert ".admit(" not in body and "INSERT" not in body and "UPDATE" not in body
    if sys.platform != "linux":
        with pytest.raises(case["mod"].SourceMapBootstrapWitnessDenied):
            attest(case)
