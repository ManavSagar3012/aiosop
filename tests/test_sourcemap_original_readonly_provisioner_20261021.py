"""Offline contract/adversarial tests of host read-only SourceMap provisioning.

FakeDB only: these tests do not claim live PostgreSQL, 0015 reviewer or 0035
issuer qualification. The real production _source verifier is invoked by the
adapter; the fake replaces that one verifier only to exercise the readback and
host staging seam. No app DB, Docker, source issuer or native request is run.
"""

from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import os
import re
import stat
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.memory.sourcemap_source_authority import SourceMapSourceAuthorityStore
from ai_osop.orchestrator import sourcemap_original_readonly_provisioner as host
from ai_osop.orchestrator import sourcemap_original_stage as stage


ORIGINAL = b'{"version":3,"sources":["owned.js"],"sourcesContent":["const owned = true;"]}'
SHA = hashlib.sha256(ORIGINAL).hexdigest()
MANIFEST = "b" * 64
AUTH = "c" * 64
PARAMETERS = "d" * 64
ARTIFACT = "artifact-" + "a" * 32
ISSUER = "independent-source-issuer"
SUPERVISOR = "independent-host-supervisor"


def _signed(claims: dict[str, Any], key: Ed25519PrivateKey, domain: bytes, kid: str) -> dict:
    signature = key.sign(domain + stage._canonical(claims))
    return {
        "claims": claims,
        "kid": kid,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def _public(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(
        "ascii"
    )


class FakeResult:
    def __init__(self, value: Optional[dict[str, Any]]) -> None:
        self.value = value

    def mappings(self) -> "FakeResult":
        return self

    def one_or_none(self) -> Optional[dict[str, Any]]:
        return self.value


class FakeDB:
    def __init__(self, records: dict[str, Any]) -> None:
        self.records = records
        self.sql: list[str] = []
        self.transactions = 0

    async def execute(self, stmt: Any, params: dict[str, Any]) -> FakeResult:
        sql = str(stmt)
        self.sql.append(sql)
        assert sql.lstrip().upper().startswith("SELECT "), sql
        if "FROM native_sourcemap_source_preflights" in sql:
            claim = self.records["expected_claim"]
            assert params == {
                "request": claim["request_id"],
                "action": claim["action_id"],
                "preflight": claim["preflight_id"],
            }
            return FakeResult(self.records.get("preflight"))
        if "FROM flow_resource_folder_catalogs" in sql:
            claim = self.records["expected_claim"]
            assert params == {"flow": claim["flow_id"], "eng": claim["engagement_id"]}
            return FakeResult(self.records.get("folder"))
        if "FROM tasks WHERE" in sql:
            claim = self.records["expected_claim"]
            assert params == {"task": claim["task_id"], "eng": claim["engagement_id"]}
            return FakeResult(self.records.get("task"))
        if "FROM flow_artifacts WHERE" in sql:
            claim = self.records["expected_claim"]
            assert params == {
                "artifact": self.records["task"]["payload"]["resource_artifact_id"],
                "flow": claim["flow_id"],
                "eng": claim["engagement_id"],
                "owner": claim["owner_id"],
            }
            return FakeResult(self.records.get("artifact"))
        raise AssertionError("Unexpected SQL " + sql)

    @asynccontextmanager
    async def begin(self) -> Any:
        self.transactions += 1
        yield self


class FakeMemory:
    def __init__(self, db: FakeDB) -> None:
        self.db = db

    def _async_session(self) -> Any:
        class Session:
            def __init__(self, db: FakeDB) -> None:
                self.db = db

            async def __aenter__(self) -> FakeDB:
                return self.db

            async def __aexit__(self, *args: Any) -> None:
                return None

        return Session(self.db)


def _claims() -> dict[str, Any]:
    now = int(time.time())
    return {
        "version": 1,
        "preflight_id": "nsp-" + "1" * 32,
        "request_id": "req-" + "2" * 48,
        "engagement_id": "eng-owner-source",
        "flow_id": "flow-original-source",
        "task_id": "task-original-source",
        "subtask_id": "subtask-original-source",
        "action_id": "action-" + "3" * 32,
        "owner_id": "owner-original",
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        "artifact_sha256": SHA,
        "manifest_sha256": MANIFEST,
        "approval_id": "apr-independent",
        "lease_id": "lease-active",
        "authorization_version": 1,
        "authorization_sha256": AUTH,
        "issued_at": now,
        "expires_at": now + 10,
    }


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    source_key = Ed25519PrivateKey.generate()
    host_key = Ed25519PrivateKey.generate()
    root = tmp_path / "sourcemap-originals"
    root.mkdir(mode=0o700)
    if os.name == "posix":
        root.chmod(0o700)
    monkeypatch.setenv("OSOP_SOURCEMAP_HOST_STAGE_ROOT", str(root))
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({ISSUER: _public(source_key)}),
    )
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_HOST_STAGE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({SUPERVISOR: _public(host_key)}),
    )
    claims = _claims()
    source = _signed(claims, source_key, stage.SOURCE_DOMAIN, ISSUER)
    signature = base64.urlsafe_b64decode(source["signature"] + "==")
    source_sha = hashlib.sha256(
        stage.SOURCE_DOMAIN + stage._canonical(claims) + signature
    ).hexdigest()
    provision = _signed(
        {**claims, "stage_id": "sms-" + "4" * 32, "source_proof_sha256": source_sha},
        host_key,
        stage.PROVISION_DOMAIN,
        SUPERVISOR,
    )
    original = {
        **{
            key: claims[key]
            for key in (
                "request_id",
                "engagement_id",
                "flow_id",
                "task_id",
                "subtask_id",
                "action_id",
                "owner_id",
                "server_id",
                "tool_name",
                "approval_id",
                "lease_id",
                "authorization_version",
                "authorization_sha256",
            )
        },
        "authorization_id": "auth-current-original",
        "flow_revision": 0,
        "parameters_sha256": PARAMETERS,
    }
    preflight = {
        **claims,
        "kid": ISSUER,
        "claims_sha256": hashlib.sha256(stage._canonical(claims)).hexdigest(),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
    }
    task = {
        "payload": {
            "resource_artifact_id": ARTIFACT,
            "resource_artifact_sha256": SHA,
            "resource_manifest_sha256": MANIFEST,
            "resource_authorization_sha256": AUTH,
            "resource_command_sha256": PARAMETERS,
        }
    }
    artifact = {
        "id": ARTIFACT,
        "flow_id": claims["flow_id"],
        "engagement_id": claims["engagement_id"],
        "owner_id": claims["owner_id"],
        "flow_revision": 0,
        "authorization_version": 1,
        "authorization_sha256": AUTH,
        "sha256": SHA,
        "size_bytes": len(ORIGINAL),
        "content": ORIGINAL,
    }
    folder = {
        "flow_id": claims["flow_id"],
        "engagement_id": claims["engagement_id"],
        "owner_sub": claims["owner_id"],
        "flow_revision": 0,
        "authorization_id": original["authorization_id"],
        "authorization_version": 1,
        "authorization_sha256": AUTH,
        "manifest_sha256": MANIFEST,
    }
    db = FakeDB(
        {
            "preflight": preflight,
            "folder": folder,
            "task": task,
            "artifact": artifact,
            "expected_claim": claims,
        }
    )
    memory = SessionMemory()
    memory._async_session = lambda: FakeMemory(db)._async_session()
    actions = FlowMCPActionStore(memory, MCPRegistry())
    calls: list[dict[str, str]] = []

    async def current(
        _self: Any, database: FakeDB, request: dict[str, str]
    ) -> tuple[dict[str, Any], str]:
        assert database is db
        calls.append(dict(request))
        assert request == {
            "request_id": claims["request_id"],
            "engagement_id": claims["engagement_id"],
            "task_id": claims["task_id"],
            "server_id": claims["server_id"],
            "tool_name": claims["tool_name"],
            "artifact_sha256": claims["artifact_sha256"],
        }
        return original, MANIFEST

    # All current authorization checks are production SourceMap _source's
    # responsibility; replacement here is deliberate FakeDB, not live PG.
    monkeypatch.setattr(SourceMapSourceAuthorityStore, "_source", current)
    return {
        "root": root,
        "source": source,
        "provision": provision,
        "source_key": source_key,
        "host_key": host_key,
        "claims": claims,
        "original": original,
        "db": db,
        "calls": calls,
        "actions": actions,
    }


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="POSIX dir-fd/fsync staging; Windows fail-closed")
async def test_committed_source_original_bytes_write_readonly_and_never_replay(
    world: dict[str, Any]
) -> None:
    provisioner = host.OriginalSourceMapReadonlyProvisioner(world["actions"])
    result = await provisioner.provision(
        source_proof=world["source"], provision_proof=world["provision"]
    )
    assert result == world["root"] / (SHA + ".map")
    assert result.read_bytes() == ORIGINAL
    assert stat.S_ISREG(result.lstat().st_mode)
    assert result.stat().st_nlink == 1
    assert result.stat().st_mode & 0o222 == 0
    assert world["db"].transactions == 1
    assert len(world["calls"]) == 1
    assert any("native_sourcemap_source_preflights" in s for s in world["db"].sql)
    assert any("flow_artifacts" in s for s in world["db"].sql)
    proof_path = world["root"] / (SHA + ".proof.json")
    assert proof_path.read_bytes() == host._proof_sidecar_bytes(world["source"], world["provision"])
    sidecar = json.loads(proof_path.read_bytes())
    assert set(sidecar) == {"version", "source_proof", "provision_proof"}
    assert sidecar["version"] == 1
    assert sidecar["source_proof"] == world["source"]
    assert sidecar["provision_proof"] == world["provision"]
    assert stat.S_ISREG(proof_path.lstat().st_mode)
    assert proof_path.stat().st_nlink == 1
    assert proof_path.stat().st_mode & 0o222 == 0
    assert not list(world["root"].glob(".proof-*.tmp"))
    for marker in ("action_id", "request_id", "preflight_id", "stage_id"):
        value = (
            world["provision"]["claims"]["stage_id"]
            if marker == "stage_id"
            else world["claims"][marker]
        )
        tag = hashlib.sha256(value.encode("ascii")).hexdigest()
        assert (world["root"] / (".used-" + marker + "-" + tag)).read_bytes() == b"consumed\n"
    with pytest.raises(host.OriginalSourceMapProvisionDenied):
        await provisioner.provision(
            source_proof=world["source"], provision_proof=world["provision"]
        )
    assert result.read_bytes() == ORIGINAL
    assert proof_path.read_bytes() == host._proof_sidecar_bytes(world["source"], world["provision"])


def _migration_columns(filename: str, table_name: str) -> set[str]:
    root = Path(__file__).resolve().parents[1] / "migrations" / "versions"
    tree = ast.parse((root / filename).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            not isinstance(node, ast.Call)
            or not isinstance(node.func, ast.Attribute)
            or node.func.attr != "create_table"
            or not node.args
            or not isinstance(node.args[0], ast.Constant)
            or node.args[0].value != table_name
        ):
            continue
        columns: set[str] = set()
        for argument in node.args[1:]:
            if (
                isinstance(argument, ast.Call)
                and isinstance(argument.func, ast.Attribute)
                and argument.func.attr == "Column"
                and argument.args
                and isinstance(argument.args[0], ast.Constant)
                and isinstance(argument.args[0].value, str)
            ):
                columns.add(argument.args[0].value)
        return columns
    raise AssertionError("Migration create_table missing: " + table_name)


@pytest.mark.asyncio
async def test_actual_0013_0026_0035_schema_matches_select_and_bound_identities(
    world: dict[str, Any]
) -> None:
    original = await host._committed_and_current_original(
        world["db"], world["actions"], world["source"], world["claims"]
    )
    assert original == ORIGINAL
    migrations = {
        "native_sourcemap_source_preflights": "0035_native_sourcemap_source_authority.py",
        "flow_resource_folder_catalogs": "0026_flow_resource_folders.py",
        "flow_artifacts": "0013_flow_artifacts.py",
    }
    for table, revision in migrations.items():
        columns = _migration_columns(revision, table)
        selects = [sql for sql in world["db"].sql if "FROM " + table in sql]
        assert len(selects) == 1, table
        sql = selects[0]
        selected = re.search(r"^SELECT\s+(.+?)\s+FROM\s+" + table + r"\b", sql, re.I | re.S)
        assert selected is not None, sql
        if selected.group(1).strip() == "*":
            assert set(host._FIELDS).issubset(columns)
            assert {"kid", "claims_sha256", "signature_sha256"}.issubset(columns)
        else:
            queried = {part.strip() for part in selected.group(1).split(",")}
            assert queried.issubset(columns), (table, queried - columns)
            if table == "flow_artifacts":
                assert "content" in queried
                assert {"size_bytes", "sha256", "id", "owner_id"}.issubset(queried)
                assert re.search(r"\bid=:artifact\b", sql)
                assert re.search(r"\bflow_id=:flow\b", sql)
                assert re.search(r"\bengagement_id=:eng\b", sql)
                assert re.search(r"\bowner_id=:owner\b", sql)
            if table == "flow_resource_folder_catalogs":
                assert {
                    "flow_revision",
                    "authorization_id",
                    "authorization_version",
                    "authorization_sha256",
                    "owner_sub",
                    "manifest_sha256",
                }.issubset(queried)
        assert "FOR SHARE" in sql
    assert len(world["calls"]) == 1


def test_sidecar_has_exact_signed_envelopes_and_bounded_canonical_bytes(
    world: dict[str, Any]
) -> None:
    expected = host._proof_sidecar_bytes(world["source"], world["provision"])
    assert expected == json.dumps(
        {
            "version": 1,
            "source_proof": world["source"],
            "provision_proof": world["provision"],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    assert 0 < len(expected) <= 8192
    assert b"signing_private_key" not in expected


@pytest.mark.asyncio
async def test_missing_supervisor_enrollment_denies_before_db(
    world: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OSOP_SOURCEMAP_HOST_STAGE_TRUSTED_PUBLIC_KEYS_JSON")
    with pytest.raises(ValueError):
        host.OriginalSourceMapReadonlyProvisioner(world["actions"])
    assert world["db"].sql == []


@pytest.mark.asyncio
async def test_caller_minted_or_tampered_proofs_never_read_bytea(world: dict[str, Any]) -> None:
    provisioner = host.OriginalSourceMapReadonlyProvisioner(world["actions"])
    for invalid_source, invalid_provision in (
        ({**world["source"], "signature": "A" * 86}, world["provision"]),
        (
            {**world["source"], "claims": {**world["claims"], "owner_id": "attacker"}},
            world["provision"],
        ),
        (world["source"], {**world["provision"], "signature": "A" * 86}),
        (world["claims"], world["provision"]),
        (world["source"], {}),
    ):
        with pytest.raises(ValueError):
            await provisioner.provision(
                source_proof=invalid_source, provision_proof=invalid_provision
            )
    assert world["db"].sql == []
    assert not list(world["root"].glob("*.map"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "row,field,value",
    [
        ("preflight", "owner_id", "attacker"),
        ("preflight", "manifest_sha256", "f" * 64),
        ("preflight", "signature_sha256", "0" * 64),
        ("preflight", "kid", "untrusted"),
        ("folder", "owner_sub", "other-owner"),
        ("folder", "manifest_sha256", "e" * 64),
        ("task", "resource_command_sha256", "f" * 64),
        ("task", "resource_artifact_id", "artifact-" + "f" * 32),
        ("artifact", "owner_id", "other-owner"),
        ("artifact", "content", ORIGINAL + b"tampered"),
        ("artifact", "size_bytes", len(ORIGINAL) + 1),
        ("artifact", "sha256", "9" * 64),
    ],
)
async def test_mutated_current_db_provenance_denied_without_staging(
    world: dict[str, Any], row: str, field: str, value: Any
) -> None:
    record = world["db"].records[row]
    if row == "task":
        record["payload"][field] = value
    else:
        record[field] = value
    provisioner = host.OriginalSourceMapReadonlyProvisioner(world["actions"])
    with pytest.raises(host.OriginalSourceMapProvisionDenied):
        await provisioner.provision(
            source_proof=world["source"], provision_proof=world["provision"]
        )
    assert not list(world["root"].glob("*.map"))


@pytest.mark.asyncio
async def test_absent_committed_0035_or_current_revoked_reviewer_never_stage(
    world: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    provisioner = host.OriginalSourceMapReadonlyProvisioner(world["actions"])
    world["db"].records["preflight"] = None
    with pytest.raises(host.OriginalSourceMapProvisionDenied):
        await provisioner.provision(
            source_proof=world["source"], provision_proof=world["provision"]
        )
    assert world["calls"] == []

    world["db"].records["preflight"] = {
        **world["claims"],
        "kid": ISSUER,
        "claims_sha256": hashlib.sha256(stage._canonical(world["claims"])).hexdigest(),
        "signature_sha256": hashlib.sha256(
            base64.urlsafe_b64decode(world["source"]["signature"] + "==")
        ).hexdigest(),
    }

    async def revoked(_self: Any, _db: Any, _request: Any) -> Any:
        raise ValueError("Current independent reviewer or lease disabled")

    monkeypatch.setattr(SourceMapSourceAuthorityStore, "_source", revoked)
    with pytest.raises(host.OriginalSourceMapProvisionDenied):
        await provisioner.provision(
            source_proof=world["source"], provision_proof=world["provision"]
        )
    assert not list(world["root"].glob("*.map"))


@pytest.mark.asyncio
async def test_missing_catalog_allowed_only_when_signed_task_manifest_verified(
    world: dict[str, Any]
) -> None:
    world["db"].records["folder"] = None
    original = await host._committed_and_current_original(
        world["db"], world["actions"], world["source"], world["claims"]
    )
    assert original == ORIGINAL
    assert world["db"].sql


@pytest.mark.asyncio
async def test_expired_independent_proofs_are_not_usable(world: dict[str, Any]) -> None:
    expired = copy.deepcopy(world["source"])
    expired["claims"]["expires_at"] = int(time.time()) - 1
    provisioner = host.OriginalSourceMapReadonlyProvisioner(world["actions"])
    with pytest.raises(ValueError):
        await provisioner.provision(source_proof=expired, provision_proof=world["provision"])
    assert world["db"].sql == []


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="POSIX no-follow dir-fd stage only")
@pytest.mark.parametrize("poison", ["symlink", "hardlink"])
async def test_existing_link_at_content_address_never_followed(
    world: dict[str, Any], tmp_path: Path, poison: str
) -> None:
    other = tmp_path / "external-original.map"
    other.write_bytes(b"do not replace the other file")
    staged = world["root"] / (SHA + ".map")
    if poison == "symlink":
        staged.symlink_to(other)
    else:
        os.link(other, staged)
    provisioner = host.OriginalSourceMapReadonlyProvisioner(world["actions"])
    with pytest.raises(host.OriginalSourceMapProvisionDenied):
        await provisioner.provision(
            source_proof=world["source"], provision_proof=world["provision"]
        )
    assert other.read_bytes() == b"do not replace the other file"
    assert staged.exists()


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="POSIX atomic sidecar publication only")
@pytest.mark.parametrize("collision", ["symlink", "hardlink", "ordinary"])
async def test_preexisting_sidecar_is_never_overwritten_and_consumes_original_once(
    world: dict[str, Any], tmp_path: Path, collision: str
) -> None:
    outside = tmp_path / "outside-proof"
    outside.write_bytes(b"preserve original outside bytes")
    sidecar = world["root"] / (SHA + ".proof.json")
    if collision == "symlink":
        sidecar.symlink_to(outside)
    elif collision == "hardlink":
        os.link(outside, sidecar)
    else:
        sidecar.write_bytes(b"preexisting private sidecar")
    original_sidecar = sidecar.read_bytes()
    provisioner = host.OriginalSourceMapReadonlyProvisioner(world["actions"])
    with pytest.raises(host.OriginalSourceMapProvisionDenied):
        await provisioner.provision(
            source_proof=world["source"], provision_proof=world["provision"]
        )
    assert sidecar.read_bytes() == original_sidecar
    assert outside.read_bytes() == b"preserve original outside bytes"
    assert (world["root"] / (SHA + ".map")).read_bytes() == ORIGINAL
    assert not list(world["root"].glob(".proof-*.tmp")) or all(
        name.is_file() and name.stat().st_mode & 0o222 == 0
        for name in world["root"].glob(".proof-*.tmp")
    )
    with pytest.raises(host.OriginalSourceMapProvisionDenied):
        await provisioner.provision(
            source_proof=world["source"], provision_proof=world["provision"]
        )
    assert sidecar.read_bytes() == original_sidecar


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "nt", reason="Windows must deny closed")
async def test_windows_no_posix_handles_denies_stage_without_writing_map(
    world: dict[str, Any]
) -> None:
    provisioner = host.OriginalSourceMapReadonlyProvisioner(world["actions"])
    with pytest.raises(host.OriginalSourceMapProvisionDenied):
        await provisioner.provision(
            source_proof=world["source"], provision_proof=world["provision"]
        )
    assert not list(world["root"].glob("*.map"))
    assert len(world["calls"]) == 1
