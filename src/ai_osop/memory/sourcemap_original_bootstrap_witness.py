"""Independently signed, READ-ONLY first-use original SourceMap precheck.

This witness breaks the *preflight-status* ordering dependency without
pretending to be a 0035 preflight, STATUS token, native execution grant, or
supervisor/mount proof. It cannot publish original bytes or reissue an UNKNOWN
Action. A privileged host may verify it BEFORE reserving one local one-shot
0035 issuer attempt; existing coordinator and production consumers are NOT
wired to this new contract.

The authoritative pre-0035 SourceMapSourceAuthorityStore._source() rechecks
the original UNKNOWN 0027 Action and immutable attempted event, live signed
Flow authorization and ROE policy, owner/Task/subtask, distinct senior
reviewer, current lease, reviewed original artifact SHA (0013) and exact
Task-approved manifest (0015/0026). Importantly, _source does NOT query a
0035 preflight. Its .admit() *does* INSERT 0035 and must NEVER be called here.

_source uses SELECT ... FOR UPDATE in its own existing trust path; PostgreSQL
SET TRANSACTION READ ONLY would reject these row locks. We use one ordinary
transaction containing ONLY _source's SELECT/row locks and its SELECT clock,
and perform NO INSERT/UPDATE/DELETE or provider/target operation. This is
read-only application behavior, not a PostgreSQL READ ONLY transaction mode.

The separately enrolled Ed25519 key is stored as ENCRYPTED PKCS8, protected
by a distinct 0600 owner-only passphrase file, both only on the Linux host.
Neither private file is accepted from a request or placed in the native
SourceMap root. Signatures are domain-separated from original 0035/status,
provision, supervisor and process signers. A precheck expires within 5s;
currentness is re-evaluated by 0035 and by the downstream host provisioner.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.sourcemap_source_authority import (
    SourceMapSourceAuthorityStore,
    canonical,
    validate_request,
)

BOOTSTRAP_DOMAIN = b"ai-osop/sourcemap-original-bootstrap-current/v1\x00"
TRUST_ENV = "OSOP_SOURCEMAP_BOOTSTRAP_TRUSTED_PUBLIC_KEYS_JSON"
SIGNING_KID_ENV = "OSOP_SOURCEMAP_BOOTSTRAP_SIGNING_KID"
SIGNING_KEY_FILE_ENV = "OSOP_SOURCEMAP_BOOTSTRAP_SIGNING_KEY_FILE"
SIGNING_PASSWORD_FILE_ENV = "OSOP_SOURCEMAP_BOOTSTRAP_SIGNING_PASSWORD_FILE"
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_REQUEST_FIELDS = (
    "request_id",
    "engagement_id",
    "task_id",
    "server_id",
    "tool_name",
    "artifact_sha256",
)
_CURRENT_ROW_FIELDS = (
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
    "lease_owner_id",
    "flow_revision",
    "authorization_id",
    "authorization_version",
    "authorization_sha256",
    "intent_sha256",
    "declaration_sha256",
    "parameters_sha256",
)
_DIGEST_FIELDS = frozenset(
    {
        "artifact_sha256",
        "manifest_sha256",
        "authorization_sha256",
        "intent_sha256",
        "declaration_sha256",
        "parameters_sha256",
    }
)
CLAIM_FIELDS = frozenset(
    {
        "version",
        "purpose",
        *_CURRENT_ROW_FIELDS,
        "artifact_sha256",
        "manifest_sha256",
        "observed_at",
        "expires_at",
    }
)
_OTHER_TRUST_ENVS = (
    "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
    "OSOP_SOURCEMAP_HOST_STAGE_TRUSTED_PUBLIC_KEYS_JSON",
    "OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_TRUSTED_PUBLIC_KEYS_JSON",
    "OSOP_SOURCEMAP_NATIVE_SUPERVISOR_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
    "OSOP_SOURCEMAP_SUPERVISOR_PROCESS_TRUSTED_PUBLIC_KEYS_JSON",
    "OSOP_SOURCEMAP_SUPERVISOR_CURRENT_DB_TRUSTED_PUBLIC_KEYS_JSON",
)


class SourceMapBootstrapWitnessDenied(ValueError):
    """Current original 0027 authorization or independent signer unavailable."""


def _deny() -> None:
    raise SourceMapBootstrapWitnessDenied("Current original SourceMap bootstrap unavailable")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _deny()
        result[key] = value
    return result


def _trusted_roots(raw: str) -> dict[str, bytes]:
    if not 2 <= len(raw) <= 8192:
        _deny()
    try:
        parsed = json.loads(raw, object_pairs_hook=_unique)
        if type(parsed) is not dict or not 1 <= len(parsed) <= 16:
            _deny()
        roots: dict[str, bytes] = {}
        for kid, key in parsed.items():
            if (
                type(kid) is not str
                or _KID.fullmatch(kid) is None
                or type(key) is not str
                or len(key) != 44
            ):
                _deny()
            pub = base64.b64decode(key, validate=True)
            if len(pub) != 32 or base64.b64encode(pub).decode("ascii") != key:
                _deny()
            roots[kid] = pub
        return roots
    except (TypeError, ValueError, UnicodeError) as exc:
        raise SourceMapBootstrapWitnessDenied("Bootstrap signing root unavailable") from exc


def _key_parent(path: Path) -> None:
    if not path.is_absolute():
        _deny()
    try:
        for item in path.parents:
            info = item.lstat()
            if not stat.S_ISDIR(info.st_mode):
                _deny()
            # Only a root-owned sticky shared ancestor may be group writable.
            if info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                _deny()
    except OSError as exc:
        raise SourceMapBootstrapWitnessDenied("Bootstrap signing parent untrusted") from exc


def _read_host_secret(path: Path, *, limit: int) -> bytes:
    _key_parent(path)
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= limit
        ):
            _deny()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            content = stream.read(limit + 1)
            after = os.fstat(stream.fileno())

        def identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        if (
            len(content) != before.st_size
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)
        ):
            _deny()
        return content
    except OSError as exc:
        raise SourceMapBootstrapWitnessDenied("Protected bootstrap secret unavailable") from exc


def _host_signer() -> tuple[str, Ed25519PrivateKey, dict[str, bytes]]:
    if sys.platform != "linux" or os.name != "posix":
        _deny()
    kid = os.getenv(SIGNING_KID_ENV, "")
    root = Path(os.getenv("OSOP_SOURCEMAP_HOST_STAGE_ROOT", ""))
    key_path = Path(os.getenv(SIGNING_KEY_FILE_ENV, ""))
    password_path = Path(os.getenv(SIGNING_PASSWORD_FILE_ENV, ""))
    if (
        _KID.fullmatch(kid) is None
        or not root.is_absolute()
        or root.name != "sourcemap-originals"
        or not key_path.is_absolute()
        or not password_path.is_absolute()
        or key_path == password_path
        or key_path == root
        or password_path == root
        or root in key_path.parents
        or root in password_path.parents
    ):
        _deny()
    try:
        roots = _trusted_roots(os.getenv(TRUST_ENV, ""))
        if kid not in roots:
            _deny()
        for env in _OTHER_TRUST_ENVS:
            existing = os.getenv(env, "")
            if existing and roots[kid] in _trusted_roots(existing).values():
                _deny()
        # Resolve ancestors and block aliases into a staged native directory.
        resolved = root.resolve(strict=True)
        for path in (key_path, password_path):
            actual = path.resolve(strict=True)
            if actual == resolved or resolved in actual.parents:
                _deny()
        encrypted = _read_host_secret(key_path, limit=4096)
        password = _read_host_secret(password_path, limit=256)
        if (
            not encrypted.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
            or not encrypted.endswith(b"-----END ENCRYPTED PRIVATE KEY-----\n")
            or not 24 <= len(password) <= 256
        ):
            _deny()
        private = serialization.load_pem_private_key(encrypted, password=password)
        if not isinstance(private, Ed25519PrivateKey):
            _deny()
        pub = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if not hmac.compare_digest(pub, roots[kid]):
            _deny()
        return kid, private, roots
    except SourceMapBootstrapWitnessDenied:
        raise
    except Exception as exc:
        raise SourceMapBootstrapWitnessDenied(
            "Independent encrypted host-only bootstrap signer unavailable"
        ) from exc


def _claims(
    request: dict[str, str], row: Mapping[str, Any], manifest: str, now: int
) -> dict[str, Any]:
    """Create immutable claims solely from authoritative _source output."""
    if (
        type(row) is not dict
        or type(now) is not int
        or now <= 0
        or type(manifest) is not str
        or _SHA.fullmatch(manifest) is None
        or any(row.get(key) != request[key] for key in _REQUEST_FIELDS if key != "artifact_sha256")
        or row.get("status") != "unknown"
        or row.get("cancel_requested") is not False
        or row.get("receipt_sha256") is not None
    ):
        _deny()
    picked = {}
    for field in _CURRENT_ROW_FIELDS:
        value = row.get(field)
        if field in ("flow_revision", "authorization_version"):
            if type(value) is not int or value < (0 if field == "flow_revision" else 1):
                _deny()
        elif field in _DIGEST_FIELDS:
            if type(value) is not str or _SHA.fullmatch(value) is None:
                _deny()
        elif type(value) is not str or _IDENTITY.fullmatch(value) is None:
            _deny()
        picked[field] = value
    if (
        not picked["engagement_id"].startswith("eng-")
        or not picked["task_id"].startswith("task-")
        or not picked["flow_id"].startswith("flow-")
        or re.fullmatch(r"action-[a-f0-9]{32}", picked["action_id"]) is None
        or picked["server_id"] != "source-map-mcp"
        or picked["tool_name"] != "inspect_local_original_sourcemap"
    ):
        _deny()
    result = {
        "version": 1,
        "purpose": "pre_0035_original_readonly_current",
        **picked,
        "artifact_sha256": request["artifact_sha256"],
        "manifest_sha256": manifest,
        "observed_at": now,
        "expires_at": now + 5,
    }
    if set(result) != CLAIM_FIELDS or len(canonical(result)) > 4096:
        _deny()
    return result


def verify_bootstrap_witness(
    proof: Any,
    roots: Mapping[str, bytes],
    expected_request: Any,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    """Public, domain-separated verification. Not an authorization to stage."""
    if (
        type(proof) is not dict
        or set(proof) != {"claims", "kid", "signature"}
        or type(proof.get("claims")) is not dict
        or set(proof["claims"]) != CLAIM_FIELDS
        or type(proof.get("kid")) is not str
        or proof["kid"] not in roots
        or type(proof.get("signature")) is not str
        or re.fullmatch(r"[A-Za-z0-9_-]{86}", proof["signature"]) is None
    ):
        _deny()
    try:
        request = validate_request(expected_request)
        claims = proof["claims"]
        when = int(time.time()) if now is None else now
        if (
            type(when) is not int
            or type(claims.get("version")) is not int
            or claims["version"] != 1
            or claims["purpose"] != "pre_0035_original_readonly_current"
            or type(claims.get("observed_at")) is not int
            or type(claims.get("expires_at")) is not int
            or not when - 2 <= claims["observed_at"] <= when + 1
            or not when < claims["expires_at"] <= claims["observed_at"] + 5
            or any(claims.get(field) != request[field] for field in _REQUEST_FIELDS)
            or any(
                type(claims.get(field)) is not str or _SHA.fullmatch(claims[field]) is None
                for field in _DIGEST_FIELDS
            )
            or type(claims.get("flow_revision")) is not int
            or claims["flow_revision"] < 0
            or type(claims.get("authorization_version")) is not int
            or claims["authorization_version"] < 1
        ):
            _deny()
        signature = base64.urlsafe_b64decode(proof["signature"] + "==")
        if (
            len(signature) != 64
            or base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=") != proof["signature"]
        ):
            _deny()
        Ed25519PublicKey.from_public_bytes(roots[proof["kid"]]).verify(
            signature, BOOTSTRAP_DOMAIN + canonical(claims)
        )
        return dict(claims)
    except SourceMapBootstrapWitnessDenied:
        raise
    except Exception as exc:
        raise SourceMapBootstrapWitnessDenied("Bootstrap witness proof invalid") from exc


class SourceMapOriginalBootstrapWitnessStore:
    """Read-only, independently signed current 0027 preissuance witness.

    PRIME wiring seam: in a protected host-only bootstrap coordinator,
    call await SourceMapOriginalBootstrapWitnessStore(actions).attest(request)
    BEFORE reserving the local one-shot 0035 token; verify using the separate
    BOOTSTRAP_DOMAIN/enrolled roots. Then invoke central 0035 once and obtain
    *fresh, independent* signed STATUS/DB/process/supervisor/mount evidence
    before ANY original bytes are published. This class never performs those
    later phases. Existing coordinator cannot consume this witness yet.
    """

    def __init__(self, actions: FlowMCPActionStore) -> None:
        if not isinstance(actions, FlowMCPActionStore):
            _deny()
        self._sources = SourceMapSourceAuthorityStore(actions)
        self._actions = actions

    async def attest(self, supplied: Any) -> dict[str, Any]:
        request = validate_request(supplied)
        # Fail before any DB access when issuer authority is unavailable.
        kid, private, roots = _host_signer()
        try:
            async with self._actions._sessions()() as db:
                async with db.begin():
                    row, manifest = await self._sources._source(db, request)
                    now = await self._sources._now(db)
                    claims = _claims(request, row, manifest, now)
            # No DML or central 0035 issuer call. The read-only transaction is
            # over before signing, and no caller supplies a positive authority
            # flag, PID, reviewer decision, lease state or artifact path.
            if abs(int(time.time()) - now) > 2 or int(time.time()) >= claims["expires_at"]:
                _deny()
            signature = private.sign(BOOTSTRAP_DOMAIN + canonical(claims))
            proof = {
                "claims": claims,
                "kid": kid,
                "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
            }
            verify_bootstrap_witness(proof, roots, request)
            if int(time.time()) >= claims["expires_at"]:
                _deny()
            return proof
        except SourceMapBootstrapWitnessDenied:
            raise
        except Exception as exc:
            raise SourceMapBootstrapWitnessDenied(
                "Current original SourceMap preissuance authority unavailable"
            ) from exc
