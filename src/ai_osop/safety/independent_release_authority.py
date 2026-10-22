"""Independent, read-only senior RELEASE APPROVAL verifier (unmounted).

The existing human report signoff and 0022 finding promotion are not production
release certificates. This verifier has no private keys and no issuance path.
The separate host authority must recheck current signed Flow/ROE, archived
report and target-owner receipts, and durable multi-replica and one-use release
qualifications before it signs an on-demand challenge response. No such host
service is currently mounted, so production invocation fails closed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping, Optional
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RELEASE_DOMAIN = b"AI-OSOP-INDEPENDENT-SENIOR-RELEASE-APPROVAL-V1\x00"
HOST_DOMAIN = b"AI-OSOP-HOST-CURRENT-RELEASE-AUTHORITY-V1\x00"
REPLICA_DOMAIN = b"AI-OSOP-INDEPENDENT-RELEASE-REPLICA-QUALIFICATION-V1\x00"
RUN_DOMAIN = b"AI-OSOP-INDEPENDENT-RELEASE-REPLICA-RUN-RECEIPT-V1\x00"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,127}\Z")
_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}\Z")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_MAX = 65536
_REPORT = frozenset(
    {
        "engagement_id",
        "report_id",
        "attestation_sha256",
        "manifest_sha256",
        "report_json_sha256",
        "generation_task_id",
    }
)
_AUTH = frozenset(
    {
        "tenant_id",
        "owner_sub",
        "flow_id",
        "flow_revision",
        "authorization_id",
        "authorization_version",
        "authorization_sha256",
    }
)
_TARGET = frozenset(
    {
        "finding_id",
        "verification_id",
        "verdict_sha256",
        "qualification_id",
        "qualification_sha256",
        "challenge_id",
        "target_owner_assertion_id",
        "target_owner_assertion_sha256",
        "nonce_receipt_id",
        "nonce_receipt_sha256",
    }
)
_REPLICA = frozenset(
    {
        "replica_id",
        "qualification_id",
        "qualification_sha256",
        "run_receipt_id",
        "run_receipt_sha256",
    }
)
_RELEASE = frozenset(
    {
        "schema",
        "senior_key_id",
        "senior_sub",
        "report",
        "scope",
        "target_owner_receipts",
        "replica_qualifications",
        "release_receipt_id",
        "release_receipt_sha256",
        "issued_at",
        "expires_at",
    }
)
_CURRENT = frozenset(
    {
        "schema",
        "claim_sha256",
        "challenge_sha256",
        "report",
        "scope",
        "target_owner_receipts",
        "replica_qualifications",
        "release_receipt_id",
        "release_receipt_sha256",
        "checked_at",
        "expires_at",
        "decision",
    }
)


class IndependentReleaseDenied(RuntimeError):
    """Missing or unverified independently authenticated release authority."""


def _deny() -> None:
    raise IndependentReleaseDenied("Independent senior release authority unavailable")


def _pairs_unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    found: dict[str, Any] = {}
    for key, value in pairs:
        if key in found:
            raise ValueError("Duplicate claim property")
        found[key] = value
    return found


def _json(raw: Any) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX:
        _deny()
    try:
        obj = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")),
        )
        if type(obj) is not dict:
            raise ValueError()
        return obj
    except (ValueError, TypeError, UnicodeError) as exc:
        raise IndependentReleaseDenied("Invalid release envelope") from exc


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise IndependentReleaseDenied("Noncanonical release claim") from exc


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _valid_id(value: Any, prefix: str = "") -> bool:
    return (
        type(value) is str
        and len(value) <= 128
        and bool(_ID.fullmatch(value))
        and (not prefix or value.startswith(prefix))
    )


def _valid_sha(value: Any) -> bool:
    return type(value) is str and bool(_SHA.fullmatch(value))


def _exact_dict(data: Any, keys: frozenset[str]) -> bool:
    return type(data) is dict and set(data) == keys


def _valid_report(report: Any) -> bool:
    return (
        _exact_dict(report, _REPORT)
        and _valid_id(report["engagement_id"], "eng-")
        and _valid_id(report["report_id"], "report-")
        and _valid_id(report["generation_task_id"], "task-")
        and all(
            _valid_sha(report[k])
            for k in ("attestation_sha256", "manifest_sha256", "report_json_sha256")
        )
    )


def _valid_scope(scope: Any) -> bool:
    return (
        _exact_dict(scope, _AUTH)
        and _valid_id(scope["tenant_id"])
        and _valid_id(scope["owner_sub"])
        and _valid_id(scope["flow_id"], "flow-")
        and _valid_id(scope["authorization_id"])
        and type(scope["flow_revision"]) is int
        and scope["flow_revision"] >= 0
        and type(scope["authorization_version"]) is int
        and scope["authorization_version"] > 0
        and _valid_sha(scope["authorization_sha256"])
    )


def _valid_receipts(rows: Any, keys: frozenset[str], *, replica: bool) -> bool:
    if type(rows) is not list or not 1 <= len(rows) <= 200:
        return False
    if replica and len(rows) < 2:
        return False
    identity_key = "replica_id" if replica else "finding_id"
    ids: list[str] = []
    for row in rows:
        if not _exact_dict(row, keys):
            return False
        for key, value in row.items():
            if key.endswith("_sha256"):
                if not _valid_sha(value):
                    return False
            elif not _valid_id(value):
                return False
        ids.append(row[identity_key])
    return ids == sorted(set(ids))


def _validate_release_claim(claim: Any, senior_key_id: str, now: int) -> None:
    if not (
        _exact_dict(claim, _RELEASE)
        and claim["schema"] == "ai-osop-independent-senior-release-v1"
        and claim["senior_key_id"] == senior_key_id
        and _valid_id(claim["senior_sub"])
    ):
        _deny()
    if not (
        _valid_report(claim["report"])
        and _valid_scope(claim["scope"])
        and _valid_receipts(claim["target_owner_receipts"], _TARGET, replica=False)
        and _valid_receipts(claim["replica_qualifications"], _REPLICA, replica=True)
        and _valid_id(claim["release_receipt_id"], "srelease-")
        and _valid_sha(claim["release_receipt_sha256"])
        and type(claim["issued_at"]) is int
        and type(claim["expires_at"]) is int
        and 0 < claim["issued_at"] <= now < claim["expires_at"]
        and claim["expires_at"] <= claim["issued_at"] + 300
    ):
        _deny()


def _verify_signature(envelope: Any, public_key: bytes, *, domain: bytes) -> dict[str, Any]:
    if not _exact_dict(envelope, frozenset({"claim", "signature"})):
        _deny()
    signature = envelope["signature"]
    if type(signature) is not str or not _SIGNATURE.fullmatch(signature):
        _deny()
    try:
        decoded = base64.urlsafe_b64decode(signature + "==")
        if (
            len(decoded) != 64
            or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != signature
        ):
            _deny()
        payload = envelope["claim"]
        Ed25519PublicKey.from_public_bytes(public_key).verify(decoded, domain + _canonical(payload))
    except (InvalidSignature, ValueError, TypeError, binascii.Error) as exc:
        raise IndependentReleaseDenied("Independent signature verification failed") from exc
    if type(payload) is not dict:
        _deny()
    return payload


@dataclass(frozen=True)
class PinnedReleaseTrust:
    """Provision these public keys solely from a host-managed trust registry.

    This constructor cannot enroll a signer; configuration/integration must
    independently authenticate registry identity and current revocation.
    """

    senior_key_id: str
    senior_public_key: bytes
    host_public_key: bytes
    report_signer_keys: tuple[bytes, ...]
    provider_signer_keys: tuple[bytes, ...]
    target_owner_keys: tuple[bytes, ...]
    replica_signer_roots: Optional[Mapping[str, bytes]] = None

    def __post_init__(self) -> None:
        if (
            not _valid_id(self.senior_key_id)
            or any(
                type(group) is not tuple
                for group in (
                    self.report_signer_keys,
                    self.provider_signer_keys,
                    self.target_owner_keys,
                )
            )
            or not all(
                type(key) is bytes and len(key) == 32
                for key in (
                    self.senior_public_key,
                    self.host_public_key,
                    *self.report_signer_keys,
                    *self.provider_signer_keys,
                    *self.target_owner_keys,
                )
            )
        ):
            _deny()
        if (
            not self.report_signer_keys
            or not self.provider_signer_keys
            or not self.target_owner_keys
        ):
            _deny()
        roots = (
            self.senior_public_key,
            self.host_public_key,
            *self.report_signer_keys,
            *self.provider_signer_keys,
            *self.target_owner_keys,
        )
        if len(set(roots)) != len(roots):
            _deny()
        for key in roots:
            try:
                Ed25519PublicKey.from_public_bytes(key)
            except ValueError as exc:
                raise IndependentReleaseDenied("Release public-key registry invalid") from exc
        replica_roots = self.replica_signer_roots
        if replica_roots is not None:
            if (
                type(replica_roots) is not dict
                or not 2 <= len(replica_roots) <= 32
                or not all(
                    _valid_id(identifier)
                    and type(key) is bytes
                    and len(key) == 32
                    for identifier, key in replica_roots.items()
                )
                or len(set(replica_roots.values())) != len(replica_roots)
                or any(key in roots for key in replica_roots.values())
            ):
                _deny()


class PinnedHostCurrentAuthority:
    """Real host-only HTTPS challenge transport to a distinct release service.

    The separate host service must read PostgreSQL under current signed
    authorization, inspect original artifacts and independently signed receipts,
    check replica evidence and a durable one-use release admission, and return
    its signed decision. This client never accepts caller-controlled status bits.
    """

    @staticmethod
    def _protected_ca(path_text: str) -> bytes:
        """Read one host-owned CA PEM from a protected, nonsymlinked POSIX path.

        Windows ACL policy requires a separate audited DACL implementation.
        Refuse on Windows rather than claim that POSIX mode bits prove safety.
        """
        if os.name != "posix" or not hasattr(os, "getuid"):
            _deny()
        path = Path(path_text)
        if not path.is_absolute() or path.suffix.lower() != ".pem":
            _deny()
        try:
            initial = path.lstat()
        except OSError as exc:
            raise IndependentReleaseDenied("Protected release CA path unavailable") from exc
        for element in (path, *path.parents):
            try:
                metadata = element.lstat()
            except OSError as exc:
                raise IndependentReleaseDenied("Protected release CA path unavailable") from exc
            if (
                stat.S_ISLNK(metadata.st_mode)
                or metadata.st_mode & 0o022
                or metadata.st_uid not in (0, os.getuid())
            ):
                _deny()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
            with os.fdopen(fd, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or (metadata.st_dev, metadata.st_ino) != (initial.st_dev, initial.st_ino)
                    or metadata.st_uid not in (0, os.getuid())
                    or metadata.st_mode & 0o022
                    or not 0 < metadata.st_size <= _MAX
                ):
                    _deny()
                content = stream.read(_MAX + 1)
                if len(content) != metadata.st_size or len(content) > _MAX:
                    _deny()
        except OSError as exc:
            raise IndependentReleaseDenied("Protected release CA unavailable") from exc
        if not content.startswith(b"-----BEGIN CERTIFICATE-----"):
            _deny()
        return content

    def __init__(self, *, url: str, ca_file: str, service_token: str) -> None:
        try:
            parts = urlsplit(url) if type(url) is str else None
            hostname = parts.hostname if parts is not None else None
            port = parts.port if parts is not None else None
        except ValueError as exc:
            raise IndependentReleaseDenied("Current release URL invalid") from exc
        if (
            parts is None
            or parts.scheme != "https"
            or not hostname
            or type(hostname) is not str
            or hostname != hostname.lower()
            or len(hostname) > 253
            or len(hostname.split(".")) < 2
            or any(not _DNS_LABEL.fullmatch(part) for part in hostname.split("."))
            or hostname in {"localhost", "localhost.localdomain"}
            or hostname.endswith((".localhost", ".local", ".invalid", ".test"))
            or hostname.split(".")[-1].isdigit()
            or port not in (None, 443)
            or parts.username
            or parts.password
            or parts.fragment
            or parts.query
            or parts.path != "/release/current-authority"
            or url
            not in {
                f"https://{hostname}/release/current-authority",
                f"https://{hostname}:443/release/current-authority",
            }
            or type(ca_file) is not str
            or type(service_token) is not str
            or not 32 <= len(service_token) <= 4096
            or any(ord(ch) < 33 or ord(ch) > 126 for ch in service_token)
        ):
            _deny()
        try:
            ca_content = self._protected_ca(ca_file)
            ssl_context = ssl.create_default_context(cadata=ca_content.decode("ascii"))
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        except (ssl.SSLError, UnicodeError, ValueError) as exc:
            raise IndependentReleaseDenied("Pinned release CA invalid") from exc
        self._url, self._ssl_context, self._token = url, ssl_context, service_token

    async def __call__(self, challenge: bytes, claim_sha256: str) -> bytes:
        import httpx

        if type(challenge) is not bytes or len(challenge) != 32 or not _valid_sha(claim_sha256):
            _deny()
        try:
            async with httpx.AsyncClient(
                verify=self._ssl_context, timeout=5.0, follow_redirects=False, trust_env=False
            ) as client:
                async with client.stream(
                    "POST",
                    self._url,
                    headers={
                        "Authorization": "Bearer " + self._token,
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                    content=_canonical(
                        {
                            "schema": "ai-osop-current-release-challenge-v1",
                            "challenge": base64.urlsafe_b64encode(challenge).decode().rstrip("="),
                            "claim_sha256": claim_sha256,
                        }
                    ),
                ) as response:
                    if response.status_code != 200:
                        _deny()
                    fragments = bytearray()
                    async for fragment in response.aiter_bytes():
                        if len(fragments) + len(fragment) > _MAX:
                            _deny()
                        fragments.extend(fragment)
                    return bytes(fragments)
        except (httpx.HTTPError, OSError, ValueError) as exc:
            raise IndependentReleaseDenied("Current release authority unavailable") from exc


async def verify_independent_release_approval(
    signed_release_envelope: bytes,
    *,
    trust: PinnedReleaseTrust,
    current_authority: Optional[Callable[[bytes, str], Awaitable[bytes]]],
    expected_engagement_id: str,
    expected_report_id: str,
    original_attestation_bytes: bytes,
    original_manifest_bytes: bytes,
    original_report_json_bytes: bytes,
) -> dict[str, Any]:
    """Verify exact original report hashes and two independent signatures.

    No approval is possible without an actual current host authority service.
    A caller's dict, boolean, signed provider claim or cached 0022 VERIFIED row
    is never an authority callback or a release record.
    """
    if not isinstance(trust, PinnedReleaseTrust) or not isinstance(
        current_authority, PinnedHostCurrentAuthority
    ):
        _deny()
    if not (
        _valid_id(expected_engagement_id, "eng-")
        and _valid_id(expected_report_id, "report-")
        and all(
            type(v) is bytes and 0 < len(v) <= 8_000_000
            for v in (
                original_attestation_bytes,
                original_manifest_bytes,
                original_report_json_bytes,
            )
        )
    ):
        _deny()
    claim = _verify_signature(
        _json(signed_release_envelope), trust.senior_public_key, domain=RELEASE_DOMAIN
    )
    now = int(time.time())
    _validate_release_claim(claim, trust.senior_key_id, now)
    report = claim["report"]
    if (
        report["engagement_id"] != expected_engagement_id
        or report["report_id"] != expected_report_id
        or not hmac.compare_digest(
            report["attestation_sha256"], _digest(original_attestation_bytes)
        )
        or not hmac.compare_digest(report["manifest_sha256"], _digest(original_manifest_bytes))
        or not hmac.compare_digest(
            report["report_json_sha256"], _digest(original_report_json_bytes)
        )
    ):
        _deny()
    # Fresh server challenge prevents using a stale signed host assertion to
    # hide a newly revoked owner, senior, ROE, source key or replica lease.
    challenge = secrets.token_bytes(32)
    claim_sha = _digest(RELEASE_DOMAIN + _canonical(claim))
    try:
        authority_raw = await current_authority(challenge, claim_sha)
    except Exception as exc:
        raise IndependentReleaseDenied("Current release authority unavailable") from exc
    current = _verify_signature(_json(authority_raw), trust.host_public_key, domain=HOST_DOMAIN)
    if not (
        _exact_dict(current, _CURRENT)
        and current["schema"] == "ai-osop-current-release-authority-v1"
        and current["decision"] == "current_independently_verified"
        and current["claim_sha256"] == claim_sha
        and current["challenge_sha256"] == _digest(challenge)
        and type(current["checked_at"]) is int
        and type(current["expires_at"]) is int
        and 0 <= now - current["checked_at"] <= 5
        and now < current["expires_at"] <= current["checked_at"] + 10
        and all(
            _canonical(current[field]) == _canonical(claim[field])
            for field in (
                "report",
                "scope",
                "target_owner_receipts",
                "replica_qualifications",
                "release_receipt_id",
                "release_receipt_sha256",
            )
        )
        and int(time.time()) < min(claim["expires_at"], current["expires_at"])
    ):
        _deny()
    return {
        "status": "independent_senior_release_signature_and_host_snapshot_verified",
        "engagement_id": expected_engagement_id,
        "report_id": expected_report_id,
        "claim_sha256": claim_sha,
        "senior_key_id": trust.senior_key_id,
        "release_receipt_id": claim["release_receipt_id"],
        "production_certificate_issued": False,
    }


async def _locked_row(db: Any, sql: str, **params: Any) -> dict[str, Any]:
    """Use the original read transaction; never cache or accept a row from caller."""
    from sqlalchemy import text

    record = (await db.execute(text(sql), params)).mappings().one_or_none()
    if record is None:
        _deny()
    return dict(record)


def _row_matches(row: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    if any(
        key not in row
        or type(row[key]) is not type(value)
        or row[key] != value
        for key, value in expected.items()
    ):
        _deny()


def _signed_replica_receipt(
    stored: Mapping[str, Any], receipt: Mapping[str, Any],
    claim: Mapping[str, Any], root: bytes, now: int
) -> None:
    """Check independently enrolled replica key and cryptographic process/run identity."""
    signed = stored.get("signed_receipt_json")
    signature = stored.get("signature_b64url")
    if type(signed) is not bytes or len(signed) > 8192 or type(signature) is not str:
        _deny()
    parsed = _json(signed)
    if _canonical(parsed) != signed:
        _deny()
    verified = _verify_signature(
        {"claim": parsed, "signature": signature}, root, domain=REPLICA_DOMAIN
    )
    expected = {
        "schema": "ai-osop.release-replica-qualification.v1",
        "replica_id": receipt["replica_id"],
        "qualification_id": receipt["qualification_id"],
        "run_receipt_id": receipt["run_receipt_id"],
        "run_receipt_sha256": receipt["run_receipt_sha256"],
        "engagement_id": claim["report"]["engagement_id"],
        "tenant_id": claim["scope"]["tenant_id"],
        "owner_sub": claim["scope"]["owner_sub"],
        "flow_id": claim["scope"]["flow_id"],
        "flow_revision": claim["scope"]["flow_revision"],
        "authorization_version": claim["scope"]["authorization_version"],
        "authorization_sha256": claim["scope"]["authorization_sha256"],
        "report_attestation_sha256": claim["report"]["attestation_sha256"],
        "outcome": "passed",
    }
    if (
        not set(verified) == set(expected) | {
            "process_identity_sha256", "issued_at", "expires_at"
        }
        or any(verified[k] != v for k, v in expected.items())
        or not _valid_sha(verified["process_identity_sha256"])
        or type(verified["issued_at"]) is not int
        or type(verified["expires_at"]) is not int
        or not 0 < verified["issued_at"] <= now < verified["expires_at"]
        or verified["expires_at"] > verified["issued_at"] + 300
        or _digest(REPLICA_DOMAIN + signed) != receipt["qualification_sha256"]
    ):
        _deny()


def _validated_replica_run(
    row: Mapping[str, Any], receipt: Mapping[str, Any],
    claim: Mapping[str, Any], *, process_identity_sha256: str
) -> None:
    """Read-only join to immutable independently audited run outcome bytes."""
    raw = row.get("run_receipt_json")
    if type(raw) is not bytes or len(raw) > 16384:
        _deny()
    run = _json(raw)
    expected = {
        "schema": "ai-osop.independent-release-run-receipt.v1",
        "replica_id": receipt["replica_id"],
        "run_receipt_id": receipt["run_receipt_id"],
        "process_identity_sha256": process_identity_sha256,
        "engagement_id": claim["report"]["engagement_id"],
        "tenant_id": claim["scope"]["tenant_id"],
        "owner_sub": claim["scope"]["owner_sub"],
        "flow_id": claim["scope"]["flow_id"],
        "flow_revision": claim["scope"]["flow_revision"],
        "authorization_version": claim["scope"]["authorization_version"],
        "authorization_sha256": claim["scope"]["authorization_sha256"],
        "report_attestation_sha256": claim["report"]["attestation_sha256"],
        "qualification_status": "passed",
        "qualified_behaviors": {
            "multi_process_independence": True,
            "crash_recovery": True,
            "ack_loss": True,
            "rollback": True,
            "live_revocation": True,
        },
    }
    if (
        run != expected
        or _canonical(run) != raw
        or _digest(RUN_DOMAIN + raw) != receipt["run_receipt_sha256"]
    ):
        _deny()


async def verify_current_release_ledger_join(
    signed_release_envelope: bytes,
    *,
    db: Any,
    trust: PinnedReleaseTrust,
    current_authority: PinnedHostCurrentAuthority,
    expected_engagement_id: str,
    expected_report_id: str,
    original_attestation_bytes: bytes,
    original_manifest_bytes: bytes,
    archived_artifacts: Mapping[str, bytes],
    evidence_by_finding: Mapping[str, Any],
) -> dict[str, Any]:
    """Unmounted, read-only production prerequisite with real signed source joins.

    Must run in the caller's open PostgreSQL transaction. Production DENIES
    until independent senior/replica enrollment and one-use release ledgers
    actually exist. Neither a mock provider's success nor a host echo is a
    substitute for existing 0016/0021/0022 effects and live key revocation.
    """
    if not (
        db is not None
        and callable(getattr(db, "execute", None))
        and callable(getattr(db, "in_transaction", None))
        and db.in_transaction() is True
        and isinstance(trust, PinnedReleaseTrust)
        and type(trust.replica_signer_roots) is dict
        and isinstance(current_authority, PinnedHostCurrentAuthority)
        and isinstance(archived_artifacts, Mapping)
        and set(archived_artifacts) == {"md", "html", "graph.html", "json"}
        and isinstance(evidence_by_finding, Mapping)
        and all(
            type(content) is bytes and 0 < len(content) <= 8_000_000
            for content in archived_artifacts.values()
        )
    ):
        _deny()
    now = int(time.time())
    claim = _verify_signature(
        _json(signed_release_envelope), trust.senior_public_key, domain=RELEASE_DOMAIN
    )
    _validate_release_claim(claim, trust.senior_key_id, now)
    report, scope = claim["report"], claim["scope"]
    if (
        report["engagement_id"] != expected_engagement_id
        or report["report_id"] != expected_report_id
        # No independent durable tenant ledger presently exists. Until it
        # does, the engagement itself is the only defensible tenant partition.
        or scope["tenant_id"] != expected_engagement_id
    ):
        _deny()
    try:
        from ai_osop.reporting.attestation import (
            SCHEMA_V3, verify_report_attestation, ReportAttestationError,
            _read_trusted_signers,
        )
        original = _json(original_attestation_bytes)
        details = original["attestation"]
        if details["schema"] != SCHEMA_V3:
            _deny()
        # Reconcile independently pinned report roots with the currently
        # enrolled reporting trust registry. A revoked signing key is never
        # revived merely because the signature verified historically.
        reporter_registry = _read_trusted_signers()
        current_reporter_key = reporter_registry.get(details["signer_key_id"])
        if current_reporter_key not in trust.report_signer_keys:
            _deny()
        checked = False
        for public_key in (current_reporter_key,):
            try:
                verify_report_attestation(
                    original,
                    artifacts=archived_artifacts,
                    evidence_by_finding=evidence_by_finding,
                    trusted_public_keys={details["signer_key_id"]: public_key},
                )
                checked = True
                break
            except (ReportAttestationError, KeyError, TypeError, ValueError):
                continue
        if not checked:
            _deny()
        manifest = _json(original_manifest_bytes)
        if not (
            set(manifest) == {
                "engagement_id", "report_id", "hash_algorithm", "signature_status",
                "artifacts", "attestation_sha256",
            }
            and manifest["engagement_id"] == expected_engagement_id
            and manifest["report_id"] == expected_report_id
            and manifest["hash_algorithm"] == "sha256"
            and manifest["signature_status"] == "ed25519_signed"
            and manifest["artifacts"] == details["artifacts"]
            and manifest["attestation_sha256"] == _digest(original_attestation_bytes)
            and details["generation_binding"]["task_id"] == report["generation_task_id"]
            and details["generation_binding"]["flow_id"] == scope["flow_id"]
            and details["generation_binding"]["flow_revision"] == scope["flow_revision"]
            and details["generation_binding"]["authorization_version"]
            == scope["authorization_version"]
            and details["generation_binding"]["authorization_sha256"]
            == scope["authorization_sha256"]
            and _digest(original_manifest_bytes) == report["manifest_sha256"]
            and _digest(original_attestation_bytes) == report["attestation_sha256"]
            and _digest(archived_artifacts["json"]) == report["report_json_sha256"]
            and {item["finding_id"] for item in details["evidence_provenance"]}
            == {item["finding_id"] for item in claim["target_owner_receipts"]}
        ):
            _deny()
        # Report signers are pinned separately from provider, host, owner and
        # senior; report signatures establish archival bytes only.
        parent = await _locked_row(
            db, "SELECT session_id,created_by FROM session_states "
            "WHERE session_id=:eng FOR SHARE", eng=expected_engagement_id
        )
        _row_matches(parent, {
            "session_id": expected_engagement_id,
            "created_by": scope["owner_sub"],
        })
        flow = await _locked_row(
            db, "SELECT id,engagement_id,revision FROM execution_flows "
            "WHERE id=:flow AND engagement_id=:eng FOR SHARE",
            eng=expected_engagement_id, flow=scope["flow_id"]
        )
        _row_matches(flow, {
            "id": scope["flow_id"], "engagement_id": expected_engagement_id,
            "revision": scope["flow_revision"],
        })
        from ai_osop.memory.authorization_store import guard_sql

        current_roe = await guard_sql(
            db, expected_engagement_id,
            expected_version=scope["authorization_version"],
            expected_digest=scope["authorization_sha256"],
        )
        if (
            current_roe.session_id != expected_engagement_id
            or current_roe.authorization_id != scope["authorization_id"]
            or current_roe.version != scope["authorization_version"]
            or current_roe.policy_sha256 != scope["authorization_sha256"]
        ):
            _deny()
        task = await _locked_row(
            db, "SELECT * FROM tasks WHERE id=:id AND engagement_id=:eng "
            "AND flow_id=:flow FOR SHARE",
            id=report["generation_task_id"], eng=expected_engagement_id,
            flow=scope["flow_id"],
        )
        _row_matches(task, {
            "id": report["generation_task_id"], "engagement_id": expected_engagement_id,
            "flow_id": scope["flow_id"], "type": "generate_report",
            "agent_type": "reporting", "status": "completed",
            "approval_required": True,
        })
        if (
            type(task.get("payload")) is not dict
            or type(task.get("result")) is not dict
            or task.get("completed_at") is None
            or task.get("started_at") is None
            or task["payload"].get("_authorization_version")
            != scope["authorization_version"]
            or task["payload"].get("_flow_revision") != scope["flow_revision"]
            or task["result"].get("report_id") != expected_report_id
            or task["result"].get("signature_status") != "ed25519_signed"
            or task["result"].get("status") != "success"
        ):
            _deny()
        from ai_osop.safety.approval_binding import task_payload_sha256
        if (
            task_payload_sha256(task["payload"])
            != details["generation_binding"]["task_payload_sha256"]
        ):
            _deny()
        # Current independent senior identity and key enrollment must be
        # authoritative and separately stored. These tables are intentionally
        # absent in current migration history: missing schema = DENY.
        senior_control = await _locked_row(
            db, "SELECT actor_id,disabled FROM operator_subject_controls "
            "WHERE actor_id=:actor FOR SHARE", actor=claim["senior_sub"]
        )
        _row_matches(senior_control, {
            "actor_id": claim["senior_sub"], "disabled": False
        })
        enrolled = await _locked_row(
            db, "SELECT * FROM independent_senior_release_key_enrollments "
            "WHERE key_id=:kid AND tenant_id=:tenant FOR SHARE",
            kid=trust.senior_key_id, tenant=scope["tenant_id"],
        )
        _row_matches(enrolled, {
            "key_id": trust.senior_key_id, "tenant_id": scope["tenant_id"],
            "senior_sub": claim["senior_sub"],
            "public_key_sha256": _digest(trust.senior_public_key),
            "status": "active", "revoked_at": None,
        })
        host_enrolled = await _locked_row(
            db, "SELECT * FROM independent_release_host_key_enrollments "
            "WHERE tenant_id=:tenant AND public_key_sha256=:sha FOR SHARE",
            tenant=scope["tenant_id"], sha=_digest(trust.host_public_key),
        )
        _row_matches(host_enrolled, {
            "tenant_id": scope["tenant_id"],
            "public_key_sha256": _digest(trust.host_public_key),
            "status": "active", "revoked_at": None,
        })
        # Read and recheck the immutable origin admission, challenge and
        # finding-scoped promotion; a cached VERIFIED boolean is insufficient.
        from ai_osop.memory.independent_target_effect_verifications import (
            _current_witness_trust, _row_digest
        )
        challenge_issued: dict[str, int] = {}
        for receipt in claim["target_owner_receipts"]:
            params = {
                "eng": expected_engagement_id,
                "flow": scope["flow_id"],
                "finding": receipt["finding_id"],
            }
            effect = await _locked_row(
                db, "SELECT * FROM independent_target_effect_verifications "
                "WHERE engagement_id=:eng AND flow_id=:flow "
                "AND finding_id=:finding FOR SHARE", **params
            )
            _row_matches(effect, {
                "id": receipt["verification_id"],
                "engagement_id": expected_engagement_id,
                "flow_id": scope["flow_id"],
                "finding_id": receipt["finding_id"],
                "verdict_sha256": receipt["verdict_sha256"],
                "qualification_id": receipt["qualification_id"],
                "qualification_sha256": receipt["qualification_sha256"],
                "challenge_id": receipt["challenge_id"],
                "authorization_id": scope["authorization_id"],
                "authorization_version": scope["authorization_version"],
                "authorization_sha256": scope["authorization_sha256"],
                "flow_revision": scope["flow_revision"],
                "status": "VERIFIED",
                "independent_effect_verified": True,
                "finding_verified": True,
                "report_release_approved": False,
                "senior_reviewer_sub": claim["senior_sub"],
            })
            if (
                type(effect.get("verdict_expires_at")) is not int
                or now >= effect["verdict_expires_at"]
                or effect.get("resource_visibility") != "private"
                or effect.get("source_http_status") != 200
                or effect.get("target_http_status") != 200
                or effect.get("anonymous_http_status") not in (401, 403, 404)
                or _row_digest(effect) != effect.get("verdict_sha256")
            ):
                _deny()
            qualification = await _locked_row(
                db, "SELECT * FROM target_effect_qualification_attempts "
                "WHERE id=:qid AND engagement_id=:eng AND flow_id=:flow "
                "AND finding_id=:finding FOR SHARE",
                qid=receipt["qualification_id"], **params
            )
            _row_matches(qualification, {
                "id": receipt["qualification_id"],
                "attempt_sha256": receipt["qualification_sha256"],
                "revision": effect["qualification_revision"],
                "proof_sha256": effect["proof_sha256"],
                "review_decision_id": effect["review_decision_id"],
                "review_decision_sha256": effect["review_decision_sha256"],
                "status": "UNKNOWN", "independent_effect_verified": False,
                "finding_verified": False, "report_release_approved": False,
            })
            challenge_row = await _locked_row(
                db, "SELECT * FROM independent_target_effect_challenges "
                "WHERE id=:id AND engagement_id=:eng AND flow_id=:flow "
                "AND finding_id=:finding FOR SHARE",
                id=receipt["challenge_id"], **params
            )
            _row_matches(challenge_row, {
                "id": receipt["challenge_id"],
                "qualification_id": receipt["qualification_id"],
                "qualification_sha256": receipt["qualification_sha256"],
                "nonce_sha256": effect["verifier_nonce_sha256"],
            })
            if (
                type(challenge_row.get("issued_at")) is not int
                or type(challenge_row.get("expires_at")) is not int
                or not challenge_row["issued_at"] <= now < challenge_row["expires_at"]
                or challenge_row["expires_at"] > challenge_row["issued_at"] + 60
            ):
                _deny()
            witness_claim = _json(effect["signed_verdict_json"])
            if (
                type(witness_claim.get("nonce")) is not str
                or _digest(witness_claim["nonce"].encode("ascii"))
                != challenge_row["nonce_sha256"]
            ):
                _deny()
            challenge_issued[receipt["verification_id"]] = challenge_row["issued_at"]
            assertion = await _locked_row(
                db, "SELECT * FROM target_authority_assertions "
                "WHERE id=:id AND engagement_id=:eng AND flow_id=:flow FOR SHARE",
                id=receipt["target_owner_assertion_id"],
                eng=expected_engagement_id, flow=scope["flow_id"],
            )
            _row_matches(assertion, {
                "id": receipt["target_owner_assertion_id"],
                "proof_sha256": effect["proof_sha256"],
                "authorization_version": scope["authorization_version"],
                "flow_revision": scope["flow_revision"],
                "original_source_task_id": effect["original_source_task_id"],
                "source_task_id": effect["source_task_id"],
                "target_task_id": effect["target_task_id"],
            })
            nonce = await _locked_row(
                db, "SELECT * FROM target_authority_nonce_receipts "
                "WHERE id=:id AND engagement_id=:eng AND flow_id=:flow FOR SHARE",
                id=receipt["nonce_receipt_id"],
                eng=expected_engagement_id, flow=scope["flow_id"],
            )
            _row_matches(nonce, {
                "id": receipt["nonce_receipt_id"],
                "proof_sha256": assertion["proof_sha256"],
                "key_id": assertion["key_id"],
            })
            try:
                nonce_admission_digest = _digest(
                    (
                        expected_engagement_id + "\0" + scope["flow_id"] + "\0"
                        + nonce["key_id"] + "\0" + nonce["nonce_sha256"]
                    ).encode("utf-8")
                )
            except (KeyError, TypeError, UnicodeError) as exc:
                raise IndependentReleaseDenied("Target nonce origin invalid") from exc
            if (
                receipt["nonce_receipt_id"] != "tauth-" + nonce_admission_digest[:32]
                or not _valid_sha(nonce["nonce_sha256"])
                or nonce["nonce_sha256"] == challenge_row["nonce_sha256"]
                # Source admission nonce is independent of 0022's verifier
                # challenge; reusing one across operators is not authority.
            ):
                _deny()
            # Both these hashes are over exact immutable stored identities,
            # never untrusted user-provided source claims.
            assertion_sha = _digest(_canonical({
                "id": assertion["id"], "engagement_id": expected_engagement_id,
                "flow_id": scope["flow_id"], "proof_sha256": assertion["proof_sha256"],
                "key_id": assertion["key_id"],
                "authorization_version": assertion["authorization_version"],
                "flow_revision": assertion["flow_revision"],
                "original_source_task_id": assertion["original_source_task_id"],
                "source_task_id": assertion["source_task_id"],
                "target_task_id": assertion["target_task_id"],
            }))
            nonce_sha = _digest(_canonical({
                "id": nonce["id"], "engagement_id": expected_engagement_id,
                "flow_id": scope["flow_id"], "proof_sha256": nonce["proof_sha256"],
                "key_id": nonce["key_id"], "nonce_sha256": nonce["nonce_sha256"],
            }))
            if (
                assertion_sha != receipt["target_owner_assertion_sha256"]
                or nonce_sha != receipt["nonce_receipt_sha256"]
                or type(effect.get("signed_verdict_json")) is not bytes
                or type(effect.get("verdict_signature_b64url")) is not str
            ):
                _deny()
            registry, pinned_sha, registry_sha = _current_witness_trust(
                engagement_id=expected_engagement_id,
                flow_id=scope["flow_id"],
                signed_claims=effect["signed_verdict_json"],
                signed_signature=effect["verdict_signature_b64url"],
                challenge_issued_at=challenge_row["issued_at"],
            )
            owner_root = base64.b64decode(
                registry["owner_public_key_b64"], validate=True
            )
            if (
                owner_root not in trust.target_owner_keys
                or pinned_sha in {
                    _digest(root)
                    for root in (
                        trust.senior_public_key, trust.host_public_key,
                        *trust.report_signer_keys, *trust.provider_signer_keys,
                        *trust.target_owner_keys, *trust.replica_signer_roots.values(),
                    )
                }
            ):
                _deny()
            if (
                registry["observer_key_id"] != effect["verifier_key_id"]
                or registry["owner_key_id"] != assertion["key_id"]
                or pinned_sha != effect["verifier_public_key_sha256"]
                or registry_sha != effect["verifier_registry_sha256"]
            ):
                _deny()
        process_ids: set[str] = set()
        for replica in claim["replica_qualifications"]:
            key = trust.replica_signer_roots.get(replica["replica_id"])
            if type(key) is not bytes:
                _deny()
            enrolled_replica = await _locked_row(
                db, "SELECT * FROM independent_release_replica_key_enrollments "
                "WHERE replica_id=:replica AND tenant_id=:tenant FOR SHARE",
                replica=replica["replica_id"], tenant=scope["tenant_id"],
            )
            _row_matches(enrolled_replica, {
                "replica_id": replica["replica_id"],
                "tenant_id": scope["tenant_id"],
                "public_key_sha256": _digest(key),
                "status": "active", "revoked_at": None,
            })
            stored = await _locked_row(
                db, "SELECT * FROM independent_release_replica_qualifications "
                "WHERE id=:id AND tenant_id=:tenant AND engagement_id=:eng "
                "AND flow_id=:flow FOR SHARE",
                id=replica["qualification_id"], tenant=scope["tenant_id"],
                eng=expected_engagement_id, flow=scope["flow_id"],
            )
            _row_matches(stored, {
                "id": replica["qualification_id"],
                "replica_id": replica["replica_id"],
                "qualification_sha256": replica["qualification_sha256"],
                "run_receipt_id": replica["run_receipt_id"],
                "run_receipt_sha256": replica["run_receipt_sha256"],
                "signer_key_sha256": _digest(key), "status": "qualified",
                "revoked_at": None,
            })
            _signed_replica_receipt(stored, replica, claim, key, now)
            process = _json(stored["signed_receipt_json"])["process_identity_sha256"]
            if process in process_ids:
                _deny()
            process_ids.add(process)
            run_row = await _locked_row(
                db, "SELECT * FROM independent_release_qualification_run_receipts "
                "WHERE id=:id AND tenant_id=:tenant AND engagement_id=:eng "
                "AND flow_id=:flow FOR SHARE",
                id=replica["run_receipt_id"], tenant=scope["tenant_id"],
                eng=expected_engagement_id, flow=scope["flow_id"],
            )
            _row_matches(run_row, {
                "id": replica["run_receipt_id"],
                "replica_id": replica["replica_id"],
                "process_identity_sha256": process,
                "receipt_sha256": replica["run_receipt_sha256"],
                "status": "qualified",
                "revoked_at": None,
            })
            _validated_replica_run(
                run_row, replica, claim, process_identity_sha256=process
            )
        release = await _locked_row(
            db, "SELECT * FROM independent_senior_release_receipts "
            "WHERE id=:id AND tenant_id=:tenant AND engagement_id=:eng "
            "AND report_id=:report FOR SHARE",
            id=claim["release_receipt_id"], tenant=scope["tenant_id"],
            eng=expected_engagement_id, report=expected_report_id,
        )
        _row_matches(release, {
            "id": claim["release_receipt_id"],
            "receipt_sha256": claim["release_receipt_sha256"],
            "signed_claim_sha256": _digest(RELEASE_DOMAIN + _canonical(claim)),
            "attestation_sha256": report["attestation_sha256"],
            "senior_sub": claim["senior_sub"],
            "senior_key_sha256": _digest(trust.senior_public_key),
            "authorization_version": scope["authorization_version"],
            "authorization_sha256": scope["authorization_sha256"],
            "flow_revision": scope["flow_revision"],
            "status": "admitted", "revoked_at": None,
        })
        checked = await verify_independent_release_approval(
            signed_release_envelope, trust=trust, current_authority=current_authority,
            expected_engagement_id=expected_engagement_id,
            expected_report_id=expected_report_id,
            original_attestation_bytes=original_attestation_bytes,
            original_manifest_bytes=original_manifest_bytes,
            original_report_json_bytes=archived_artifacts["json"],
        )
        # A host check awaits remote I/O; refuse if independent authorization,
        # senior status or signed target witness trust changed during the await.
        refreshed = await guard_sql(
            db, expected_engagement_id,
            expected_version=scope["authorization_version"],
            expected_digest=scope["authorization_sha256"],
        )
        if (
            refreshed.session_id != expected_engagement_id
            or refreshed.authorization_id != scope["authorization_id"]
            or refreshed.version != scope["authorization_version"]
            or refreshed.policy_sha256 != scope["authorization_sha256"]
        ):
            _deny()
        for receipt in claim["target_owner_receipts"]:
            current = await _locked_row(
                db, "SELECT signed_verdict_json,verdict_signature_b64url,"
                "verifier_registry_sha256,verifier_public_key_sha256,"
                "verifier_key_id,verdict_expires_at FROM "
                "independent_target_effect_verifications WHERE id=:id "
                "AND engagement_id=:eng FOR SHARE",
                id=receipt["verification_id"], eng=expected_engagement_id,
            )
            if int(time.time()) >= current["verdict_expires_at"]:
                _deny()
            # Resolve current independent public key and nested owner signature
            # once more, as its key may have rotated during remote status I/O.
            registry, pinned_sha, registry_sha = _current_witness_trust(
                engagement_id=expected_engagement_id,
                flow_id=scope["flow_id"],
                signed_claims=current["signed_verdict_json"],
                signed_signature=current["verdict_signature_b64url"],
                challenge_issued_at=challenge_issued[receipt["verification_id"]],
            )
            if (
                pinned_sha != current["verifier_public_key_sha256"]
                or registry_sha != current["verifier_registry_sha256"]
                or registry["observer_key_id"] != current["verifier_key_id"]
            ):
                _deny()
        senior_now = await _locked_row(
            db, "SELECT actor_id,disabled FROM operator_subject_controls "
            "WHERE actor_id=:actor FOR SHARE", actor=claim["senior_sub"]
        )
        _row_matches(senior_now, {
            "actor_id": claim["senior_sub"], "disabled": False,
        })
        enrollment_now = await _locked_row(
            db, "SELECT * FROM independent_senior_release_key_enrollments "
            "WHERE key_id=:kid AND tenant_id=:tenant FOR SHARE",
            kid=trust.senior_key_id, tenant=scope["tenant_id"],
        )
        _row_matches(enrollment_now, {
            "senior_sub": claim["senior_sub"],
            "public_key_sha256": _digest(trust.senior_public_key),
            "status": "active", "revoked_at": None,
        })
        host_enrollment_now = await _locked_row(
            db, "SELECT * FROM independent_release_host_key_enrollments "
            "WHERE tenant_id=:tenant AND public_key_sha256=:sha FOR SHARE",
            tenant=scope["tenant_id"], sha=_digest(trust.host_public_key),
        )
        _row_matches(host_enrollment_now, {
            "public_key_sha256": _digest(trust.host_public_key),
            "status": "active", "revoked_at": None,
        })
        current_reporter_registry = _read_trusted_signers()
        if current_reporter_registry.get(details["signer_key_id"]) != current_reporter_key:
            _deny()
        for replica in claim["replica_qualifications"]:
            replica_enrollment_now = await _locked_row(
                db, "SELECT * FROM independent_release_replica_key_enrollments "
                "WHERE replica_id=:replica AND tenant_id=:tenant FOR SHARE",
                replica=replica["replica_id"], tenant=scope["tenant_id"],
            )
            _row_matches(replica_enrollment_now, {
                "replica_id": replica["replica_id"],
                "public_key_sha256": _digest(
                    trust.replica_signer_roots[replica["replica_id"]]
                ),
                "status": "active", "revoked_at": None,
            })
            stored_now = await _locked_row(
                db, "SELECT * FROM independent_release_replica_qualifications "
                "WHERE id=:id AND tenant_id=:tenant AND engagement_id=:eng "
                "AND flow_id=:flow FOR SHARE",
                id=replica["qualification_id"], tenant=scope["tenant_id"],
                eng=expected_engagement_id, flow=scope["flow_id"],
            )
            _row_matches(stored_now, {
                "id": replica["qualification_id"],
                "qualification_sha256": replica["qualification_sha256"],
                "signer_key_sha256": _digest(
                    trust.replica_signer_roots[replica["replica_id"]]
                ),
                "status": "qualified", "revoked_at": None,
            })
            _signed_replica_receipt(
                stored_now, replica, claim,
                trust.replica_signer_roots[replica["replica_id"]], int(time.time()),
            )
            process = _json(stored_now["signed_receipt_json"])[
                "process_identity_sha256"
            ]
            run_now = await _locked_row(
                db, "SELECT * FROM independent_release_qualification_run_receipts "
                "WHERE id=:id AND tenant_id=:tenant AND engagement_id=:eng "
                "AND flow_id=:flow FOR SHARE",
                id=replica["run_receipt_id"], tenant=scope["tenant_id"],
                eng=expected_engagement_id, flow=scope["flow_id"],
            )
            _row_matches(run_now, {
                "id": replica["run_receipt_id"],
                "process_identity_sha256": process,
                "receipt_sha256": replica["run_receipt_sha256"],
                "status": "qualified", "revoked_at": None,
            })
            _validated_replica_run(
                run_now, replica, claim, process_identity_sha256=process
            )
        release_now = await _locked_row(
            db, "SELECT * FROM independent_senior_release_receipts "
            "WHERE id=:id AND tenant_id=:tenant AND engagement_id=:eng "
            "AND report_id=:report FOR SHARE",
            id=claim["release_receipt_id"], tenant=scope["tenant_id"],
            eng=expected_engagement_id, report=expected_report_id,
        )
        _row_matches(release_now, {
            "id": claim["release_receipt_id"],
            "receipt_sha256": claim["release_receipt_sha256"],
            "signed_claim_sha256": checked["claim_sha256"],
            "status": "admitted", "revoked_at": None,
        })
        return {
            **checked,
            "status": "read_only_current_release_ledger_join_verified",
            "production_certificate_issued": False,
            "ledger_effects_checked": len(claim["target_owner_receipts"]),
            "ledger_replicas_checked": len(process_ids),
        }
    except IndependentReleaseDenied:
        raise
    except Exception as exc:
        raise IndependentReleaseDenied("Current signed release ledger unavailable") from exc
