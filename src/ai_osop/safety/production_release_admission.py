"""Host-wiring-only, read-only production release admission preflight.

No endpoint mounts this module. It neither issues/accepts untrusted roots nor
owns a signer, provider client, target client, vault or durable write. A release
must be independently signed by a separately enrolled senior and *freshly*
verified against original report bytes, 0016/0021/0022 owner/effect evidence,
and the current host/replica/one-use release ledgers. An ambiguous lost ACK,
replay, database outage, or absent independent authority is DENIED.

An admitted *read-only* decision is not a permission to dispatch, download,
publish, consume, or sign anything. Actual one-use release execution requires
an independent durable compare-and-swap operation not supplied here.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

from ai_osop.reporting.attested_storage import (
    AttestedStorageUnavailable,
    _read_trusted_file,
    load_attested_bundle,
    validated_report_id,
    verify_loaded_bundle,
)
from ai_osop.safety.independent_release_authority import (
    IndependentReleaseDenied,
    PinnedHostCurrentAuthority,
    PinnedReleaseTrust,
    RELEASE_DOMAIN,
    _canonical,
    _digest,
    _json,
    _validate_release_claim,
    _verify_signature,
    verify_current_release_ledger_join,
)


class ProductionReleaseDenied(PermissionError):
    """No independently current, original-byte bound production admission."""


def _deny() -> None:
    raise ProductionReleaseDenied("Production release admission unavailable")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class ReadOnlyReleaseAdmission:
    """Describes a verified *read*, NEVER an approval or release capability."""

    status: str
    engagement_id: str
    report_id: str
    claim_sha256: str
    attestation_sha256: str
    manifest_sha256: str
    release_receipt_id: str
    admission_generation: int
    independent_effects_checked: int
    replica_qualifications_checked: int
    production_certificate_issued: bool = False
    grants_release_execution: bool = False
    consumes_release_receipt: bool = False


def _trust_current(trust: PinnedReleaseTrust) -> tuple[str, PinnedReleaseTrust]:
    """Pin a copy of separately supplied PUBLIC roots across awaited checks."""
    if type(trust) is not PinnedReleaseTrust:
        _deny()
    try:
        roots = trust.replica_signer_roots
        if type(roots) is not dict or len(roots) < 2:
            _deny()
        copied = PinnedReleaseTrust(
            senior_key_id=trust.senior_key_id,
            senior_public_key=trust.senior_public_key,
            host_public_key=trust.host_public_key,
            report_signer_keys=trust.report_signer_keys,
            provider_signer_keys=trust.provider_signer_keys,
            target_owner_keys=trust.target_owner_keys,
            replica_signer_roots=dict(roots),
        )
        value = {
            "senior_key_id": copied.senior_key_id,
            "senior_key_sha256": _sha(copied.senior_public_key),
            "host_key_sha256": _sha(copied.host_public_key),
            "report_roots": sorted(_sha(key) for key in copied.report_signer_keys),
            "provider_roots": sorted(_sha(key) for key in copied.provider_signer_keys),
            "owner_roots": sorted(_sha(key) for key in copied.target_owner_keys),
            "replicas": {
                name: _sha(key) for name, key in sorted(copied.replica_signer_roots.items())
            },
        }
        return _digest(_canonical(value)), copied
    except (IndependentReleaseDenied, ValueError, TypeError, KeyError) as exc:
        raise ProductionReleaseDenied("Current external release roots invalid") from exc


def _raw_originals(
    engagement_id: str, report_id: str
) -> tuple[dict[str, Any], bytes, bytes]:
    """Retrieve original bytes from the SAME configured protected report root.

    The storage loader's parsed JSON alone loses whitespace/key ordering and
    cannot prove original manifest SHA. Independent report signer secrets are
    neither read nor referenced here.
    """
    if not validated_report_id(engagement_id, report_id):
        _deny()
    loaded = load_attested_bundle(engagement_id, report_id)
    configured = os.environ.get("OSOP_ATTESTED_REPORT_ROOT", "")
    if not configured or not os.path.isabs(configured):
        _deny()
    root = Path(configured)
    folder = root / engagement_id
    if (
        not root.is_dir()
        or root.is_symlink()
        or not folder.is_dir()
        or folder.is_symlink()
        or folder.resolve().parent != root.resolve()
    ):
        _deny()
    attestation = _read_trusted_file(folder / f"{report_id}.attestation", 65_536)
    manifest = _read_trusted_file(folder / f"{report_id}.manifest", 16_384)
    if (
        not hmac.compare_digest(_sha(attestation), loaded["attestation_sha256"])
        or not hmac.compare_digest(_sha(manifest), loaded["manifest_sha256"])
        or _json(attestation) != loaded["attestation"]
        or _json(manifest) != loaded["manifest"]
    ):
        _deny()
    return loaded, attestation, manifest


def _current_certificate(
    raw_envelope: bytes, trust: PinnedReleaseTrust, now: int
) -> dict[str, Any]:
    """Validate detached senior signature before any durable read or host I/O."""
    signed = _json(raw_envelope)
    if not hmac.compare_digest(_canonical(signed), raw_envelope):
        _deny()
    claim = _verify_signature(signed, trust.senior_public_key, domain=RELEASE_DOMAIN)
    _validate_release_claim(claim, trust.senior_key_id, now)
    # No empty report/target effect can become 'production verified' merely
    # because a valid senior key signed a structurally valid claim.
    if not claim["target_owner_receipts"]:
        _deny()
    return claim


async def _one_use_ack_fence(
    db: Any, claim: Mapping[str, Any], expected_claim_sha: str,
    *, previous_generation: Optional[int] = None
) -> int:
    """Read-only durable finality+replay fence; unknown ACK is a denial.

    This references *future* release ledger fields and therefore denies in
    current production until reviewed migrations and an independent atomic
    admission producer are installed. A read never consumes or issues a grant.
    """
    from sqlalchemy import text

    scope, report = claim["scope"], claim["report"]
    row = (
        await db.execute(
            text(
                "SELECT * FROM independent_senior_release_receipts "
                "WHERE id=:receipt AND engagement_id=:eng AND tenant_id=:tenant "
                "AND report_id=:report FOR SHARE"
            ),
            {
                "receipt": claim["release_receipt_id"],
                "eng": report["engagement_id"],
                "tenant": scope["tenant_id"],
                "report": report["report_id"],
            },
        )
    ).mappings().one_or_none()
    if not isinstance(row, Mapping):
        _deny()
    row = dict(row)
    expected = {
        "id": claim["release_receipt_id"],
        "engagement_id": report["engagement_id"],
        "tenant_id": scope["tenant_id"],
        "report_id": report["report_id"],
        "receipt_sha256": claim["release_receipt_sha256"],
        "signed_claim_sha256": expected_claim_sha,
        "attestation_sha256": report["attestation_sha256"],
        "manifest_sha256": report["manifest_sha256"],
        "authorization_id": scope["authorization_id"],
        "authorization_version": scope["authorization_version"],
        "authorization_sha256": scope["authorization_sha256"],
        "flow_id": scope["flow_id"],
        "flow_revision": scope["flow_revision"],
        "senior_sub": claim["senior_sub"],
        "senior_key_id": claim["senior_key_id"],
        "status": "admitted",
        "commit_status": "committed",
        "ack_status": "confirmed",
        "revoked_at": None,
        "consumed_at": None,
        "replayed_at": None,
        "rollback_at": None,
    }
    if any(
        key not in row or type(row[key]) is not type(value) or row[key] != value
        for key, value in expected.items()
    ):
        _deny()
    generation = row.get("admission_generation")
    if (
        type(generation) is not int
        or generation <= 0
        or (previous_generation is not None and generation != previous_generation)
    ):
        _deny()
    committed_at = row.get("committed_at")
    if type(committed_at) is not int or not 0 < committed_at <= int(time.time()):
        _deny()
    return generation


class ProductionReleaseAdmission:
    """For a privileged, separate host only. Never mount in the application.

    The caller must supply a real PostgreSQL AsyncSession *already in its
    transaction*, a genuinely independently enrolled PUBLIC trust registry,
    a protected independently hosted current-authority HTTPS client and
    authorized original evidence bytes (not model/provider assertions).
    """

    async def qualify_read_only(
        self,
        *,
        db: Any,
        trust: PinnedReleaseTrust,
        current_authority: PinnedHostCurrentAuthority,
        signed_senior_envelope: bytes,
        engagement_id: str,
        report_id: str,
        evidence_by_finding: Mapping[str, Any],
    ) -> ReadOnlyReleaseAdmission:
        if (
            type(self) is not ProductionReleaseAdmission
            or type(current_authority) is not PinnedHostCurrentAuthority
            or db is None
            or not callable(getattr(db, "execute", None))
            or not callable(getattr(db, "in_transaction", None))
            or db.in_transaction() is not True
            or not isinstance(evidence_by_finding, Mapping)
            or not validated_report_id(engagement_id, report_id)
        ):
            _deny()
        # Transaction/session must be PostgreSQL, not a mock/SQLite adapter
        # accidentally accepted as an authoritative release ledger.
        bind = None
        try:
            get_bind = getattr(db, "get_bind", None)
            bind = get_bind() if callable(get_bind) else getattr(db, "bind", None)
            if getattr(getattr(bind, "dialect", None), "name", None) != "postgresql":
                _deny()
            trust_sha, pinned_trust = _trust_current(trust)
            claim = _current_certificate(signed_senior_envelope, pinned_trust, int(time.time()))
            if (
                claim["report"]["engagement_id"] != engagement_id
                or claim["report"]["report_id"] != report_id
                or claim["scope"]["tenant_id"] != engagement_id
                or not evidence_by_finding
                or set(evidence_by_finding) != {
                    item["finding_id"] for item in claim["target_owner_receipts"]
                }
            ):
                _deny()
            loaded, original_attestation, original_manifest = _raw_originals(
                engagement_id, report_id
            )
            checked = verify_loaded_bundle(
                loaded, session_id=engagement_id, report_id=report_id,
                evidence_by_finding=evidence_by_finding,
            )
            if (
                loaded["attestation"]["attestation"].get("schema")
                != "ai-osop-report-attestation-v3"
                or checked["release_status"] != "generation_binding_pending_verification"
                or checked["verification"]["source_authenticity_verified"] is not False
                or checked["verification"]["operator_approved"] is not False
            ):
                _deny()
            original = claim["report"]
            if (
                not hmac.compare_digest(_sha(original_attestation), original["attestation_sha256"])
                or not hmac.compare_digest(_sha(original_manifest), original["manifest_sha256"])
                or not hmac.compare_digest(
                    _sha(loaded["artifacts"]["json"]), original["report_json_sha256"]
                )
            ):
                _deny()
            claim_sha = _digest(RELEASE_DOMAIN + _canonical(claim))
            generation = await _one_use_ack_fence(db, claim, claim_sha)
            verified = await verify_current_release_ledger_join(
                signed_senior_envelope,
                db=db,
                trust=pinned_trust,
                current_authority=current_authority,
                expected_engagement_id=engagement_id,
                expected_report_id=report_id,
                original_attestation_bytes=original_attestation,
                original_manifest_bytes=original_manifest,
                archived_artifacts=loaded["artifacts"],
                evidence_by_finding=evidence_by_finding,
            )
            if (
                type(verified) is not dict
                or verified.get("status") != "read_only_current_release_ledger_join_verified"
                or verified.get("claim_sha256") != claim_sha
                or verified.get("senior_key_id") != pinned_trust.senior_key_id
                or verified.get("release_receipt_id") != claim["release_receipt_id"]
                or verified.get("engagement_id") != engagement_id
                or verified.get("report_id") != report_id
                or verified.get("production_certificate_issued") is not False
                or type(verified.get("ledger_effects_checked")) is not int
                or verified["ledger_effects_checked"] != len(claim["target_owner_receipts"])
                or type(verified.get("ledger_replicas_checked")) is not int
                or verified["ledger_replicas_checked"] != len(claim["replica_qualifications"])
            ):
                _deny()
            # Remote host awaits can race filesystem replacement, trust-root
            # rotation, key revocation or an ACK-loss/rollback. Recheck all
            # original bytes and immutable ledger finality before returning.
            current, attestation_now, manifest_now = _raw_originals(
                engagement_id, report_id
            )
            if (
                _sha(attestation_now) != _sha(original_attestation)
                or _sha(manifest_now) != _sha(original_manifest)
                or any(
                    current["artifacts"][kind] != loaded["artifacts"][kind]
                    for kind in ("md", "html", "graph.html", "json")
                )
                or _trust_current(trust)[0] != trust_sha
                or int(time.time()) >= claim["expires_at"]
            ):
                _deny()
            final_snapshot = verify_loaded_bundle(
                current, session_id=engagement_id, report_id=report_id,
                evidence_by_finding=evidence_by_finding,
            )
            if final_snapshot.get("release_status") != "generation_binding_pending_verification":
                _deny()
            if await _one_use_ack_fence(
                db, claim, claim_sha, previous_generation=generation
            ) != generation:
                _deny()
            return ReadOnlyReleaseAdmission(
                status="current_signed_release_readback_verified_not_executable",
                engagement_id=engagement_id,
                report_id=report_id,
                claim_sha256=claim_sha,
                attestation_sha256=original["attestation_sha256"],
                manifest_sha256=original["manifest_sha256"],
                release_receipt_id=claim["release_receipt_id"],
                admission_generation=generation,
                independent_effects_checked=verified["ledger_effects_checked"],
                replica_qualifications_checked=verified["ledger_replicas_checked"],
            )
        except ProductionReleaseDenied:
            raise
        except Exception as exc:
            # Network, current registry, SQL adapter and host callback failures
            # all deny; never allow an unhandled provider/DB error to be
            # interpreted as an implicitly admissible release.
            raise ProductionReleaseDenied(
                "Current independent production release unavailable"
            ) from exc


async def qualify_production_release_read_only(**kwargs: Any) -> ReadOnlyReleaseAdmission:
    """Unmounted convenience facade; all authorization remains in the class."""
    return await ProductionReleaseAdmission().qualify_read_only(**kwargs)
