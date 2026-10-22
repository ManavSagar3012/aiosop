"""Detached Ed25519 attestation of report bytes and persisted evidence snapshots.

Signatures establish a trusted signer's assertion about *these bytes*. They do
not establish exploit success, evidence source authenticity, operational scope,
report approval, or completeness of an underlying graph query. Verification
must be performed with independently provisioned trusted public keys and raw
evidence retrieved through an authorized, independent channel.
"""

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "ai-osop-report-attestation-v1"
SCHEMA_V2 = "ai-osop-report-attestation-v2"
SCHEMA_V3 = "ai-osop-report-attestation-v3"
PROVENANCE_ALLOWLIST = frozenset({"validated_engagement_graph"})
ARTIFACT_ALLOWLIST = frozenset({"md", "html", "graph.html", "json"})
_IDENTIFIER = re.compile(r"^[a-zA-Z0-9_.-]{1,128}$")
_KEY_ID = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ReportAttestationError(ValueError):
    """The attestation is unsafe, unverifiable, or not trusted."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ReportAttestationError("Attestation contains noncanonical content") from exc


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _unique_object_pairs(pairs: list) -> Dict[str, Any]:
    """Deny JSON duplicate keys that different independent readers interpret differently."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate report JSON field")
        result[key] = value
    return result


def hash_evidence_snapshot(evidence: Any) -> str:
    """Deterministic hash of the *retrieved raw evidence* (never sample text)."""
    if not isinstance(evidence, list) or not evidence or len(evidence) > 256:
        raise ReportAttestationError("Evidence snapshot is missing or unbounded")
    if not all(isinstance(entry, dict) and entry for entry in evidence):
        raise ReportAttestationError("Evidence snapshot is malformed")
    return _digest(_canonical(evidence))


def _read_trusted_signers(raw: Optional[str] = None) -> Dict[str, bytes]:
    """Allowlist is provisioned separately, never embedded in an attestation."""
    text = raw if raw is not None else os.environ.get("OSOP_REPORT_TRUSTED_ED25519_KEYS_JSON", "")
    if not text or len(text) > 16384:
        raise ReportAttestationError("Trusted report signers are not configured")
    try:
        decoded = json.loads(text)
        if not isinstance(decoded, dict) or not 1 <= len(decoded) <= 32:
            raise ValueError()
        trusted = {}
        for kid, encoded in decoded.items():
            if not isinstance(kid, str) or not _KEY_ID.fullmatch(kid):
                raise ValueError()
            if not isinstance(encoded, str) or len(encoded) > 128:
                raise ValueError()
            raw_key = base64.b64decode(encoded, validate=True)
            if len(raw_key) != 32:
                raise ValueError()
            Ed25519PublicKey.from_public_bytes(raw_key)
            trusted[kid] = raw_key
        return trusted
    except (ValueError, TypeError, UnicodeError, binascii.Error) as exc:
        raise ReportAttestationError("Trusted report signer configuration is invalid") from exc


def load_signer(signer_key_id: str) -> Ed25519PrivateKey:
    """Load configured private signer; reject unknown key ID or mismatched key."""
    if not isinstance(signer_key_id, str) or not _KEY_ID.fullmatch(signer_key_id):
        raise ReportAttestationError("A trusted signer key ID is required")
    trusted = _read_trusted_signers()
    key_path = os.environ.get("OSOP_REPORT_SIGNING_KEY_FILE", "")
    if signer_key_id not in trusted or not key_path:
        raise ReportAttestationError("Trusted report signing key unavailable")
    try:
        path = Path(key_path)
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 16384:
            raise ValueError()
        private = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(private, Ed25519PrivateKey):
            raise ValueError()
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if not hmac.compare_digest(public, trusted[signer_key_id]):
            raise ValueError()
        return private
    except (OSError, TypeError, ValueError) as exc:
        raise ReportAttestationError("Trusted report signing key unavailable") from exc


def _validate_finding_provenance(provenance: Any) -> list:
    if not isinstance(provenance, list) or len(provenance) > 200:
        raise ReportAttestationError("Attested evidence provenance is not bounded")
    ids = set()
    ordered = []
    for entry in provenance:
        if not isinstance(entry, dict) or set(entry) != {
            "finding_id",
            "source_type",
            "evidence_sha256",
        }:
            raise ReportAttestationError("Unrecognized evidence provenance fields")
        finding_id = entry["finding_id"]
        if (
            not isinstance(finding_id, str)
            or not _IDENTIFIER.fullmatch(finding_id)
            or finding_id in ids
            or not isinstance(entry["source_type"], str)
            or entry["source_type"] not in PROVENANCE_ALLOWLIST
            or not isinstance(entry["evidence_sha256"], str)
            or not _SHA256.fullmatch(entry["evidence_sha256"])
        ):
            raise ReportAttestationError("Evidence provenance is not trusted or unique")
        ids.add(finding_id)
        ordered.append(dict(entry))
    if ordered != sorted(ordered, key=lambda item: item["finding_id"]):
        raise ReportAttestationError("Evidence provenance is not canonical")
    return ordered


def _validated_generation_binding(binding: Any) -> Dict[str, Any]:
    """Bind a generator Task/ROE, optionally to its immutable Flow revision."""
    common = {
        "task_id", "authorization_version", "authorization_sha256", "task_payload_sha256",
    }
    with_flow = common | {"flow_id", "flow_revision"}
    if not isinstance(binding, Mapping) or frozenset(binding) not in {
        frozenset(common), frozenset(with_flow),
    }:
        raise ReportAttestationError("Report generation binding is missing or malformed")
    if (
        not isinstance(binding["task_id"], str)
        or not _IDENTIFIER.fullmatch(binding["task_id"])
        or type(binding["authorization_version"]) is not int
        or binding["authorization_version"] <= 0
        or not isinstance(binding["authorization_sha256"], str)
        or not _SHA256.fullmatch(binding["authorization_sha256"])
        or not isinstance(binding["task_payload_sha256"], str)
        or not _SHA256.fullmatch(binding["task_payload_sha256"])
    ):
        raise ReportAttestationError("Report generation binding is invalid")
    if set(binding) == with_flow and (
        not isinstance(binding["flow_id"], str)
        or not _IDENTIFIER.fullmatch(binding["flow_id"])
        or not binding["flow_id"].startswith("flow-")
        or type(binding["flow_revision"]) is not int
        or binding["flow_revision"] < 0
    ):
        raise ReportAttestationError("Report generation Flow binding is invalid")
    return dict(binding)


def _check_report_evidence_bindings(
    report_blob: bytes, provenance: list, *, engagement_id: str,
    strict: bool = False,
) -> None:
    """Assert report JSON contains exactly the evidence this signature covers."""
    try:
        report = json.loads(
            report_blob.decode("utf-8"), object_pairs_hook=_unique_object_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite report field")),
        )
        if not isinstance(report, dict):
            raise ValueError()
        if ("engagement_id" in report and report["engagement_id"] != engagement_id) or (
            strict and report.get("engagement_id") != engagement_id
        ):
            raise ValueError()
        if strict and report.get("requires_approval") is not True:
            raise ValueError()
        # Integrity signing is never an operator sign-off or evidence-source
        # certification. Refuse content that asserts otherwise via known
        # machine-readable report fields, even if a trusted key signs it.
        if any(report.get(flag) is True for flag in (
            "operator_approved", "report_approved", "certified",
            "exploit_success_verified", "source_authenticity_verified",
            "completeness_verified", "production_ready",
        )):
            raise ValueError()
        if strict and report.get("verification_status") not in {
            "verified_findings_only", "no_verified_findings",
        }:
            raise ValueError()
        findings = report["findings"]
        if strict and (len(findings) == 0) != (
            report["verification_status"] == "no_verified_findings"
        ):
            raise ValueError()
        if not isinstance(findings, list) or len(findings) > 200:
            raise ValueError()
        report_digests = {}
        for finding in findings:
            fid, digest = finding["id"], finding["evidence_hash"]
            if (
                not isinstance(fid, str)
                or not _IDENTIFIER.fullmatch(fid)
                or fid in report_digests
                or not isinstance(digest, str)
                or not _SHA256.fullmatch(digest)
            ):
                raise ValueError()
            report_digests[fid] = digest
    except (ValueError, KeyError, TypeError, UnicodeError) as exc:
        raise ReportAttestationError("Signed report evidence references are invalid") from exc
    if report_digests != {item["finding_id"]: item["evidence_sha256"] for item in provenance}:
        raise ReportAttestationError("Signed report finding evidence does not match")


def _build_payload(
    *,
    engagement_id: str,
    report_id: str,
    signer_key_id: str,
    artifacts: Mapping[str, bytes],
    provenance: list,
    generation_binding: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    if not isinstance(engagement_id, str) or not _IDENTIFIER.fullmatch(engagement_id):
        raise ReportAttestationError("Unsafe attestation engagement ID")
    if not isinstance(report_id, str) or not _IDENTIFIER.fullmatch(report_id):
        raise ReportAttestationError("Unsafe attestation report ID")
    if not isinstance(signer_key_id, str) or not _KEY_ID.fullmatch(signer_key_id):
        raise ReportAttestationError("Trusted signer key ID required")
    if set(artifacts) != ARTIFACT_ALLOWLIST:
        raise ReportAttestationError("Signed artifact set is incomplete or unknown")
    digests = {}
    for extension, value in artifacts.items():
        if not isinstance(value, bytes) or len(value) > 8 * 1024 * 1024:
            raise ReportAttestationError("Artifact bytes are missing or unbounded")
        digests[extension] = _digest(value)
    validated = _validate_finding_provenance(provenance)
    bound = _validated_generation_binding(generation_binding) if generation_binding is not None else None
    _check_report_evidence_bindings(
        artifacts["json"], validated, engagement_id=engagement_id,
        strict=bound is not None,
    )
    payload = {
        "schema": (
            SCHEMA_V3 if bound is not None and "flow_id" in bound
            else SCHEMA_V2 if bound is not None else SCHEMA
        ),
        "algorithm": "Ed25519",
        "signer_key_id": signer_key_id,
        "engagement_id": engagement_id,
        "report_id": report_id,
        "artifacts": digests,
        "evidence_provenance": validated,
        "attestation_scope": {
            "record_validation": "graph_validated_flag_only",
            "exploit_success_verified": False,
            "source_authenticity_verified": False,
            "operator_approved": False,
            "completeness_verified": False,
        },
    }
    if bound is not None:
        payload["generation_binding"] = bound
    return payload


def sign_report_attestation(
    *,
    engagement_id: str,
    report_id: str,
    signer_key_id: str,
    artifacts: Mapping[str, bytes],
    evidence_provenance: list,
    generation_binding: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Sign a draft; bind Task/ROE (v2) or Task/ROE/Flow revision (v3).

    Signing alone attests to neither Task completion nor current authorization.
    Release checks must independently validate signed references in PostgreSQL.
    """
    payload = _build_payload(
        engagement_id=engagement_id,
        report_id=report_id,
        signer_key_id=signer_key_id,
        artifacts=artifacts,
        provenance=evidence_provenance,
        generation_binding=generation_binding,
    )
    private = load_signer(signer_key_id)
    signature = private.sign(_canonical(payload))
    return {
        "attestation": payload,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def _strict_envelope(envelope: Any) -> Dict[str, Any]:
    if not isinstance(envelope, dict) or set(envelope) != {"attestation", "signature"}:
        raise ReportAttestationError("Signed report envelope is malformed")
    payload = envelope["attestation"]
    common = {
        "schema",
        "algorithm",
        "signer_key_id",
        "engagement_id",
        "report_id",
        "artifacts",
        "evidence_provenance",
        "attestation_scope",
    }
    if not isinstance(payload, dict):
        raise ReportAttestationError("Signed report metadata is malformed")
    if payload.get("schema") == SCHEMA:
        expected = common
    elif payload.get("schema") == SCHEMA_V2:
        expected = common | {"generation_binding"}
        if set(_validated_generation_binding(payload.get("generation_binding"))) != {
            "task_id", "authorization_version", "authorization_sha256", "task_payload_sha256",
        }:
            raise ReportAttestationError("V2 report cannot claim a Flow binding")
    elif payload.get("schema") == SCHEMA_V3:
        expected = common | {"generation_binding"}
        if "flow_id" not in _validated_generation_binding(payload.get("generation_binding")):
            raise ReportAttestationError("V3 report requires a Flow binding")
    else:
        raise ReportAttestationError("Signed report algorithm or version is unsupported")
    if set(payload) != expected:
        raise ReportAttestationError("Signed report metadata is malformed")
    if payload["algorithm"] != "Ed25519":
        raise ReportAttestationError("Signed report algorithm or version is unsupported")
    if payload["attestation_scope"] != {
        "record_validation": "graph_validated_flag_only",
        "exploit_success_verified": False,
        "source_authenticity_verified": False,
        "operator_approved": False,
        "completeness_verified": False,
    }:
        raise ReportAttestationError("Signed report overstates evidence assurance")
    return payload


def verify_report_attestation(
    envelope: Mapping[str, Any],
    *,
    artifacts: Mapping[str, bytes],
    evidence_by_finding: Mapping[str, Any],
    trusted_public_keys: Optional[Mapping[str, bytes]] = None,
) -> Dict[str, Any]:
    """Independently check detached signature, artifacts, and raw evidence.

    ``trusted_public_keys`` must be provided out of band, or loaded from the
    local trusted key allowlist. Evidence must be independently retrieved and
    supplied as an exact mapping by finding ID. Never trust signer keys or raw
    evidence supplied *inside* the signed document.
    """
    payload = _strict_envelope(envelope)
    kid = payload["signer_key_id"]
    keys = trusted_public_keys if trusted_public_keys is not None else _read_trusted_signers()
    if not isinstance(kid, str) or not _KEY_ID.fullmatch(kid) or kid not in keys:
        raise ReportAttestationError("Report signer is not trusted")
    public = keys[kid]
    if not isinstance(public, bytes) or len(public) != 32:
        raise ReportAttestationError("Trusted report verifier key unavailable")
    signature = envelope["signature"]
    if (
        not isinstance(signature, str)
        or len(signature) != 86
        or not re.fullmatch(r"[A-Za-z0-9_-]{86}", signature)
    ):
        raise ReportAttestationError("Report signature encoding is invalid")
    try:
        raw_signature = base64.urlsafe_b64decode(signature + "==")
        if (
            len(raw_signature) != 64
            or base64.urlsafe_b64encode(raw_signature).decode().rstrip("=") != signature
        ):
            raise ValueError()
        Ed25519PublicKey.from_public_bytes(public).verify(raw_signature, _canonical(payload))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ReportAttestationError("Report signature verification failed") from exc

    expected = _build_payload(
        engagement_id=payload["engagement_id"],
        report_id=payload["report_id"],
        signer_key_id=kid,
        artifacts=artifacts,
        provenance=payload["evidence_provenance"],
        generation_binding=payload.get("generation_binding"),
    )
    if _canonical(payload) != _canonical(expected):
        raise ReportAttestationError("Signed report artifact bytes differ")

    claimed = payload["evidence_provenance"]
    if not isinstance(evidence_by_finding, Mapping) or set(evidence_by_finding) != {
        item["finding_id"] for item in claimed
    }:
        raise ReportAttestationError("Independent evidence set does not match signed report")
    for item in claimed:
        if not hmac.compare_digest(
            item["evidence_sha256"], hash_evidence_snapshot(evidence_by_finding[item["finding_id"]])
        ):
            raise ReportAttestationError("Independent evidence bytes differ")

    _check_report_evidence_bindings(
        artifacts["json"], claimed, engagement_id=payload["engagement_id"],
        strict=payload["schema"] in {SCHEMA_V2, SCHEMA_V3},
    )
    return {
        "status": "signature_and_snapshot_verified",
        "report_id": payload["report_id"],
        "engagement_id": payload["engagement_id"],
        "signer_key_id": kid,
        "evidence_records_checked": len(claimed),
        "source_authenticity_verified": False,
        "operator_approved": False,
        "exploit_success_verified": False,
    }


def verify_report_files(
    report_paths: Mapping[str, str],
    *,
    evidence_by_finding: Mapping[str, Any],
    trusted_public_keys: Optional[Mapping[str, bytes]] = None,
) -> Dict[str, Any]:
    """Independently verify persisted report paths, including the manifest."""
    if set(report_paths) != ARTIFACT_ALLOWLIST | {"manifest", "attestation"}:
        raise ReportAttestationError("Report bundle is incomplete")

    def read_bounded_file(raw_path: str, limit: int) -> bytes:
        # This entry point is also used by offline independent verifiers.
        # Enforce byte limits before buffering and reject filesystem links.
        if not isinstance(raw_path, str):
            raise ReportAttestationError("Report artifact path is invalid")
        path = Path(raw_path)
        if path.is_symlink():
            raise ReportAttestationError("Report artifact path is invalid")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            file_stat = os.fstat(stream.fileno())
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > limit:
                raise ReportAttestationError("Report artifact exceeds safe size")
            content = stream.read(limit + 1)
        if len(content) > limit:
            raise ReportAttestationError("Report artifact exceeds safe size")
        return content

    try:
        artifacts = {
            key: read_bounded_file(report_paths[key], 8 * 1024 * 1024)
            for key in ARTIFACT_ALLOWLIST
        }
        manifest_bytes = read_bounded_file(report_paths["manifest"], 16384)
        envelope_bytes = read_bounded_file(report_paths["attestation"], 65536)
        manifest = json.loads(
            manifest_bytes, object_pairs_hook=_unique_object_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite manifest")),
        )
        envelope = json.loads(
            envelope_bytes, object_pairs_hook=_unique_object_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite envelope")),
        )
    except (OSError, ValueError, TypeError, UnicodeError, ReportAttestationError) as exc:
        raise ReportAttestationError("Report bundle could not be read safely") from exc
    checked = verify_report_attestation(
        envelope,
        artifacts=artifacts,
        evidence_by_finding=evidence_by_finding,
        trusted_public_keys=trusted_public_keys,
    )
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "engagement_id",
            "report_id",
            "hash_algorithm",
            "signature_status",
            "artifacts",
            "attestation_sha256",
        }
        or manifest["hash_algorithm"] != "sha256"
        or manifest["signature_status"] != "ed25519_signed"
    ):
        raise ReportAttestationError("Signed report manifest is malformed")
    if (
        manifest["engagement_id"] != checked["engagement_id"]
        or manifest["report_id"] != checked["report_id"]
        or manifest["artifacts"] != envelope["attestation"]["artifacts"]
        or manifest["attestation_sha256"] != _digest(envelope_bytes)
    ):
        raise ReportAttestationError("Signed report manifest has been modified")
    return checked
