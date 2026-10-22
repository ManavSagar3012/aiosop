"""Opt-in host-side READ-ONLY original Browser custody + CURRENT authority join.

The mounted native endpoint proves *provider-local* original-file SHA metadata,
but never returns the original bytes. An independent host-owned byte reader and
a separately enrolled custodian signer MUST be installed; no fallback to
provider metadata, local paths, or a model/provider assertion is permitted.

Unregistered by design. The host must install this bridge in a privileged
read-only reconciliation service, NOT the native provider or target workflow.
The result cannot certify target effects, reporting, or another navigation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any, Awaitable, Callable, Mapping, Optional

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ai_osop.memory.browser_source_authority import DOMAIN as SOURCE_DOMAIN, _CLAIM_FIELDS
from ai_osop.orchestrator.browser_current_authority_readback import (
    EVIDENCE_DOMAIN,
    _EVIDENCE_FIELDS,
    _provider_roots,
    _roots,
    _verify,
    verify_current_browser_authority,
)

_CUSTODY_DOMAIN = b"ai-osop/browser-host-readonly-original-custody/v1\x00"
_CENTRAL_PATH = "/native-browser/current-authority/readback"
_NATIVE_PATH = "/mcp/request/evidence/readback"
_BINDING = ("request_id", "engagement_id", "task_id", "server_id")
_IDENTITY = (
    "request_id",
    "engagement_id",
    "flow_id",
    "task_id",
    "subtask_id",
    "action_id",
    "owner_id",
    "preflight_id",
    "authorization_sha256",
    "original_intent_sha256",
    "url_sha256",
)
_ARTIFACTS = {
    "screenshot": ("png", 4 * 1024 * 1024),
    "dom": ("html", 1024 * 1024),
    "har": ("har", 4 * 1024 * 1024),
}
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
_MAX_BODY = 16384
_CUSTODY_FIELDS = frozenset(
    {
        "version",
        "request_id",
        "engagement_id",
        "flow_id",
        "task_id",
        "subtask_id",
        "action_id",
        "owner_id",
        "preflight_id",
        "authorization_sha256",
        "original_intent_sha256",
        "evidence_attestation_sha256",
        "first_current_sha256",
        "last_current_sha256",
        "artifacts_sha256",
        "checked_at",
        "expires_at",
        "original_bytes_read",
        "target_effect_verified",
        "automatic_retry_authorized",
        "purpose",
    }
)

# Both callables must be installed by a separately trusted host custody
# service. The byte reader MUST open the originals itself, not consult a
# provider-supplied path or report precomputed hashes.
OriginalReader = Callable[
    [Mapping[str, str], Mapping[str, Mapping[str, Any]]],
    Awaitable[Mapping[str, bytes]],
]
CustodySigner = Callable[[Mapping[str, Any]], Awaitable[Mapping[str, Any]]]


class BrowserOriginalBridgeDenied(RuntimeError):
    """No owner-backed, current signed read-only custody proof available."""


def _deny() -> None:
    raise BrowserOriginalBridgeDenied("Original Browser host custody join UNKNOWN")


def _canonical(value: Any, limit: int = 8192) -> bytes:
    try:
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
        if not 2 <= len(raw) <= limit:
            _deny()
        return raw
    except (ValueError, TypeError, OverflowError, UnicodeError, RecursionError) as exc:
        raise BrowserOriginalBridgeDenied("Original Browser custody identity invalid") from exc


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _deny()
        result[key] = value
    return result


def _not_number(value: str) -> Any:
    _deny()


def _safe_origin(client: httpx.AsyncClient) -> None:
    url = client.base_url
    # Only a preconfigured HTTPS endpoint or numeric loopback host can receive
    # dedicated service credentials. Never let provider data select the URL.
    if (
        url.username
        or url.password
        or url.query
        or url.fragment
        or url.path not in ("", "/")
        or not (
            url.scheme == "https" or (url.scheme == "http" and url.host in ("127.0.0.1", "::1"))
        )
    ):
        _deny()


def _root(raw: Mapping[str, bytes], kid: str) -> bytes:
    if type(kid) is not str or not _KID.fullmatch(kid) or kid not in raw:
        _deny()
    value = raw[kid]
    if type(value) is not bytes or len(value) != 32:
        _deny()
    return value


def _external_roots(roots: Mapping[str, bytes]) -> dict[str, bytes]:
    if type(roots) is not dict or not 1 <= len(roots) <= 16:
        _deny()
    result = {_kid: _root(roots, _kid) for _kid in roots}
    try:
        source = _roots("OSOP_BROWSER_SOURCE_TRUSTED_PUBLIC_KEYS_JSON")
        central = _roots("OSOP_BROWSER_CURRENT_AUTHORITY_TRUSTED_PUBLIC_KEYS_JSON")
        native = _provider_roots()
    except Exception as exc:
        raise BrowserOriginalBridgeDenied("Independent enrolled Browser roots unavailable") from exc
    if set(result.values()) & (set(source.values()) | set(central.values()) | set(native.values())):
        _deny()
    return result


def _verify_custody(
    envelope: Mapping[str, Any],
    roots: Mapping[str, bytes],
    expected: Mapping[str, Any],
) -> dict[str, Any]:
    if (
        type(envelope) is not dict
        or set(envelope) != {"claims", "kid", "signature"}
        or type(envelope["claims"]) is not dict
        or set(envelope["claims"]) != _CUSTODY_FIELDS
    ):
        _deny()
    kid, sig = envelope["kid"], envelope["signature"]
    if type(sig) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{86}", sig):
        _deny()
    try:
        binary = base64.urlsafe_b64decode(sig + "==")
        if len(binary) != 64 or base64.urlsafe_b64encode(binary).decode("ascii").rstrip("=") != sig:
            _deny()
        Ed25519PublicKey.from_public_bytes(_root(roots, kid)).verify(
            binary, _CUSTODY_DOMAIN + _canonical(envelope["claims"])
        )
    except BrowserOriginalBridgeDenied:
        raise
    except Exception as exc:
        raise BrowserOriginalBridgeDenied("Independent custody signature invalid") from exc
    claims = envelope["claims"]
    now = int(time.time())
    if (
        claims != expected
        or type(claims["checked_at"]) is not int
        or type(claims["expires_at"]) is not int
        or not now - 2 <= claims["checked_at"] <= now
        or not now < claims["expires_at"] <= claims["checked_at"] + 5
        or claims["original_bytes_read"] is not True
        or claims["target_effect_verified"] is not False
        or claims["automatic_retry_authorized"] is not False
        or claims["purpose"] != "host_readonly_original_custody"
    ):
        _deny()
    return dict(claims)


async def _bounded_json(
    client: httpx.AsyncClient,
    path: str,
    body: dict[str, Any],
    bearer: str,
) -> dict[str, Any]:
    try:
        if len(_canonical(body, 12288)) > 12288:
            _deny()
        async with client.stream(
            "POST",
            path,
            json=body,
            headers={
                "authorization": "Bearer " + bearer,
                "content-type": "application/json",
                "accept": "application/json",
            },
            follow_redirects=False,
            timeout=6.0,
        ) as response:
            if (
                response.status_code != 200
                or response.headers.get("content-type", "").split(";", 1)[0] != "application/json"
            ):
                _deny()
            reported = response.headers.get("content-length")
            if reported is not None and (not reported.isdecimal() or int(reported) > _MAX_BODY):
                _deny()
            data = bytearray()
            async for chunk in response.aiter_bytes():
                if len(chunk) > _MAX_BODY - len(data):
                    _deny()
                data.extend(chunk)
        decoded = json.loads(
            data.decode("utf-8", "strict"),
            object_pairs_hook=_unique,
            parse_constant=_not_number,
            parse_float=_not_number,
        )
        if type(decoded) is not dict:
            _deny()
        return decoded
    except BrowserOriginalBridgeDenied:
        raise
    except (
        httpx.HTTPError,
        ValueError,
        TypeError,
        UnicodeError,
        RecursionError,
        OverflowError,
    ) as exc:
        raise BrowserOriginalBridgeDenied("Browser host original readback unavailable") from exc


def _manifest(evidence: Mapping[str, Any], binding: Mapping[str, str]) -> dict[str, dict[str, Any]]:
    if (
        type(evidence) is not dict
        or set(evidence) != {"claims", "kid", "signature"}
        or type(evidence["claims"]) is not dict
        or set(evidence["claims"]) != _EVIDENCE_FIELDS
    ):
        _deny()
    try:
        verified = _verify(evidence, _provider_roots(), EVIDENCE_DOMAIN, _EVIDENCE_FIELDS)
        if (
            verified["evidence_mode"] != "screenshot_dom_har"
            or verified["version"] != 1
            or verified["server_id"] != "browser-mcp"
            or any(verified[name] != binding[name] for name in _BINDING)
            or type(verified["issued_at"]) is not int
            or not 0 <= int(time.time()) - verified["issued_at"] <= 120
            or type(verified["artifacts"]) is not dict
            or set(verified["artifacts"]) != set(_ARTIFACTS)
        ):
            _deny()
        artifacts: dict[str, dict[str, Any]] = {}
        for name, (extension, max_size) in _ARTIFACTS.items():
            item = verified["artifacts"][name]
            if (
                type(item) is not dict
                or set(item) != {"path", "sha256", "size_bytes"}
                or type(item["path"]) is not str
                or not re.fullmatch(r"captures/[0-9a-f]{32}\." + extension, item["path"])
                or type(item["sha256"]) is not str
                or not _SHA.fullmatch(item["sha256"])
                or type(item["size_bytes"]) is not int
                or not 0 < item["size_bytes"] <= max_size
            ):
                _deny()
            artifacts[name] = dict(item)
        return artifacts
    except BrowserOriginalBridgeDenied:
        raise
    except Exception as exc:
        raise BrowserOriginalBridgeDenied("Original native evidence signature unavailable") from exc


def _match_native(
    response: dict[str, Any], binding: Mapping[str, str], manifest: Mapping[str, Mapping[str, Any]]
) -> None:
    if type(response) is not dict or set(response) != {"request_id", "status", "result"}:
        _deny()
    data = response["result"]
    if (
        response["request_id"] != binding["request_id"]
        or response["status"] != "success"
        or type(data) is not dict
        or set(data)
        != set(_BINDING)
        | {
            "status",
            "provider_signed_evidence_currently_matches",
            "current_authorization_verified",
            "independent_target_effect_verified",
            "safe_to_automatically_retry",
            "artifacts",
        }
        or any(data[k] != binding[k] for k in _BINDING)
        or data["status"] != "current_provider_local_original_bytes_match"
        or data["provider_signed_evidence_currently_matches"] is not True
        or data["current_authorization_verified"] is not False
        or data["independent_target_effect_verified"] is not False
        or data["safe_to_automatically_retry"] is not False
        or data["artifacts"] != manifest
    ):
        _deny()


def _match_central(
    response: dict[str, Any],
    expected: Mapping[str, str],
    source: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    if (
        type(response) is not dict
        or set(response)
        != {
            "status",
            "authority_proof",
            "original_browser_artifact_bytes_verified",
            "independent_target_effect_verified",
            "automatic_retry_authorized",
            "production_release_certified",
        }
        or response["status"] != "current_central_authority_only"
        or response["original_browser_artifact_bytes_verified"] is not False
        or response["independent_target_effect_verified"] is not False
        or response["automatic_retry_authorized"] is not False
        or response["production_release_certified"] is not False
    ):
        _deny()
    try:
        claims = verify_current_browser_authority(response["authority_proof"], expected)
        if (
            claims["source_claims_sha256"]
            != hashlib.sha256(_canonical(source["claims"])).hexdigest()
            or claims["evidence_attestation_sha256"]
            != hashlib.sha256(_canonical(evidence, 4096)).hexdigest()
            or claims["authorization_sha256"] != expected["authorization_sha256"]
            or claims["original_intent_sha256"] != expected["original_intent_sha256"]
        ):
            _deny()
        return claims
    except BrowserOriginalBridgeDenied:
        raise
    except Exception as exc:
        raise BrowserOriginalBridgeDenied(
            "Signed central CURRENT Browser authority unavailable"
        ) from exc


class NativeBrowserCurrentOriginalBridge:
    """Explicitly host-mounted, no-network-by-default READ ONLY custody bridge.

    The injected clients must be provisioned with independent TLS CA/pins by
    host configuration. The external reader must independently open provider
    originals and the external signer is a *separate* enrolled host issuer.
    This class has no path to original execution, settlement or target effects.
    """

    def __init__(
        self,
        *,
        enabled: bool = False,
        central_client: Optional[httpx.AsyncClient] = None,
        provider_client: Optional[httpx.AsyncClient] = None,
        central_bearer: str = "",
        provider_bearer: str = "",
        original_reader: Optional[OriginalReader] = None,
        independent_signer: Optional[CustodySigner] = None,
        independent_roots: Optional[Mapping[str, bytes]] = None,
    ) -> None:
        self.enabled = enabled
        self.central_client = central_client
        self.provider_client = provider_client
        self.central_bearer = central_bearer
        self.provider_bearer = provider_bearer
        self.original_reader = original_reader
        self.independent_signer = independent_signer
        self.independent_roots = independent_roots

    async def join(
        self,
        source: Mapping[str, Any],
        evidence: Mapping[str, Any],
        expected: Mapping[str, str],
    ) -> dict[str, Any]:
        # Deny before touching any network or reader if opt-in enrollment is
        # missing. Nothing on the native provider can turn this gate on.
        if (
            self.enabled is not True
            or self.central_client is None
            or self.provider_client is None
            or not callable(self.original_reader)
            or not callable(self.independent_signer)
            or self.independent_roots is None
            or type(self.central_bearer) is not str
            or type(self.provider_bearer) is not str
            or any(
                not 32 <= len(b) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in b)
                for b in (self.central_bearer, self.provider_bearer)
            )
            or hmac.compare_digest(self.central_bearer, self.provider_bearer)
        ):
            _deny()
        _safe_origin(self.central_client)
        _safe_origin(self.provider_client)
        roots = _external_roots(self.independent_roots)
        if (
            type(expected) is not dict
            or set(expected) != set(_IDENTITY)
            or any(type(v) is not str or not v for v in expected.values())
            or type(source) is not dict
            or type(source.get("claims")) is not dict
        ):
            _deny()
        src = source["claims"]
        if (
            src.get("owner_id") != expected["owner_id"]
            or src.get("flow_id") != expected["flow_id"]
            or src.get("engagement_id") != expected["engagement_id"]
            or src.get("subtask_id") != expected["subtask_id"]
            or src.get("preflight_id") != expected["preflight_id"]
            or src.get("url_sha256") != expected["url_sha256"]
            or src.get("authorization_sha256") != expected["authorization_sha256"]
            or any(
                src.get(name) != expected[name] for name in ("request_id", "task_id", "action_id")
            )
        ):
            _deny()
        # Trust the *enrolled central source issuer*, never source text.
        try:
            verified_source = _verify(
                source,
                _roots("OSOP_BROWSER_SOURCE_TRUSTED_PUBLIC_KEYS_JSON"),
                SOURCE_DOMAIN,
                _CLAIM_FIELDS,
            )
            if (
                verified_source["server_id"] != "browser-mcp"
                or verified_source["evidence_mode"] != "screenshot_dom_har"
                or verified_source["tool_name"] != "execute"
            ):
                _deny()
        except BrowserOriginalBridgeDenied:
            raise
        except Exception as exc:
            raise BrowserOriginalBridgeDenied("Original source signer unavailable") from exc
        binding = {name: src[name] for name in _BINDING}
        manifest = _manifest(evidence, binding)
        attested = evidence["claims"]
        if (
            attested["source_preflight_id"] != expected["preflight_id"]
            or attested["action_id"] != expected["action_id"]
            or attested["authorization_sha256"] != expected["authorization_sha256"]
        ):
            _deny()

        async def current() -> dict[str, Any]:
            response = await _bounded_json(
                self.central_client,
                _CENTRAL_PATH,
                {"source_proof": source, "provider_evidence": evidence},
                self.central_bearer,
            )
            return _match_central(response, expected, source, evidence)

        async def native() -> None:
            response = await _bounded_json(
                self.provider_client,
                _NATIVE_PATH,
                binding,
                self.provider_bearer,
            )
            _match_native(response, binding, manifest)

        # Central-before -> provider-before -> host-owned *real original bytes*
        # -> provider-after -> central-after. No retry on loss of ACK.
        first = await current()
        await native()
        try:
            originals = await self.original_reader(binding, manifest)
        except Exception as exc:
            raise BrowserOriginalBridgeDenied("Independent original-byte read unavailable") from exc
        if type(originals) is not dict or set(originals) != set(_ARTIFACTS):
            _deny()
        for name, (_, size) in _ARTIFACTS.items():
            raw = originals[name]
            if (
                type(raw) is not bytes
                or not 0 < len(raw) <= size
                or len(raw) != manifest[name]["size_bytes"]
                or not hmac.compare_digest(
                    hashlib.sha256(raw).hexdigest(), manifest[name]["sha256"]
                )
            ):
                _deny()
        # No original bytes are retained on self, returned, logged or given to
        # the external signer; only independently recomputed SHA metadata.
        await native()
        last = await current()
        if (
            first["request_id"] != last["request_id"]
            or any(first[name] != last[name] for name in _IDENTITY)
            or first["evidence_attestation_sha256"] != last["evidence_attestation_sha256"]
            or first["source_claims_sha256"] != last["source_claims_sha256"]
        ):
            _deny()
        now = int(time.time())
        if now >= first["expires_at"] or now >= last["expires_at"]:
            _deny()
        claims = {
            "version": 1,
            **{name: expected[name] for name in _IDENTITY if name not in {"url_sha256"}},
            "evidence_attestation_sha256": last["evidence_attestation_sha256"],
            "first_current_sha256": hashlib.sha256(_canonical(first)).hexdigest(),
            "last_current_sha256": hashlib.sha256(_canonical(last)).hexdigest(),
            "artifacts_sha256": hashlib.sha256(_canonical(manifest)).hexdigest(),
            "checked_at": now,
            "expires_at": now + 5,
            "original_bytes_read": True,
            "target_effect_verified": False,
            "automatic_retry_authorized": False,
            "purpose": "host_readonly_original_custody",
        }
        try:
            envelope = await self.independent_signer(claims)
        except Exception as exc:
            raise BrowserOriginalBridgeDenied(
                "Independent host custody signer unavailable"
            ) from exc
        verified = _verify_custody(envelope, roots, claims)
        if int(time.time()) >= min(first["expires_at"], last["expires_at"]):
            _deny()
        return {
            "status": "host_original_bytes_current_read_only",
            "custody_proof": dict(envelope),
            "custody_claims": verified,
            "artifacts": {name: dict(value) for name, value in manifest.items()},
            "independent_target_effect_verified": False,
            "automatic_retry_authorized": False,
            "production_release_certified": False,
        }
