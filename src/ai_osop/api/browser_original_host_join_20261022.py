"""Explicit, read-only four-original Browser host join for a senior operator.

This is a *mounted-ready* companion to the existing default-deny Browser
custody route, not a replacement for its central CURRENT/provenance service.
Host enrollment is externally provisioned: this file cannot mint a signer,
enroll keys, select files, start a Browser, or contact a target.

All four sealed originals are read twice by the existing enrolled host reader
(the fourth, raw HTTP, remains a distinct host-enrolled prerequisite). A
third central signed CURRENT read occurs *after* the final original-byte
read. No HTTP receipt is an independently signed target effect.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import threading
import time
from typing import Any, Awaitable, Callable, Optional
from weakref import WeakKeyDictionary

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response

from ai_osop.adapters.native_browser_current_original_bridge import (
    BrowserOriginalBridgeDenied,
    NativeBrowserCurrentOriginalBridge,
    _bounded_json,
    _canonical,
    _external_roots,
    _match_central,
    _safe_origin,
    _verify_custody,
)
from ai_osop.api.browser_current_custody_readback import (
    BrowserCurrentCustodyReadback,
    _parse_request,
)
from ai_osop.api.browser_host_original_enrollment_20261022 import (
    BrowserHostEnrollmentDenied,
    BrowserHostOriginalEnrollment,
)
from ai_osop.api.deps import require_role

PATH = "/system/browser/original-host/readback"
_CENTRAL_PATH = "/native-browser/current-authority/readback"
_KINDS = ("http_raw", "screenshot", "dom", "har")
_BRIDGE_KINDS = ("screenshot", "dom", "har")
_BINDING = ("request_id", "engagement_id", "task_id", "server_id")
_IDENTITY = (
    "engagement_id",
    "request_id",
    "flow_id",
    "task_id",
    "subtask_id",
    "action_id",
    "owner_id",
    "preflight_id",
    "authorization_sha256",
    "original_intent_sha256",
)
_HOST_JOIN_SLOT = "_osop_browser_original_host_join_20261022"
# One trusted Python-side installation per FastAPI app. A module-owned
# identity registry also prevents a later app.state overwrite from silently
# substituting another signed custodian for an already enrolled one.
_HOST_JOIN_INSTALL_LOCK = threading.Lock()
_INSTALLED_HOST_JOINS: WeakKeyDictionary[FastAPI, BrowserOriginalHostJoin] = WeakKeyDictionary()


class BrowserOriginalHostJoinDenied(RuntimeError):
    """Only bounded machine-classified denial escapes the operator route."""

    def __init__(self, reason: str = "CURRENT_HOST_ORIGINAL_UNVERIFIED") -> None:
        self.reason = reason
        super().__init__("Independent Browser original host join UNVERIFIED")


def _deny(reason: str = "CURRENT_HOST_ORIGINAL_UNVERIFIED") -> None:
    raise BrowserOriginalHostJoinDenied(reason)


def _unverified(reason: str) -> dict[str, Any]:
    return {
        "status": "UNVERIFIED",
        "reason": reason,
        "current_original_artifact_bytes_verified": False,
        "raw_http_original_bytes_verified": False,
        "independent_target_effect_verified": False,
        "automatic_retry_authorized": False,
        "production_release_certified": False,
    }


CancellationCheck = Callable[[], Awaitable[bool]]


async def _not_cancelled(check: Optional[CancellationCheck]) -> None:
    if check is not None:
        # Cancellation is a denial, not an authorization for a second POST.
        try:
            disconnected = await check()
        except asyncio.CancelledError:
            raise
        except Exception:
            _deny("ORIGINAL_HOST_REQUEST_CANCELLED")
        if disconnected is not False:
            _deny("ORIGINAL_HOST_REQUEST_CANCELLED")


class BrowserOriginalHostJoin:
    """Reconcile one pinned four-file host enrollment with fresh CURRENT.

    No service construction from a request body and no auto-retry. All current
    authority still comes from existing 0027/0034 read-only central/provider
    endpoints, not the host enrolment's own claims.
    """

    def __init__(
        self,
        enrollment: Optional[BrowserHostOriginalEnrollment] = None,
        *,
        enabled: bool = False,
    ) -> None:
        self._enrollment = enrollment
        self._enabled = enabled

    async def readback(
        self,
        engagement_id: str,
        request_id: str,
        actor_id: str,
        *,
        cancellation_check: Optional[CancellationCheck] = None,
    ) -> dict[str, Any]:
        if self._enabled is not True or type(self._enrollment) is not BrowserHostOriginalEnrollment:
            _deny("INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED")
        enrolled = self._enrollment
        await _not_cancelled(cancellation_check)
        try:
            # Always resolve the independently *signed* record before any
            # bridge network access. Snapshot exact source and enrollment,
            # because the trusted record map may change during awaits.
            original = await enrolled.host_record_resolver(engagement_id, request_id, actor_id)
            first, manifest = enrolled._admitted((engagement_id, request_id))
            if first != original:
                _deny()
            record = enrolled._records[(engagement_id, request_id)]
            enrollment_sha = hashlib.sha256(_canonical(record.signed_enrollment, 8192)).hexdigest()
            expected = dict(first.expected)
            source_sha = hashlib.sha256(_canonical(first.source_proof, 8192)).hexdigest()
            evidence_sha = hashlib.sha256(_canonical(first.provider_evidence, 4096)).hexdigest()
            bridge_service = enrolled.service()
            bridge = bridge_service.bridge
            if (
                bridge_service.enabled is not True
                or bridge_service.independent_host_enrolled is not True
                or bridge is None
                or bridge.enabled is not True
                or bridge.central_client is None
                or not isinstance(bridge.central_bearer, str)
            ):
                _deny("INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED")
            # Without genuinely installed source, CURRENT, provider and host
            # roots, fail before the first network read.
            _external_roots(enrolled._enrollment_roots)
            custodians = _external_roots(enrolled._custody_roots)
            original_enrollment_roots = dict(enrolled._enrollment_roots)
            original_custody_roots = dict(custodians)
            if set(enrolled._enrollment_roots.values()) & set(custodians.values()):
                _deny()
        except BrowserOriginalHostJoinDenied:
            raise
        except Exception:
            _deny("INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED")

        await _not_cancelled(cancellation_check)
        # Existing custody join: central CURRENT before and after, provider
        # before and after, exact host HTTP/PNG/DOM/HAR reader and signer
        # callback (itself rereads all four before signature).
        receipt = await bridge_service.readback(engagement_id, request_id, actor_id)
        await _not_cancelled(cancellation_check)
        if (
            type(receipt) is not dict
            or receipt.get("status") != "CURRENT_ORIGINAL_CUSTODY_VERIFIED"
            or receipt.get("current_original_artifact_bytes_verified") is not True
            or receipt.get("independent_target_effect_verified") is not False
            or receipt.get("automatic_retry_authorized") is not False
            or receipt.get("production_release_certified") is not False
            or set(receipt.get("artifacts", {})) != set(_BRIDGE_KINDS)
        ):
            _deny()
        try:
            proof = receipt["custody_proof"]
            claims = proof["claims"]
            verified = _verify_custody(proof, custodians, claims)
            if (
                any(verified.get(name) != expected[name] for name in _IDENTITY)
                or verified["original_bytes_read"] is not True
                or verified["target_effect_verified"] is not False
                or verified["automatic_retry_authorized"] is not False
                or not hmac.compare_digest(
                    verified["artifacts_sha256"],
                    hashlib.sha256(_canonical(receipt["artifacts"])).hexdigest(),
                )
                or any(receipt["artifacts"][name] != manifest[name] for name in _BRIDGE_KINDS)
            ):
                _deny()

            # Re-check four raw originals, without accepting paths/bytes from
            # the HTTP operator or using the Browser target.
            binding = {name: expected[name] for name in _BINDING if name != "server_id"}
            binding["server_id"] = "browser-mcp"
            last_bytes = await enrolled.original_reader(
                binding, {name: manifest[name] for name in _BRIDGE_KINDS}
            )
            await _not_cancelled(cancellation_check)
            if type(last_bytes) is not dict or set(last_bytes) != set(_BRIDGE_KINDS):
                _deny()
            for name in _BRIDGE_KINDS:
                raw = last_bytes[name]
                if (
                    type(raw) is not bytes
                    or len(raw) != manifest[name]["size_bytes"]
                    or not hmac.compare_digest(
                        hashlib.sha256(raw).hexdigest(), manifest[name]["sha256"]
                    )
                ):
                    _deny()
            # Third CURRENT read AFTER the final host-original read. It is
            # independently signed by central ROE/Flow/Task owner authority.
            _safe_origin(bridge.central_client)
            last_central = await _bounded_json(
                bridge.central_client,
                _CENTRAL_PATH,
                {"source_proof": first.source_proof, "provider_evidence": first.provider_evidence},
                bridge.central_bearer,
            )
            latest = _match_central(
                last_central, expected, first.source_proof, first.provider_evidence
            )
            await _not_cancelled(cancellation_check)

            # A concurrent host record/issuer revision or revoke denies. The
            # original typed URI and provider payloads must not be swapped.
            last, final_manifest = enrolled._admitted((engagement_id, request_id))
            current_record = enrolled._records[(engagement_id, request_id)]
            if (
                dict(_external_roots(enrolled._enrollment_roots)) != original_enrollment_roots
                or dict(_external_roots(enrolled._custody_roots)) != original_custody_roots
                or last != first
                or final_manifest != manifest
                or not hmac.compare_digest(
                    enrollment_sha,
                    hashlib.sha256(_canonical(current_record.signed_enrollment, 8192)).hexdigest(),
                )
                or not hmac.compare_digest(
                    source_sha, hashlib.sha256(_canonical(last.source_proof, 8192)).hexdigest()
                )
                or not hmac.compare_digest(
                    evidence_sha,
                    hashlib.sha256(_canonical(last.provider_evidence, 4096)).hexdigest(),
                )
                or any(latest.get(name) != expected[name] for name in _IDENTITY)
                or int(time.time()) >= min(verified["expires_at"], latest["expires_at"])
            ):
                _deny()
        except asyncio.CancelledError:
            raise
        except BrowserOriginalHostJoinDenied:
            raise
        except (BrowserHostEnrollmentDenied, BrowserOriginalBridgeDenied):
            _deny()
        except Exception:
            _deny()

        # Expose only safe digest/size metadata; no raw HTTP request bytes,
        # URLs, filesystem paths, tokens, or unsigned target-effect assertion.
        return {
            "status": "CURRENT_HOST_ORIGINAL_FOUR_DIGEST_READBACK",
            "engagement_id": engagement_id,
            "request_id": request_id,
            "host_enrollment_sha256": enrollment_sha,
            "custody_claims_sha256": hashlib.sha256(_canonical(verified)).hexdigest(),
            "artifacts": {
                name: {
                    "sha256": manifest[name]["sha256"],
                    "size_bytes": manifest[name]["size_bytes"],
                }
                for name in _KINDS
            },
            "current_original_artifact_bytes_verified": True,
            "raw_http_original_bytes_verified": True,
            "independent_target_effect_verified": False,
            "automatic_retry_authorized": False,
            "production_release_certified": False,
        }


def install_browser_original_host_join(app: Any, join: Any) -> None:
    """Host-only, single-use admission for a router mounted in DENY mode.

    Must be called from trusted Python bootstrap after the independent host
    enrolled actual four-file originals and provisioned separate roots, not
    from an HTTP endpoint/lifespan request payload. A failed attempt never
    marks the slot, and the successful binding cannot be replaced by calling
    this installer again, even with the same object.
    """
    if (
        not isinstance(app, FastAPI)
        or type(join) is not BrowserOriginalHostJoin
        or join._enabled is not True
        or type(join._enrollment) is not BrowserHostOriginalEnrollment
    ):
        raise ValueError("Independent Browser original host join required")
    enrollment = join._enrollment
    try:
        # Validate actual separately enrolled roots/signers, not the caller's
        # assertion that enabled=True. The typed default-deny service is an
        # intentionally invalid configuration.
        service = enrollment.service()
        bridge = service.bridge
        if (
            type(service) is not BrowserCurrentCustodyReadback
            or service.enabled is not True
            or service.independent_host_enrolled is not True
            or type(bridge) is not NativeBrowserCurrentOriginalBridge
            or bridge.enabled is not True
            or not callable(bridge.original_reader)
            or not callable(bridge.independent_signer)
            or not callable(service.host_record_resolver)
            or type(enrollment._records) is not dict
            or not 1 <= len(enrollment._records) <= 1024
        ):
            raise ValueError()
        # A manifest whose signer/identity is forged must not become the
        # mounted host. Admission is checked again on each readback.
        for key in tuple(enrollment._records):
            enrollment._admitted(key)
        # Never install against an absent or duplicated endpoint. This
        # requires prime to mount the default-deny route once beforehand.
        routes = [
            route
            for route in app.routes
            if getattr(route, "path", None) == PATH
            and "POST" in (getattr(route, "methods", None) or ())
        ]
        if (
            len(routes) != 1
            or getattr(routes[0].endpoint, "__module__", None) != __name__
            or getattr(routes[0].endpoint, "__qualname__", None)
            != "create_browser_original_host_join_router.<locals>.host_readback"
            or getattr(routes[0].endpoint, "_osop_default_deny_host_join", None) is not True
        ):
            raise ValueError()
    except Exception as exc:
        raise ValueError("Independent Browser original host join unavailable") from exc

    # The process-wide critical section guarantees check+insert atomicity
    # when distinct trusted bootstrap threads race. No setter/replacement
    # endpoint exists; no signer/key is generated or accepted over HTTP.
    with _HOST_JOIN_INSTALL_LOCK:
        if app in _INSTALLED_HOST_JOINS or hasattr(app.state, _HOST_JOIN_SLOT):
            raise ValueError("Independent Browser original host join already installed")
        setattr(app.state, _HOST_JOIN_SLOT, join)
        _INSTALLED_HOST_JOINS[app] = join


def create_browser_original_host_join_router(
    join: Optional[BrowserOriginalHostJoin] = None,
) -> APIRouter:
    """Mount once, default-deny; optional trusted host installer activates it."""
    router = APIRouter(tags=["browser-original-host-readonly"])

    @router.post(PATH)
    async def host_readback(
        request: Request,
        response: Response,
        operator: dict[str, Any] = Depends(require_role("senior_operator")),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        engagement_id, request_id = await _parse_request(request)
        if (
            type(operator.get("sub")) is not str
            or not operator["sub"]
            or type(operator.get("claims")) is not dict
        ):
            raise HTTPException(
                status_code=403, detail=_unverified("SIGNED_SENIOR_OPERATOR_REQUIRED")
            )
        # The default (no injected join) is resolved at request time, so an
        # independently provisioned host can install after router import
        # without creating a second FastAPI route. The separate identity
        # registry rejects an app.state value replaced behind the installer.
        if join is not None:
            selected = join
        else:
            selected = getattr(request.app.state, _HOST_JOIN_SLOT, None)
            with _HOST_JOIN_INSTALL_LOCK:
                installed = _INSTALLED_HOST_JOINS.get(request.app)
            if installed is None or selected is not installed:
                selected = None
        if (
            type(selected) is not BrowserOriginalHostJoin
            or selected._enabled is not True
            or type(selected._enrollment) is not BrowserHostOriginalEnrollment
        ):
            raise HTTPException(
                status_code=503,
                detail=_unverified("INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED"),
                headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
            )
        try:
            return await selected.readback(
                engagement_id,
                request_id,
                operator["sub"],
                cancellation_check=request.is_disconnected,
            )
        except asyncio.CancelledError:
            raise
        except BrowserOriginalHostJoinDenied as error:
            raise HTTPException(
                status_code=503,
                detail=_unverified(error.reason),
                headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
            ) from None

    # The host installer recognizes only the unconfigured default-deny mount.
    # A prebound join remains a separate explicit legacy integration mode,
    # never eligible for the one-time late host installer.
    setattr(host_readback, "_osop_default_deny_host_join", join is None)
    return router
