"""Opt-in operator entry point for independent Browser original-byte custody.

This module intentionally does not install a host reader, signing key, MCP
connection, or mounted route. The integrator must configure a separate host
custodian and its already-enrolled trust roots. Request bodies identify an
original request only: provider testimony and arbitrary file paths are never
accepted as HTTP inputs.

The existing bridge performs central signed CURRENT ROE/Flow/Task readback,
provider original readback, independently read original bytes, then rechecks
both authorities before accepting a distinct signed host custody witness.
Neither this entry point nor that witness settles UNKNOWN target effects.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from ai_osop.adapters.native_browser_current_original_bridge import (
    BrowserOriginalBridgeDenied,
    NativeBrowserCurrentOriginalBridge,
    _IDENTITY,
)
from ai_osop.api.deps import require_role
from ai_osop.memory.browser_source_authority import BrowserSourceDenied, exact_origin

_REQUEST_ID = re.compile(r"req-[a-f0-9]{48}\Z")
_ENGAGEMENT_ID = re.compile(r"eng-[A-Za-z0-9._:@-]{1,75}\Z")
_MAX_BODY = 512
_PATH = "/system/browser/custody/readback"
_HOST_SLOT = "_independently_host_enrolled_browser_original_20261022"


@dataclass(frozen=True)
class OriginalBrowserHostRecord:
    """Resolved from a host-controlled immutable ledger, never an API body.

    original_uri is the complete original request URI from the trusted host
    record; source_proof and provider_evidence are original signed envelopes.
    expected includes current Flow/Task/ROE owner, token and original-intent
    SHA identities. The bridge verifies all of these against central CURRENT.
    """

    original_uri: str
    source_proof: Mapping[str, Any]
    provider_evidence: Mapping[str, Any]
    expected: Mapping[str, str]


OriginalBrowserHostResolver = Callable[
    [str, str, str], Awaitable[OriginalBrowserHostRecord]
]


def _unverified(reason: str) -> dict[str, Any]:
    return {
        "status": "UNVERIFIED",
        "reason": reason,
        "current_original_artifact_bytes_verified": False,
        "independent_target_effect_verified": False,
        "automatic_retry_authorized": False,
        "production_release_certified": False,
    }


def _fail(reason: str, *, status_code: int = 503) -> None:
    raise HTTPException(
        status_code=status_code,
        detail=_unverified(reason),
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate Browser request member")
        result[key] = value
    return result


async def _parse_request(request: Request) -> tuple[str, str]:
    if request.scope.get("query_string"):
        _fail("OPERATOR_QUERY_FORBIDDEN", status_code=403)
    if (
        request.url.scheme != "https"
        and (
            request.url.scheme != "http"
            or getattr(request.client, "host", None) not in {"127.0.0.1", "::1"}
        )
    ):
        _fail("INDEPENDENT_TRANSPORT_UNVERIFIED", status_code=403)
    if sum(k.lower() == b"authorization" for k, _ in request.scope.get("headers", [])) != 1:
        _fail("OPERATOR_BEARER_REQUIRED", status_code=401)
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        _fail("INVALID_OPERATOR_REQUEST", status_code=415)
    data = bytearray()
    async for chunk in request.stream():
        if len(chunk) > _MAX_BODY - len(data):
            _fail("INVALID_OPERATOR_REQUEST", status_code=413)
        data.extend(chunk)
    try:
        decoded = json.loads(
            data.decode("utf-8", "strict"),
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            parse_float=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        _fail("INVALID_OPERATOR_REQUEST", status_code=422)
    if (
        type(decoded) is not dict
        or set(decoded) != {"request_id", "engagement_id"}
        or type(decoded["request_id"]) is not str
        or _REQUEST_ID.fullmatch(decoded["request_id"]) is None
        or type(decoded["engagement_id"]) is not str
        or _ENGAGEMENT_ID.fullmatch(decoded["engagement_id"]) is None
    ):
        _fail("INVALID_OPERATOR_REQUEST", status_code=422)
    return decoded["engagement_id"], decoded["request_id"]


class BrowserCurrentCustodyReadback:
    """Explicit host configuration for one bounded operator read operation."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        independent_host_enrolled: bool = False,
        bridge: Optional[NativeBrowserCurrentOriginalBridge] = None,
        host_record_resolver: Optional[OriginalBrowserHostResolver] = None,
    ) -> None:
        self.enabled = enabled
        self.independent_host_enrolled = independent_host_enrolled
        self.bridge = bridge
        self.host_record_resolver = host_record_resolver

    async def readback(
        self, engagement_id: str, request_id: str, actor_id: str
    ) -> dict[str, Any]:
        # An opt-in flag alone does not establish host custody independence.
        if (
            self.enabled is not True
            or self.independent_host_enrolled is not True
            or not isinstance(self.bridge, NativeBrowserCurrentOriginalBridge)
            or self.bridge.enabled is not True
            or not callable(self.host_record_resolver)
            or not callable(self.bridge.original_reader)
            or not callable(self.bridge.independent_signer)
            or self.bridge.independent_roots is None
        ):
            return _unverified("INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED")

        try:
            record = await self.host_record_resolver(engagement_id, request_id, actor_id)
        except Exception:
            return _unverified("ORIGINAL_HOST_RECORD_UNAVAILABLE")
        if not isinstance(record, OriginalBrowserHostRecord):
            return _unverified("ORIGINAL_HOST_RECORD_UNVERIFIED")
        expected = record.expected
        source = record.source_proof
        # Compare the original full URI, not merely the URL origin, against
        # the signed original hash. No caller-selected URI is ever fetched.
        if (
            type(record.original_uri) is not str
            or not 1 <= len(record.original_uri) <= 2048
            or type(expected) is not dict
            or set(expected) != set(_IDENTITY)
            or any(type(value) is not str or not value for value in expected.values())
            or expected["engagement_id"] != engagement_id
            or expected["request_id"] != request_id
            or type(source) is not dict
            or type(source.get("claims")) is not dict
        ):
            return _unverified("ORIGINAL_HOST_IDENTITY_MISMATCH")
        claims = source["claims"]
        try:
            uri_sha = hashlib.sha256(record.original_uri.encode("utf-8")).hexdigest()
            origin = exact_origin(record.original_uri)
            if (
                not hmac.compare_digest(uri_sha, expected["url_sha256"])
                or claims.get("url_sha256") != uri_sha
                or claims.get("origin") != origin
                or any(claims.get(name) != expected[name] for name in (
                    "request_id", "engagement_id", "flow_id", "task_id",
                    "subtask_id", "action_id", "owner_id", "preflight_id",
                    "authorization_sha256",
                ))
            ):
                return _unverified("ORIGINAL_HOST_IDENTITY_MISMATCH")
        except (BrowserSourceDenied, ValueError, TypeError, UnicodeError):
            return _unverified("ORIGINAL_HOST_IDENTITY_MISMATCH")
        try:
            result = await self.bridge.join(source, record.provider_evidence, expected)
        except BrowserOriginalBridgeDenied:
            return _unverified("CURRENT_ORIGINAL_CUSTODY_UNVERIFIED")
        except Exception:
            return _unverified("CURRENT_ORIGINAL_READBACK_UNAVAILABLE")
        if (
            type(result) is not dict
            or result.get("status") != "host_original_bytes_current_read_only"
            or result.get("independent_target_effect_verified") is not False
            or result.get("automatic_retry_authorized") is not False
            or result.get("production_release_certified") is not False
            or type(result.get("custody_proof")) is not dict
            or type(result.get("custody_claims")) is not dict
            or result["custody_claims"].get("original_bytes_read") is not True
        ):
            return _unverified("CURRENT_ORIGINAL_CUSTODY_UNVERIFIED")
        return {
            "status": "CURRENT_ORIGINAL_CUSTODY_VERIFIED",
            "current_original_artifact_bytes_verified": True,
            "independent_target_effect_verified": False,
            "automatic_retry_authorized": False,
            "production_release_certified": False,
            "custody_proof": result["custody_proof"],
            "artifacts": result["artifacts"],
        }


def install_host_browser_original_enrollment(app: Any, enrollment: Any) -> None:
    """Trusted host-only one-time installation for the *already mounted* route.

    The independent host enrolls actual raw HTTP + PNG/DOM/HAR and separate
    signing roots before the application begins serving requests. No route,
    environment option or client-supplied filename can install this service.
    No signer keys are generated by the API.
    """
    # Delayed import avoids a cycle: the host enrollment factory consumes
    # BrowserCurrentCustodyReadback to construct the four-original reader.
    from ai_osop.api.browser_host_original_enrollment_20261022 import (
        BrowserHostOriginalEnrollment,
    )

    app_state = getattr(app, "state", None)
    if (
        app_state is None
        or hasattr(app_state, _HOST_SLOT)
        or type(enrollment) is not BrowserHostOriginalEnrollment
    ):
        raise ValueError("Independent Browser original host enrollment required")
    service = enrollment.service()
    if (
        type(service) is not BrowserCurrentCustodyReadback
        or service.enabled is not True
        or service.independent_host_enrolled is not True
        or type(service.bridge) is not NativeBrowserCurrentOriginalBridge
        or service.bridge.enabled is not True
        or not callable(service.host_record_resolver)
    ):
        raise ValueError("Independent Browser original host enrollment unavailable")
    setattr(app_state, _HOST_SLOT, service)


def create_browser_current_custody_router(
    service: Optional[BrowserCurrentCustodyReadback] = None,
) -> APIRouter:
    """Prime may include this router after host enrollment; default is DENY."""
    active = service if service is not None else BrowserCurrentCustodyReadback()
    configured_router = APIRouter(tags=["browser-current-original-custody"])

    @configured_router.post(_PATH)
    async def operator_browser_custody_readback(
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
            _fail("SIGNED_SENIOR_OPERATOR_REQUIRED", status_code=403)
        # A separately qualified deployment may enroll immutable original
        # custody AFTER module import but before FastAPI lifespan. The route
        # was mounted once at app construction: never add duplicate routes or
        # replace original signer custody based on an HTTP request body.
        selected = (
            active
            if service is not None
            else getattr(request.app.state, _HOST_SLOT, active)
        )
        if type(selected) is not BrowserCurrentCustodyReadback:
            _fail("INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED")
        result = await selected.readback(engagement_id, request_id, operator["sub"])
        if result["status"] == "UNVERIFIED":
            _fail(result["reason"])
        return result

    return configured_router


# Mount-safe import for an unconfigured host. A production integrator must
# explicitly call create_browser_current_custody_router(configured_service).
router = create_browser_current_custody_router()
