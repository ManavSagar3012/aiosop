"""Independent PostgreSQL admission for one original browser navigation.

This source is consulted by the native browser immediately before navigation.
Its receipt proves current central authorization at issuance, not the outcome
of a browser request. Failed ACKs and duplicated requests never reissue it.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import uuid
from typing import Any, Mapping
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from ai_osop.core.models import ScopeDefinition
from ai_osop.mcp.protocol import SideEffectClass
from ai_osop.memory.flow_mcp_action_dispatch import (
    FlowMCPActionStore,
    MCPActionDenied,
    _ACTION,
    _DIGEST_DOMAIN,
    _SHA,
    _binding,
    _digest,
    _safe_parameters,
)
from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets

DOMAIN = b"ai-osop/browser-source-preflight/v1\x00"
_REQUEST = re.compile(r"req-[a-f0-9]{48}\Z")
_KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
_ORIGIN_HOST = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}\Z")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_FIELDS = frozenset(
    {
        "request_id",
        "engagement_id",
        "task_id",
        "server_id",
        "tool_name",
        "action",
        "url_sha256",
        "origin",
        "user_label",
        "evidence_mode",
    }
)
_CLAIM_FIELDS = frozenset(
    {
        "version",
        "preflight_id",
        "request_id",
        "engagement_id",
        "flow_id",
        "task_id",
        "subtask_id",
        "action_id",
        "owner_id",
        "server_id",
        "tool_name",
        "action",
        "url_sha256",
        "origin",
        "user_label",
        "evidence_mode",
        "authorization_version",
        "authorization_sha256",
        "approval_id",
        "lease_id",
        "issued_at",
        "expires_at",
    }
)


class BrowserSourceDenied(MCPActionDenied):
    """A safely redacted source-authority denial."""


def _deny(code: int = 409) -> None:
    raise BrowserSourceDenied(code, "Current browser source admission unavailable")


def _canonical(value: Any) -> bytes:
    try:
        result = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (ValueError, TypeError, UnicodeError, OverflowError) as exc:
        raise BrowserSourceDenied(403, "Browser source claims invalid") from exc
    if len(result) > 4096:
        _deny(403)
    return result


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _signer() -> tuple[str, Ed25519PrivateKey]:
    """The trusted central issuer key is exclusively deployment supplied."""
    try:
        kid = os.environ["OSOP_BROWSER_SOURCE_SIGNING_KID"]
        encoded = os.environ["OSOP_BROWSER_SOURCE_SIGNING_PRIVATE_KEY_B64"]
        if type(kid) is not str or _KID.fullmatch(kid) is None:
            raise ValueError("kid")
        if type(encoded) is not str or not 43 <= len(encoded) <= 44:
            raise ValueError("key length")
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        if len(raw) != 32 or encoded not in {_b64url(raw), base64.b64encode(raw).decode("ascii")}:
            raise ValueError("key format")
        signer = Ed25519PrivateKey.from_private_bytes(raw)
        return kid, signer
    except (KeyError, ValueError, TypeError, base64.binascii.Error) as exc:
        raise BrowserSourceDenied(503, "Independent browser source signer unavailable") from exc


def exact_origin(url: Any) -> str:
    """Match the native browser's conservative canonical destination format."""
    if (
        type(url) is not str
        or not 8 <= len(url) <= 256
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in url)
        or "\\" in url
        or "?" in url
        or "#" in url
        or "@" in url
    ):
        _deny(403)
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        _deny(403)
    if (
        scheme not in {"http", "https"}
        or not host
        or _ORIGIN_HOST.fullmatch(host) is None
        or host.endswith(".")
        or ".." in host
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (scheme == "http" and host not in {"127.0.0.1", "localhost"})
        or (port is not None and not 1 <= port <= 65535)
    ):
        _deny(403)
    return f"{scheme}://{host}:{port or (443 if scheme == 'https' else 80)}"


def validate_request(value: Any) -> dict[str, str]:
    if type(value) is not dict or set(value) != _FIELDS:
        _deny(422)
    if (
        type(value["request_id"]) is not str
        or _REQUEST.fullmatch(value["request_id"]) is None
        or type(value["engagement_id"]) is not str
        or not re.fullmatch(r"eng-[A-Za-z0-9._:-]{1,60}", value["engagement_id"])
        or type(value["task_id"]) is not str
        or not re.fullmatch(r"task-[A-Za-z0-9._:-]{1,59}", value["task_id"])
        or type(value["url_sha256"]) is not str
        or _SHA.fullmatch(value["url_sha256"]) is None
        or value["server_id"] != "browser-mcp"
        or value["tool_name"] != "execute"
        or value["action"] != "navigate"
        or type(value["origin"]) is not str
        or not 8 <= len(value["origin"]) <= 260
        or type(value["user_label"]) is not str
        or _LABEL.fullmatch(value["user_label"]) is None
        or type(value["evidence_mode"]) is not str
        or value["evidence_mode"] not in {"none", "screenshot_dom_har"}
    ):
        _deny(422)
    if exact_origin(value["origin"]) != value["origin"]:
        _deny(422)
    return dict(value)


class BrowserSourceAuthorityStore:
    """One-time source admission locked to the original 0027 Action."""

    def __init__(self, actions: FlowMCPActionStore) -> None:
        if not isinstance(actions, FlowMCPActionStore):
            _deny(503)
        self.actions = actions

    @staticmethod
    async def _now(db: Any) -> int:
        result = (
            await db.execute(text("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint"))
        ).scalar_one()
        if type(result) is not int or result <= 0:
            _deny(503)
        return result

    @staticmethod
    def _original_intent(row: Mapping[str, Any]) -> None:
        binding = {
            "engagement_id": row["engagement_id"],
            "flow_id": row["flow_id"],
            "revision": row["flow_revision"],
            "version": row["authorization_version"],
            "authorization_id": row["authorization_id"],
            "authorization_sha256": row["authorization_sha256"],
        }
        intent = {
            **binding,
            **{
                name: row[name]
                for name in (
                    "task_id",
                    "subtask_id",
                    "action_id",
                    "owner_id",
                    "approval_id",
                    "lease_id",
                    "lease_owner_id",
                    "server_id",
                    "tool_name",
                    "side_effect_class",
                    "declaration_sha256",
                    "parameters_sha256",
                )
            },
        }
        if (
            row["intent_sha256"] != _digest(_DIGEST_DOMAIN, intent, 4096)
            or row["request_id"] != "req-" + row["intent_sha256"][:48]
        ):
            _deny()

    async def _source(self, db: Any, request: Mapping[str, str]) -> dict[str, Any]:
        # Read immutable identity to build the original binding. The owning
        # signed Flow is then fenced before locking the Action for mutation.
        candidate = (
            (
                await db.execute(
                    text("SELECT * FROM flow_mcp_action_dispatches WHERE request_id=:request"),
                    {"request": request["request_id"]},
                )
            )
            .mappings()
            .one_or_none()
        )
        if candidate is None:
            _deny()
        original = dict(candidate)
        if (
            original.get("engagement_id") != request["engagement_id"]
            or original.get("task_id") != request["task_id"]
            or original.get("server_id") != "browser-mcp"
            or original.get("tool_name") != "execute"
            or original.get("side_effect_class") != "RECON_ACTIVE"
            or original.get("request_id") != request["request_id"]
            or type(original.get("action_id")) is not str
            or _ACTION.fullmatch(original["action_id"]) is None
        ):
            _deny()
        b = _binding(
            {
                "engagement_id": original["engagement_id"],
                "flow_id": original["flow_id"],
                "revision": original["flow_revision"],
                "version": original["authorization_version"],
                "authorization_id": original["authorization_id"],
                "authorization_sha256": original["authorization_sha256"],
            }
        )
        session = await self.actions._authority(db, b, original["owner_id"], dispatch=True)
        row = await self.actions._row(db, original["action_id"], lock=True)
        if row is None or row != original:
            _deny()
        self.actions._same(row, b, original["owner_id"])
        if (
            row.get("status") != "unknown"
            or row.get("cancel_requested") is not False
            or row.get("receipt_sha256") is not None
        ):
            _deny()
        self._original_intent(row)
        attempted = (
            await db.execute(
                text(
                    "SELECT 1 FROM flow_mcp_action_dispatch_events "
                    "WHERE action_id=:action AND engagement_id=:eng AND flow_id=:flow "
                    "AND kind='dispatch_attempted' AND status='unknown' "
                    "AND intent_sha256=:intent LIMIT 1 FOR SHARE"
                ),
                {
                    "action": row["action_id"],
                    "eng": row["engagement_id"],
                    "flow": row["flow_id"],
                    "intent": row["intent_sha256"],
                },
            )
        ).scalar_one_or_none()
        if attempted != 1:
            _deny()
        declaration = self.actions._declaration("browser-mcp", "execute")
        if (
            declaration.side_effect_class is not SideEffectClass.RECON_ACTIVE
            or declaration.requires_approval is not True
            or declaration.scope_check is not True
            or self.actions.declaration_sha256(declaration, "browser-mcp")
            != row["declaration_sha256"]
        ):
            _deny()
        parameters = _safe_parameters(
            row["safe_parameters"], declaration, server_id=row["server_id"]
        )
        # Both the declared browser action and destination must be the exact
        # independently reviewed 0027 bytes, not a caller's JSON assertion.
        if (
            set(parameters)
            not in (
                {"url", "action", "user_label"},
                {"url", "action", "user_label", "evidence_mode"},
            )
            or parameters["action"] != "navigate"
            or parameters["user_label"] != request["user_label"]
            or parameters.get("evidence_mode", "none") != request["evidence_mode"]
            or not isinstance(parameters["url"], str)
            or self.actions.parameters_sha256(parameters) != row["parameters_sha256"]
            or not hmac.compare_digest(
                hashlib.sha256(parameters["url"].encode("utf-8")).hexdigest(),
                request["url_sha256"],
            )
            or exact_origin(parameters["url"]) != request["origin"]
        ):
            _deny()
        scope = ScopeEnforcer(ScopeDefinition.model_validate(session["scope"]))
        scope.validate_time_window()
        validate_payload_targets(scope, parameters, require_target=True)
        # The original 0027 dispatch is already the budgeted MCP request. For
        # limited ROEs, require its Redis reservation receipt by exact
        # request_id; do not debit a fresh unit or trust caller budget claims.
        roe = (
            (
                await db.execute(
                    text("SELECT roe FROM session_states WHERE session_id=:eng FOR SHARE"),
                    {"eng": row["engagement_id"]},
                )
            )
            .mappings()
            .one_or_none()
        )
        if roe is None or type(roe.get("roe")) is not dict:
            _deny()
        current_roe = roe["roe"]
        restrictions = {str(item).lower() for item in scope.scope.restrictions}
        if (
            restrictions.intersection(
                {
                    "no_active_scanning",
                    "passive_only",
                    "no_scans",
                    "no_intrusive_scanning",
                    "no_side_effects",
                    "no_exploitation",
                }
            )
            or current_roe.get("allow_active_scanning") is False
        ):
            _deny()
        allowed = {str(item).lower() for item in scope.scope.allowed_techniques}
        if allowed and not allowed.intersection(
            {"execute", "browser-mcp.execute", "active_scanning", "automated_scanning"}
        ):
            _deny()
        if "tool_call_budget_total" in current_roe or "tool_call_budget_per_tool" in current_roe:
            # SessionMemory.consume_mcp_tool_budget uses this same request
            # receipt key for the original MCPConnection.execute admission.
            # A missing/expired reservation or Redis outage denies navigation.
            source_receipt = (
                "osop:tool-budget:"
                + hashlib.sha256(row["engagement_id"].encode("utf-8")).hexdigest()[:24]
                + ":request:"
                + hashlib.sha256(
                    ("browser-mcp.execute:" + row["request_id"]).encode("utf-8")
                ).hexdigest()
            )
            try:
                redis_conn = await asyncio.wait_for(
                    self.actions.memory._ensure_redis(), timeout=2.0
                )
                proof = await asyncio.wait_for(redis_conn.get(source_receipt), timeout=2.0)
                if proof not in (b"1", "1"):
                    _deny()
            except BrowserSourceDenied:
                raise
            except Exception as exc:
                raise BrowserSourceDenied(
                    503, "Original MCP budget reservation unavailable"
                ) from exc
        admitted = await self.actions._approved_task(
            db,
            b,
            original["owner_id"],
            row["task_id"],
            row["subtask_id"],
            row["server_id"],
            row["tool_name"],
            row["declaration_sha256"],
            row["parameters_sha256"],
            row["side_effect_class"],
            scope,
        )
        if any(
            admitted.get(k) != row[k]
            for k in ("action_id", "approval_id", "lease_id", "lease_owner_id")
        ):
            _deny()
        return row

    async def admit(self, claimed: Any) -> dict[str, Any]:
        request = validate_request(claimed)
        kid, signer = _signer()  # Fail before any row lock/write if key absent.
        token: dict[str, Any]
        try:
            async with self.actions._sessions()() as db:
                async with db.begin():
                    original = await self._source(db, request)
                    now = await self._now(db)
                    claims = {
                        "version": 1,
                        "preflight_id": "nbp-" + uuid.uuid4().hex,
                        **{
                            name: original[name]
                            for name in (
                                "request_id",
                                "engagement_id",
                                "flow_id",
                                "task_id",
                                "subtask_id",
                                "action_id",
                                "owner_id",
                                "server_id",
                                "tool_name",
                                "authorization_version",
                                "authorization_sha256",
                                "approval_id",
                                "lease_id",
                            )
                        },
                        "action": "navigate",
                        "url_sha256": request["url_sha256"],
                        "origin": request["origin"],
                        "user_label": request["user_label"],
                        "evidence_mode": request["evidence_mode"],
                        "issued_at": now,
                        "expires_at": now + 10,
                    }
                    if set(claims) != _CLAIM_FIELDS:
                        _deny(503)
                    encoded = _canonical(claims)
                    signature = signer.sign(DOMAIN + encoded)
                    saved = {
                        **claims,
                        "kid": kid,
                        "claims_sha256": hashlib.sha256(encoded).hexdigest(),
                        "signature_sha256": hashlib.sha256(signature).hexdigest(),
                    }
                    inserted = (
                        await db.execute(
                            text(
                                "INSERT INTO native_browser_source_preflights ("
                                + ",".join(saved)
                                + ") VALUES ("
                                + ",".join(":" + k for k in saved)
                                + ") ON CONFLICT DO NOTHING RETURNING preflight_id"
                            ),
                            saved,
                        )
                    ).scalar_one_or_none()
                    if inserted != claims["preflight_id"]:
                        _deny()  # Even after lost ACK; never reissue.
                    token = {"claims": claims, "kid": kid, "signature": _b64url(signature)}
            # Transaction committed successfully before any signed receipt escapes.
            return token
        except BrowserSourceDenied:
            raise
        except MCPActionDenied as exc:
            raise BrowserSourceDenied(409, "Current browser source admission unavailable") from exc
        except Exception as exc:
            # Includes unique constraint races, unexpected database failures,
            # and commit failures. No retry follows an UNKNOWN outcome.
            raise BrowserSourceDenied(503, "Durable browser source admission unavailable") from exc
