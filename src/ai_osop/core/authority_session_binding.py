"""Non-reversible, admission-time binding of authenticated replay identities.

Optional independently configured HMAC secret prevents exposing raw tokens,
cookies, response bodies or other low-entropy session material in TaskORM.
The digest witnesses an original PostgreSQL imported session snapshot, not a
target-owned attestation or proof of a vulnerability.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any, Dict, Optional


class AuthoritySessionBindingUnavailable(RuntimeError):
    """Trusted replay session provenance cannot be established."""


def _key() -> Optional[bytes]:
    value = os.environ.get("OSOP_TARGET_AUTHORITY_PROVENANCE_KEY")
    if value is None:
        return None
    if (
        type(value) is not str
        or not 32 <= len(value.encode("utf-8")) <= 256
        or any(ord(char) < 33 for char in value)
    ):
        raise AuthoritySessionBindingUnavailable("Invalid independent provenance secret")
    return value.encode("utf-8")


def _mac(secret: bytes, label: bytes, data: Dict[str, Any]) -> str:
    try:
        encoded = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, UnicodeError, ValueError, RecursionError) as exc:
        raise AuthoritySessionBindingUnavailable("Replay identity provenance invalid") from exc
    if not 0 < len(encoded) <= 32768:
        raise AuthoritySessionBindingUnavailable("Replay identity provenance size invalid")
    return hmac.new(secret, label + b"\x00" + encoded, hashlib.sha256).hexdigest()


def bound_replay_fingerprints(
    session: Any,
    *,
    engagement_id: str,
    user_label: str,
    method: str,
    url: str,
    task_id: str,
    parent_task_id: str,
) -> Dict[str, str]:
    """Derive exact request and session witnesses from PG-only session DTO.

    An unset local secret leaves normal human-approved replay functionality
    untouched, but independent target-authority verification must then deny.
    The caller must obtain `session` from get_session_authoritative, not Redis.
    """
    secret = _key()
    if secret is None:
        return {}
    if (
        getattr(session, "engagement_id", None) != engagement_id
        or getattr(session, "user_label", None) != user_label
        or not callable(getattr(session, "to_dict", None))
        or not callable(getattr(session, "is_expired", None))
        or session.is_expired(skew_seconds=0)
        or not (getattr(session, "cookies", None) or getattr(session, "local_storage", None))
        or method != "GET"
        or not isinstance(url, str)
        or not url.startswith("https://")
        or not isinstance(task_id, str)
        or not task_id.startswith("task-")
        or not isinstance(parent_task_id, str)
        or not parent_task_id.startswith("task-")
    ):
        raise AuthoritySessionBindingUnavailable(
            "Authenticated HTTPS replay provenance unavailable"
        )
    return {
        "_authority_request_sha256": _mac(
            secret,
            b"osop-target-authority-request-v1",
            {
                "engagement_id": engagement_id,
                "user_label": user_label,
                "method": method,
                "url": url,
                "task_id": task_id,
                "parent_task_id": parent_task_id,
            },
        ),
        "_authority_session_sha256": _mac(
            secret,
            b"osop-target-authority-session-v1",
            {
                "engagement_id": engagement_id,
                "user_label": user_label,
                "pg_imported_session": session.to_dict(),
            },
        ),
    }


def reverify_replay_fingerprints(
    recorded: Dict[str, Any],
    session: Any,
    *,
    engagement_id: str,
    user_label: str,
    method: str,
    url: str,
    task_id: str,
    parent_task_id: str,
) -> None:
    """Fail before any browser effect if signed approved session was rotated."""
    if not isinstance(recorded, dict) or not all(isinstance(key, str) for key in recorded):
        raise AuthoritySessionBindingUnavailable("Approved replay identity binding malformed")
    authority_keys = {key for key in recorded if key.startswith("_authority_")}
    if not authority_keys:
        return  # Existing provider-only replay stays candidate-only.
    if authority_keys != {"_authority_request_sha256", "_authority_session_sha256"}:
        raise AuthoritySessionBindingUnavailable("Approved replay identity binding malformed")
    fresh = bound_replay_fingerprints(
        session,
        engagement_id=engagement_id,
        user_label=user_label,
        method=method,
        url=url,
        task_id=task_id,
        parent_task_id=parent_task_id,
    )
    if not fresh or any(
        not isinstance(recorded.get(name), str) or not hmac.compare_digest(recorded[name], value)
        for name, value in fresh.items()
    ):
        raise AuthoritySessionBindingUnavailable("Approved replay identity has rotated")
