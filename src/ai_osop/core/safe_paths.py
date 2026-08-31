"""Path-safety helpers for operator-influenced filesystem locations.

MIMOSA-TRIAGE-2026-08-30: engagement_id is operator-supplied (it flows from
POST /engagements into session ids) and was joined directly into report paths
(os.path.join("reports", engagement_id)) at several sites. A crafted id
("../..") would write outside reports/. Severity is low (senior-operator-only
input), but the platform audits itself to a higher standard: sanitize every
operator-influenced path component to a flat, charset-restricted slug.
"""

import re

_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_COMPONENT_LEN = 120


def safe_component(value: str) -> str:
    """Return a filesystem-safe, flat component for an operator-supplied id.

    - path separators and traversal payloads collapse to '_'
    - leading dots stripped (no '..' forms, no hidden files)
    - charset limited to alphanumerics, dot, underscore, hyphen
    - length bounded
    """
    raw = str(value or "")
    slug = _SAFE_COMPONENT_RE.sub("_", raw).lstrip(".")
    slug = slug[:_MAX_COMPONENT_LEN]
    return slug or "unnamed"
