"""Secret redaction for receipts. Applied at capture time, before persistence."""

import hashlib
import re
from typing import Dict

# Headers whose values are bearer material and must never persist in plaintext.
_SECRET_HEADERS = frozenset({"authorization", "cookie", "x-api-key", "set-cookie", "proxy-authorization"})

# Long hex/alnum runs are usually tokens or hashes of secrets.
_TOKEN_RE = re.compile(r"[A-Za-z0-9\-_/+]{24,}={0,2}")

# Explicitly-tagged bearer material may be shorter than the generic threshold.
_BEARER_RE = re.compile(r"(?i)(bearer[ \t]+)([A-Za-z0-9\-_./+=]{8,})")


def _label(value: str) -> str:
    return f"[REDACTED:sha256:{hashlib.sha256(value.encode()).hexdigest()[:12]}]"


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in headers.items():
        out[k] = _label(v) if k.lower() in _SECRET_HEADERS else v
    return out


def redact_text(text: str) -> str:
    text = _TOKEN_RE.sub(lambda m: _label(m.group(0)), text)
    return _BEARER_RE.sub(lambda m: m.group(1) + _label(m.group(2)), text)
