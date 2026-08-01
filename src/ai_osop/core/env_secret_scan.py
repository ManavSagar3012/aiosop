"""Startup env-var secret scan.

Local, no external calls: pattern-based detection of common secret shapes
(AWS/GitHub/Slack/JWT/private keys) in os.environ. Emits one warning log line
per finding plus a metric. HIBP k-anonymity lookup stays opt-in — uncomment
OSOP_ENV_SCAN_HIBP_URL with a HIBP-compatible endpoint only when a HIBP key is
provisioned.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
from typing import Any, Dict, List, Optional

import structlog

from ai_osop.core import metrics_a2
from ai_osop.core.config import settings

logger = structlog.get_logger(__name__)

# (pattern_name, compiled_regex) — anchored to secret shapes, not keywords,
# to avoid false positives on benign variable names.
_ENV_SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key_pair", re.compile(r"[0-9a-zA-Z/+]{40}")),  # heuristic
    ("github_pat", re.compile(r"\bghp_[0-9A-Za-z]{36,}\b")),
    ("github_oauth", re.compile(r"\bgho_[0-9A-Za-z]{36,}\b")),
    ("slack_bot", re.compile(r"\bxoxb-[0-9A-Za-z-]{10,}\b")),
    ("slack_user", re.compile(r"\bxoxp-[0-9A-Za-z-]{10,}\b")),
    ("jwt_like", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
]

_ALLOWLIST_SUFFIXES = ("_MOCK", "_EXAMPLE", "_PLACEHOLDER")


def scan_environ(environ: Dict[str, str] | None = None) -> List[Dict[str, Any]]:
    """Return findings: one dict per (name, pattern) hit. No values — only names
    and pattern names, since logging a secret would defeat the point."""
    env = dict(os.environ if environ is None else environ)
    findings = []

    for name, value in env.items():
        if not isinstance(value, str) or not value:
            continue
        if name.endswith(_ALLOWLIST_SUFFIXES):
            continue
        for pattern_name, pattern in _ENV_SECRET_PATTERNS:
            if pattern.search(value):
                findings.append(
                    {
                        "name": name,
                        "pattern": pattern_name,
                        "length": len(value),
                        "hash_prefix": __import__("hashlib").sha256(value.encode()).hexdigest()[:8],
                    }
                )
                break  # one finding per var is enough
    return findings


def audit_environ_on_boot() -> int:
    """Run the scan, log + count each finding. Returns number of hits.

    When `OSOP_ENV_SCAN_HIBP_URL` is set (e.g. a HIBP-compatible k-anonymity
    range endpoint), each detected secret is also checked against that service —
    only the SHA-1 prefix leaves the process, never the secret itself.
    """
    findings = scan_environ()
    for f in findings:
        hibp_hits = None
        if os.environ.get("OSOP_ENV_SCAN_HIBP_URL"):
            import hashlib as _h

            try:
                env_value = os.environ.get(f["name"], "")
                digest = _h.sha1(env_value.encode("utf-8", "ignore")).hexdigest()
                hibp_hits = check_hibp_range(digest)
            except Exception:  # noqa: BLE001
                hibp_hits = None
        # Don't include the value — only metadata.
        logger.warning(
            "env_secret_detected",
            env_var=f["name"],
            pattern=f["pattern"],
            value_length=f["length"],
            value_hash_prefix=f["hash_prefix"],
            hibp_hit_count=hibp_hits,
        )
        if hibp_hits:
            logger.critical(
                "env_secret_known_breached",
                env_var=f["name"],
                pattern=f["pattern"],
                hibp_hit_count=hibp_hits,
            )
    try:
        metrics_a2.tool_call("env_secret_scan", "flagged" if findings else "clean")
    except Exception:  # noqa: BLE001
        pass
    return len(findings)


def check_hibp_range(sha1_hex_of_secret: str) -> Optional[int]:
    """Opt-in k-anonymity breach check against a HIBP-compatible endpoint.

    Reads `OSOP_ENV_SCAN_HIBP_URL`. Sends only the first 5 hex chars of the
    SHA-1 of the secret; returns the hit count (or None when the endpoint is
    not configured / unreachable). Never raises into startup.
    """
    endpoint = os.environ.get("OSOP_ENV_SCAN_HIBP_URL")
    if not endpoint:
        return None
    try:
        import urllib.request

        prefix = sha1_hex_of_secret[:5].upper()
        url = f"{endpoint.rstrip('/')}/range/{prefix}"
        with urllib.request.urlopen(url, timeout=3) as r:
            body = r.read().decode("utf-8", "ignore")
        suffix = sha1_hex_of_secret[5:].upper()
        for line in body.splitlines():
            if not line or ":" not in line:
                continue
            line_suffix, _, count = line.partition(":")
            if line_suffix.strip().upper() == suffix:
                try:
                    return int(count)
                except ValueError:
                    return 0
        return 0
    except Exception:  # noqa: BLE001 - opt-in only; never fatal
        return None
