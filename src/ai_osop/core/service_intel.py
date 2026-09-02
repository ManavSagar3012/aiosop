"""Service Intelligence primitives (charter: Service Vulnerability Assessment).

Implements the DETECTED -> CANDIDATE -> VALIDATED hierarchy so fingerprinting is
never reported as vulnerability validation:

    DETECTED   banner/version observed          (observation class)
    CANDIDATE  matches a known-risk rule        (weakness class, needs validation)
    VALIDATED  only set by the Validation Engine (never by these probes)

Tier-1 probes implemented natively (no external tooling required):
    * TLS        versions offered, cert expiry/SANs/issuer, hostname match,
                 legacy-version acceptance
    * SSH        banner grab -> product/version -> known-risk rules

Everything returns plain dicts so results are JSON-storable as evidence and
feed directly into Finding Intelligence classification.
"""

import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DETECTED = "detected"
CANDIDATE = "candidate"
VALIDATED = "validated"


# --------------------------------------------------------------------------
# TLS assessment
# --------------------------------------------------------------------------

_LEGACY_TLS = [("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1_1", ssl.TLSVersion.TLSv1_1)]


def _tls_client_ctx(version: Optional[ssl.TLSVersion] = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version is not None:
        ctx.minimum_version = version
        ctx.maximum_version = version
    return ctx


def _probe_tls_version(
    host: str, port: int, version: Optional[ssl.TLSVersion], timeout: float
) -> bool:
    """True if the server completes a handshake restricted to `version`."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with _tls_client_ctx(version).wrap_socket(sock, server_hostname=host):
                return True
    except Exception:  # noqa: BLE001 - refused handshake == not supported
        return False


def assess_tls(host: str, port: int = 443, timeout: float = 6.0) -> Dict[str, Any]:
    """Assess TLS on host:port. Returns evidence-rich dict, never raises."""
    result: Dict[str, Any] = {
        "probe": "tls",
        "host": host,
        "port": port,
        "reachable": False,
        "versions": [],
        "legacy_versions_accepted": [],
        "certificate": {},
        "issues": [],
    }
    # 1) modern handshake for cert details
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with _tls_client_ctx().wrap_socket(sock, server_hostname=host) as tls:
                result["reachable"] = True
                result["versions"].append(tls.version())
                cert_bin = tls.getpeercert(binary_form=True)
                decoded = {}
                if cert_bin:
                    der = ssl.DER_cert_to_PEM_cert(cert_bin)
                    decode = getattr(getattr(ssl, "_ssl", None),
                                     "_test_decode_cert", None)
                    if decode:
                        decoded = decode(der) or {}
                parsed = decoded
                result["certificate"] = {
                    "subject": parsed.get("subject"),
                    "issuer": parsed.get("issuer"),
                    "not_after": parsed.get("notAfter"),
                    "sans": [v for k, v in parsed.get("subjectAltName", []) if k == "DNS"],
                }
    except Exception as e:  # noqa: BLE001
        result["error"] = f"handshake_failed: {e}"
        return result

    # 2) enumerate modern versions independently (1.2 / 1.3)
    for name, ver in (("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)):
        if _probe_tls_version(host, port, ver, timeout):
            if name not in result["versions"]:
                result["versions"].append(name)

    # 3) legacy acceptance = weakness candidates
    for name, ver in _LEGACY_TLS:
        if _probe_tls_version(host, port, ver, timeout):
            result["legacy_versions_accepted"].append(name)
            result["issues"].append(
                {
                    "id": f"tls_legacy_{name.lower()}",
                    "level": CANDIDATE,
                    "title": f"Legacy protocol {name} accepted",
                    "why_it_matters": "Downgrade/POODLE-class exposure; modern clients "
                    "should never need pre-TLS1.2.",
                }
            )

    # 4) certificate reasoning
    cert = result["certificate"]
    not_after = cert.get("not_after")
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            cert["days_remaining"] = days
            if days < 0:
                result["issues"].append(
                    {
                        "id": "tls_cert_expired",
                        "level": CANDIDATE,
                        "title": "Certificate expired",
                        "days_expired": -days,
                    }
                )
            elif days <= 30:
                result["issues"].append(
                    {
                        "id": "tls_cert_expiring_soon",
                        "level": CANDIDATE,
                        "title": f"Certificate expires in {days}d",
                    }
                )
        except Exception:  # noqa: BLE001 - unparsable date stays raw evidence
            pass
    sans = cert.get("sans") or []
    if sans and not any(host == s or host.endswith("." + s.lstrip("*.")) for s in sans):
        result["issues"].append(
            {
                "id": "tls_hostname_mismatch",
                "level": CANDIDATE,
                "title": "Hostname not covered by SANs",
            }
        )
    return result


# --------------------------------------------------------------------------
# SSH banner grab
# --------------------------------------------------------------------------

_SSH_RISK_RULES: List[Dict[str, Any]] = [
    {
        "pattern": r"OpenSSH[_-](\d+)\.(\d+)",
        "product": "OpenSSH",
        "rule": lambda m: int(m.group(1)) < 7,
        "id": "ssh_openssh_eol_major",
        "title": "OpenSSH < 7.x exposed",
    },
    {
        "pattern": r"SSH-\d\.\d+-(libssh[^_\s]*)",
        "product": "libssh",
        "rule": None,
        "id": "ssh_libssh_banner",
        "title": "libssh detected (CVE-prone lineage)",
    },
]


def grab_ssh_banner(host: str, port: int = 22, timeout: float = 5.0) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
            return data.decode("utf-8", "ignore").splitlines()[0].strip()
    except Exception:  # noqa: BLE001
        return None


def assess_ssh(host: str, port: int = 22, timeout: float = 5.0) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "probe": "ssh",
        "host": host,
        "port": port,
        "reachable": False,
        "banner": None,
        "issues": [],
    }
    banner = grab_ssh_banner(host, port, timeout)
    if not banner:
        return out
    out["reachable"] = True
    out["banner"] = banner
    out["level"] = DETECTED
    for rule in _SSH_RISK_RULES:
        m = re.search(rule["pattern"], banner)
        if m and (rule["rule"] is None or rule["rule"](m)):
            out["issues"].append(
                {"id": rule["id"], "level": CANDIDATE, "title": rule["title"], "banner": banner}
            )
    return out


# --------------------------------------------------------------------------
# Detection-level hierarchy guard
# --------------------------------------------------------------------------

_LEVEL_RANK = {DETECTED: 0, CANDIDATE: 1, VALIDATED: 2}


def assert_level_transition(current: str, target: str) -> None:
    """Findings may only move FORWARD along DETECTED->CANDIDATE->VALIDATED.

    Probes can never silently downgrade a VALIDATED finding to a fingerprint.
    """
    if _LEVEL_RANK.get(target, -1) < _LEVEL_RANK.get(current, -1):
        raise ValueError(
            f"Illegal level regression {current} -> {target}; validated findings "
            f"may only be superseded by the Validation Engine."
        )
