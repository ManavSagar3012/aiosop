"""Tests for Service Intelligence (Tier-1 TLS/SSH assessment)."""

import socket
from unittest.mock import patch

import pytest

from ai_osop.core import service_intel as si

class TestLevelHierarchy:
    def test_forward_transitions_allowed(self):
        si.assert_level_transition(si.DETECTED, si.CANDIDATE)
        si.assert_level_transition(si.CANDIDATE, si.VALIDATED)
        si.assert_level_transition(si.DETECTED, si.DETECTED)

    def test_regression_rejected(self):
        with pytest.raises(ValueError, match="regression"):
            si.assert_level_transition(si.VALIDATED, si.CANDIDATE)
        with pytest.raises(ValueError):
            si.assert_level_transition(si.CANDIDATE, si.DETECTED)

class TestSSH:
    def test_banner_grab_parses_version_risk(self):
        fake = "SSH-2.0-OpenSSH_6.9p1 Debian"
        with patch.object(si.socket, "create_connection") as mc:
            s = mc.return_value.__enter__.return_value
            s.recv.return_value = (fake + "\n").encode()
            out = si.assess_ssh("h", 22)
        assert out["reachable"] and "OpenSSH" in out["banner"]
        assert any(i["id"] == "ssh_openssh_eol_major" for i in out["issues"])
        # level stays CANDIDATE — never auto-VALIDATED
        assert all(i["level"] == si.CANDIDATE for i in out["issues"])

    def test_modern_ssh_no_false_positive(self):
        with patch.object(si.socket, "create_connection") as mc:
            s = mc.return_value.__enter__.return_value
            s.recv.return_value = b"SSH-2.0-OpenSSH_9.6p1\n"
            out = si.assess_ssh("h", 22)
        assert out["reachable"] and out["issues"] == []
        assert out["level"] == si.DETECTED

    def test_unreachable_returns_clean(self):
        with patch.object(si.socket, "create_connection", side_effect=ConnectionRefusedError()):
            out = si.assess_ssh("h", 22)
        assert not out["reachable"] and out["banner"] is None

def _tls_env(cert: dict):
    """Patch full handshake chain: connection -> wrap_socket -> cert decode."""
    from contextlib import contextmanager
    from unittest.mock import MagicMock

    tls = MagicMock()
    tls.version.return_value = "TLSv1.3"
    tls.getpeercert.return_value = b"DERBYTES"

    @contextmanager
    def fake_wrap(self, sock, server_hostname=None):  # noqa: ANN001
        yield tls

    conn_cm = MagicMock()
    conn_cm.__enter__.return_value = MagicMock()
    p1 = patch.object(si.socket, "create_connection", return_value=conn_cm)
    p2 = patch.object(si.ssl.SSLContext, "wrap_socket", fake_wrap)
    p3 = patch("ssl.DER_cert_to_PEM_cert", return_value="PEM")
    p4 = patch("ssl._ssl._test_decode_cert", create=True, return_value=cert)
    return p1, p2, p3, p4

class TestTLS:
    def _run_tls(self, cert):
        p1, p2, p3, p4 = _tls_env(cert)
        with p1, p2, p3, p4:
            return si.assess_tls("h", 443)

    def test_legacy_acceptance_flagged_as_candidate(self):
        p1, p2, p3, p4 = _tls_env({"notAfter": "Jan 01 00:00:00 2099 GMT",
                                   "subjectAltName": [("DNS", "h")]})
        with patch.object(si, "_probe_tls_version",
                          side_effect=lambda h, p, v, t: v in (
                              si.ssl.TLSVersion.TLSv1, si.ssl.TLSVersion.TLSv1_1)):
            with p1, p2, p3, p4:
                out = si.assess_tls("h", 443)
        legacy = {i["title"] for i in out["issues"] if i["id"].startswith("tls_legacy")}
        assert {"Legacy protocol TLSv1 accepted",
                "Legacy protocol TLSv1_1 accepted"} <= legacy
        assert all(i["level"] == si.CANDIDATE for i in out["issues"])
    def test_expired_certificate_candidate(self):
        out = self._run_tls({"notAfter": "Jan 01 00:00:00 2020 GMT",
                             "subjectAltName": [("DNS", "h")]})
        assert "tls_cert_expired" in [i["id"] for i in out["issues"]]

    def test_hostname_mismatch_detected(self):
        out = self._run_tls({"notAfter": "Jan 01 00:00:00 2099 GMT",
                             "subjectAltName": [("DNS", "other.example")]})
        assert any(i["id"] == "tls_hostname_mismatch" for i in out["issues"])
