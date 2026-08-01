"""AIOSOP-SANDBOX-FAILCLOSED: sandbox egress iptables setup must fail closed.

If any iptables rule (most critically the terminal DROP or the FORWARD->chain
jump) fails to apply, the sandbox must NOT run with an unenforced egress policy.
Regression guard for the prior behaviour, which only logged a warning and
continued running wide open on any iptables failure.
"""

from unittest.mock import MagicMock, patch

import pytest

from ai_osop.core.exceptions import SandboxException
from ai_osop.safety.scope import _apply_egress_rules

_CMDS = [
    ["iptables", "-N", "AIOSOP-test"],
    ["iptables", "-I", "FORWARD", "1", "-i", "br-test", "-j", "AIOSOP-test"],
    ["iptables", "-A", "AIOSOP-test", "-j", "DROP"],
]


def test_fails_closed_when_drop_rule_fails():
    # Chain + jump succeed, the terminal DROP fails -> egress would be open.
    outcomes = [
        MagicMock(returncode=0, stderr=b""),
        MagicMock(returncode=0, stderr=b""),
        MagicMock(returncode=1, stderr=b"iptables: permission denied"),
    ]
    with patch("subprocess.run", side_effect=outcomes):
        with pytest.raises(SandboxException):
            _apply_egress_rules(_CMDS)


def test_fails_closed_when_forward_jump_fails():
    # The FORWARD->chain jump fails -> the DROP chain is never consulted.
    outcomes = [
        MagicMock(returncode=0, stderr=b""),
        MagicMock(returncode=2, stderr=b"no such chain"),
        MagicMock(returncode=0, stderr=b""),
    ]
    with patch("subprocess.run", side_effect=outcomes):
        with pytest.raises(SandboxException):
            _apply_egress_rules(_CMDS)


def test_passes_when_all_rules_apply():
    with patch("subprocess.run", return_value=MagicMock(returncode=0, stderr=b"")):
        _apply_egress_rules(_CMDS)  # must not raise
