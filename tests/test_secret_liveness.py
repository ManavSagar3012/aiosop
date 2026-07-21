"""Secret-liveness validation tests.

Covers the assessment status model in ai_osop.core.secret_verifier:
  (a) vendor test/placeholder keys     -> not_a_secret
  (b) structurally-invalid provider key -> unverified (rejected format)
  (c) structurally-valid-but-unprobed  -> unverified (never auto-confirmed)
  (d) downgrade gate: only confirmed_live is reportable

All network probes are mocked so tests are deterministic and offline.
"""

import asyncio

from ai_osop.core.secret_verifier import (
    STATUS_CONFIRMED_LIVE,
    STATUS_NOT_A_SECRET,
    STATUS_UNVERIFIED,
    assess_secret,
    is_reportable,
    structural_valid,
)

# A structurally valid GitHub PAT (ghp_ + exactly 36 alphanumerics).
GOOD_GITHUB = "ghp_" + "aB3" * 12  # 36 chars after prefix


class _FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code


class _FakeClient:
    """Minimal stand-in for httpx.AsyncClient that returns a canned status."""

    def __init__(self, status_code):
        self._status = status_code
        self.calls = []

    async def request(self, method, url, headers=None):
        self.calls.append((method, url, headers))
        return _FakeResponse(self._status)


# ---------------------------------------------------------------- (a) not_a_secret
def test_vendor_test_key_is_not_a_secret():
    verdict = asyncio.run(assess_secret("sk_test_4eC39HqLyjWDarjtT1zdp7dc"))
    assert verdict["status"] == STATUS_NOT_A_SECRET
    assert verdict["reportable"] is False
    assert verdict["confidence"] == 0.0


def test_placeholder_and_allzeros_are_not_a_secret():
    for value in ("YOUR_API_KEY_HERE", "changeme", "AKIA" + "0" * 16, "xxxxxxxxxxxxxxxx"):
        verdict = asyncio.run(assess_secret(value))
        assert verdict["status"] == STATUS_NOT_A_SECRET, value
        assert is_reportable(verdict) is False


# ---------------------------------------------------- (b) structurally-invalid provider
def test_structurally_invalid_github_key_is_unverified():
    # Right prefix, wrong length/charset -> recognized provider but fails structure.
    verdict = asyncio.run(assess_secret("ghp_short"))
    assert verdict["provider"] == "github"
    assert verdict["structural_valid"] is False
    assert verdict["status"] == STATUS_UNVERIFIED
    assert verdict["reportable"] is False
    assert verdict["confidence"] < 0.2


def test_generic_high_entropy_string_is_unverified_not_confirmed():
    # No provider prefix, but long and high-entropy -> unverified (low confidence).
    verdict = asyncio.run(assess_secret("Zx9Q2wErT7yUiOpAsDf4GhJkLmNbVcX1"))
    assert verdict["provider"] is None
    assert verdict["status"] == STATUS_UNVERIFIED
    assert verdict["reportable"] is False


# ----------------------------------------- (c) structurally-valid-but-unprobed
def test_valid_provider_key_unprobed_is_unverified():
    # Probing disabled (default) -> may not auto-confirm, tops out at unverified.
    verdict = asyncio.run(assess_secret(GOOD_GITHUB, allow_live_probe=False))
    assert verdict["provider"] == "github"
    assert verdict["structural_valid"] is True
    assert verdict["status"] == STATUS_UNVERIFIED
    assert verdict["probed"] is False
    assert verdict["reportable"] is False


def test_structural_only_provider_never_confirms_even_with_probe():
    # AWS keys have no safe verify endpoint; even with probing enabled they can
    # rise no higher than unverified (no fabricated liveness).
    aws_key = "AKIA" + "ABCDEFGHIJKLMNOP"  # AKIA + 16 uppercase/alnum
    assert structural_valid(aws_key) is True
    verdict = asyncio.run(assess_secret(aws_key, allow_live_probe=True))
    assert verdict["provider"] == "aws"
    assert verdict["status"] == STATUS_UNVERIFIED
    assert verdict["probed"] is False


# --------------------------------------------------- (d) probe + downgrade gate
def test_probe_authenticates_marks_confirmed_live(monkeypatch):
    # GOV-6 (2026-07-21): external liveness probing is now fail-closed by policy.
    # This test verifies the probe MECHANISM (a live 200 -> confirmed_live), so it
    # must opt into the policy the same way a real engagement would.
    from ai_osop.core import config as _config
    monkeypatch.setattr(_config.settings, "allow_external_liveness_probing", True, raising=False)
    client = _FakeClient(200)
    verdict = asyncio.run(
        assess_secret(
            GOOD_GITHUB,
            allow_live_probe=True,
            client=client,
            base_override="https://mock.local",
        )
    )
    assert verdict["status"] == STATUS_CONFIRMED_LIVE
    assert verdict["live"] is True
    assert verdict["probed"] is True
    assert verdict["reportable"] is True
    assert is_reportable(verdict) is True
    # Real read-only call was made against the mock, GET only.
    assert client.calls and client.calls[0][0] == "GET"


def test_probe_rejection_downgrades_to_unverified():
    client = _FakeClient(401)
    verdict = asyncio.run(
        assess_secret(
            GOOD_GITHUB,
            allow_live_probe=True,
            client=client,
            base_override="https://mock.local",
        )
    )
    assert verdict["status"] == STATUS_UNVERIFIED
    assert verdict["live"] is False
    assert verdict["probed"] is True
    assert is_reportable(verdict) is False


def test_only_confirmed_live_is_reportable():
    # The anti-noise gate: unverified / not_a_secret are never reportable.
    assert is_reportable({"status": STATUS_CONFIRMED_LIVE}) is True
    assert is_reportable({"status": STATUS_UNVERIFIED}) is False
    assert is_reportable({"status": STATUS_NOT_A_SECRET}) is False
    assert is_reportable({}) is False
