"""Regression tests for the scope/audit signing key (OSOP-P0-03).

Invariant: scope manifests and the audit chain are signed and verified with ONE key,
and in a production environment an unset OSOP_AUDIT_SECRET_KEY must fail closed rather
than silently fall back to a public constant (which would make every scope signature
and audit record forgeable).
"""

from __future__ import annotations

import pytest

import ai_osop.core.config as config
from ai_osop.core.models import ScopeDefinition


@pytest.fixture
def restore_settings():
    orig_key = config.settings.audit_secret_key
    orig_env = config.settings.environment
    orig_pass = config.settings.neo4j_password
    orig_jwt = config.settings.jwt_secret
    yield
    config.settings.audit_secret_key = orig_key
    config.settings.environment = orig_env
    config.settings.neo4j_password = orig_pass
    config.settings.jwt_secret = orig_jwt


def test_prod_unset_key_fails_closed(restore_settings):
    config.settings.audit_secret_key = None
    config.settings.environment = "production"
    with pytest.raises(RuntimeError):
        config.scope_signing_key()


def test_dev_unset_key_uses_labelled_insecure_default(restore_settings):
    config.settings.audit_secret_key = None
    config.settings.environment = "development"
    key = config.scope_signing_key()
    assert key == config._INSECURE_DEV_SIGNING_KEY
    # It must NOT be the old public constant that signers/verifiers used to disagree on.
    assert key != b"default-insecure-audit-key"


def test_configured_key_returned_as_bytes_any_env(restore_settings):
    config.settings.audit_secret_key = "real-secret"
    for env in ("development", "production"):
        config.settings.environment = env
        assert config.scope_signing_key() == b"real-secret"


def test_assert_production_secrets_blocks_weak_neo4j(restore_settings):
    config.settings.environment = "production"
    config.settings.audit_secret_key = "real-secret-key"
    config.settings.jwt_secret = "a-strong-jwt-secret"
    config.settings.neo4j_password = "change-me-local"
    with pytest.raises(RuntimeError, match="NEO4J"):
        config.assert_production_secrets()


def test_assert_production_secrets_blocks_unset_audit_key(restore_settings):
    config.settings.environment = "production"
    config.settings.neo4j_password = "a-strong-password"
    config.settings.jwt_secret = "a-strong-jwt-secret"
    config.settings.audit_secret_key = None
    with pytest.raises(RuntimeError, match="AUDIT_SECRET_KEY"):
        config.assert_production_secrets()


def test_assert_production_secrets_noop_in_dev(restore_settings):
    config.settings.environment = "development"
    config.settings.neo4j_password = "change-me-local"
    config.settings.audit_secret_key = None
    config.assert_production_secrets()  # must NOT raise in dev


def test_assert_production_secrets_passes_when_configured(restore_settings):
    config.settings.environment = "production"
    config.settings.neo4j_password = "a-strong-password"
    config.settings.audit_secret_key = "a-real-audit-key"
    config.settings.jwt_secret = "a-strong-jwt-secret"
    config.assert_production_secrets()  # must not raise


def test_sign_then_verify_roundtrip_with_one_key(restore_settings):
    """A scope signed with scope_signing_key() verifies with the same key — proving the
    signer/verifier divergence bug (constant vs real key) is gone."""
    config.settings.audit_secret_key = "roundtrip-key"
    config.settings.environment = "production"
    key = config.scope_signing_key()
    scope = ScopeDefinition(engagement_id="eng-x", domains=["example.com"], ips=[])
    scope.sign(key)
    assert scope.verify_signature(key) is True
    # A different key must NOT verify (tamper / wrong-key detection).
    assert scope.verify_signature(b"some-other-key") is False
