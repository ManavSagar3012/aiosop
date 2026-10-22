"""Emergency durable account disable also fences background signed execution."""

from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import settings
from ai_osop.memory.authorization_store import AuthorizationDenied, guard_sql


class _Result:
    def __init__(self, value):
        self.value = value

    def mappings(self):
        return self

    def one_or_none(self):
        return self.value

    def scalar_one_or_none(self):
        return self.value


class _Database:
    def __init__(self, disabled=False, *, missing_controls=False, owner="operator-test"):
        self.disabled = disabled
        self.owner = owner
        self.missing_controls = missing_controls
        self.reads = []

    async def execute(self, sql, args):
        statement = str(sql)
        self.reads.append((statement, args))
        if "FROM session_states" in statement:
            return _Result({"created_by": self.owner, "session_id": "eng-operator-test"})
        if "FROM operator_subject_controls" in statement:
            if self.missing_controls:
                raise OSError("missing SQL schema, password=NEVER_ECHO_THIS")
            return _Result(self.disabled)
        if "FROM signed_authorizations" in statement:
            return _Result(None)
        raise AssertionError("Unexpected signed admission query")


@pytest.mark.asyncio
async def test_signed_background_dispatch_denied_for_durably_disabled_owner(monkeypatch):
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    db = _Database(disabled=True)
    with pytest.raises(AuthorizationDenied, match="owner is disabled"):
        await guard_sql(db, "eng-operator-test", expected_version=2)
    assert len(db.reads) == 2
    assert "FOR SHARE" in db.reads[1][0]
    assert db.reads[1][1] == {"actor": "operator-test"}
    assert "FROM signed_authorizations" not in " ".join(x[0] for x in db.reads)


@pytest.mark.asyncio
async def test_enabled_owner_still_requires_original_signed_roe(monkeypatch):
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    db = _Database(disabled=False)
    with pytest.raises(AuthorizationDenied, match="No active verified signed authorization"):
        await guard_sql(db, "eng-operator-test", expected_version=2)
    assert len(db.reads) == 3
    assert "FROM signed_authorizations" in db.reads[-1][0]


@pytest.mark.asyncio
async def test_missing_subject_control_migration_fails_closed_without_error_leak(monkeypatch):
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    db = _Database(missing_controls=True)
    with pytest.raises(AuthorizationDenied, match="unavailable") as error:
        await guard_sql(db, "eng-operator-test", expected_version=2)
    assert "NEVER_ECHO_THIS" not in str(error.value)
    assert len(db.reads) == 2


@pytest.mark.asyncio
async def test_malformed_engagement_owner_denied_before_authz(monkeypatch):
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    db = _Database(owner="operator\nother-tenant")
    with pytest.raises(AuthorizationDenied, match="operator identity unavailable"):
        await guard_sql(db, "eng-operator-test", expected_version=2)
    assert len(db.reads) == 1


@pytest.mark.asyncio
async def test_feature_off_preserves_existing_signed_roe_admission(monkeypatch):
    monkeypatch.setattr(settings, "operator_revocation_required", False)
    db = _Database(disabled=True)
    with pytest.raises(AuthorizationDenied, match="No active verified signed authorization"):
        await guard_sql(db, "eng-operator-test", expected_version=2)
    assert len(db.reads) == 2
    assert "FROM operator_subject_controls" not in " ".join(x[0] for x in db.reads)
