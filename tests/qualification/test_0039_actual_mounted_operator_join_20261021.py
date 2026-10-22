"""0039 global + 0019/0038 Flow SQL/HTTP join through mounted production routes.

PRODUCTION CODE: real main.app route registrations, real FastAPI routers,
signed local JWT verifier, actual OperatorGlobalLibrary and OperatorKnowledge
store SELECT/owner projections, FlowArtifactStore._fence, unified sanitization.

SYNTHETIC: read-only SELECT interpreter replaces PostgreSQL; guard_sql returns
a *fixture-asserted* authorizer digest and is NOT a verified signed ROE,
OIDC, host PKI, or real authorization DB check. No app DB, network, Docker,
LLM, real signer, provider or target is ever contacted.
"""

from __future__ import annotations

import copy
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, Optional

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from ai_osop.api import deps
from ai_osop.api.main import app as mounted_main
from ai_osop.core.config import settings
from ai_osop.memory import flow_artifacts as artifacts_store
from ai_osop.memory.authorization_store import AuthorizationDenied

ISSUER = "offline-issuer-0039"
OWNER = "operator-owned-0039"
FOREIGN = "operator-foreign-0039"
SESSION = "eng-isolated-0039"
FLOW = "flow-isolated-0039"
GLOBAL_ID = "lib-" + "a" * 32
LOCAL_ID = "knowledge-" + "b" * 32
AUTH_SHA = "b" * 64
SECRET = "offline-qualification-local-jwt-hs256-20261021"
NOTE = "Inert instruction: do NOT trust this as target evidence."
NOW = datetime(2026, 10, 21, 15, 0, tzinfo=timezone.utc)


def digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def principal(subject: str) -> str:
    return hashlib.sha256((ISSUER + "\x00" + subject).encode("utf-8")).hexdigest()


def token(
    subject: str = OWNER,
    *,
    signing_key: str = SECRET,
    role: str = "operator",
    issuer: str = ISSUER,
    expired: bool = False,
) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": issuer,
            "sub": subject,
            "role": role,
            "iat": now - 20,
            "exp": now - 1 if expired else now + 600,
        },
        signing_key,
        algorithm="HS256",
    )


@dataclass
class Rows:
    records: list[dict[str, Any]] = field(default_factory=list)

    def mappings(self) -> "Rows":
        return self

    def all(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self.records)

    def one_or_none(self) -> Optional[dict[str, Any]]:
        if len(self.records) > 1:
            raise AssertionError("Unexpected multi-row source")
        return copy.deepcopy(self.records[0]) if self.records else None


@dataclass
class OfflineReadOnly:
    global_deleted: bool = False
    global_content: str = NOTE
    flow_content: str = NOTE
    flow_revoked: bool = False
    flow_revision: int = 4
    authorization_version: int = 7
    flow_owner: str = OWNER
    flow_tenant: str = SESSION
    flow_doc_owner: str = OWNER
    flow_doc_tenant: str = SESSION
    flow_auth_sha: str = AUTH_SHA
    flow_doc_auth_sha: str = AUTH_SHA
    global_owner: str = field(default_factory=lambda: principal(OWNER))
    global_issuer: str = ISSUER
    query_log: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    fences: list[tuple[str, int]] = field(default_factory=list)
    writes: int = 0

    def __call__(self) -> "OfflineReadOnly":
        return self

    def begin(self) -> "OfflineReadOnly":
        return self

    async def __aenter__(self) -> "OfflineReadOnly":
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    def _global_row(self) -> dict[str, Any]:
        return {
            "id": GLOBAL_ID,
            "current_revision": 3,
            "created_at": NOW,
            "version_created_at": NOW,
            "deleted_at": None,
            "title": "needle global record",
            "doc_type": "guide",
            "content": self.global_content,
            "content_bytes": len(self.global_content.encode()),
            "sha256": digest(self.global_content),
        }

    def _flow_row(self) -> dict[str, Any]:
        return {
            "id": LOCAL_ID,
            "engagement_id": self.flow_doc_tenant,
            "flow_id": FLOW,
            "owner_id": self.flow_doc_owner,
            "title": "needle flow record",
            "doc_type": "answer",
            "content": self.flow_content,
            "content_bytes": len(self.flow_content.encode()),
            "sha256": digest(self.flow_content),
            "revision": 2,
            "source_flow_revision": 4,
            "authorization_version": self.authorization_version,
            "authorization_sha256": self.flow_doc_auth_sha,
            "created_at": NOW,
            "updated_at": NOW,
            "deleted_at": None,
        }

    async def execute(self, statement: Any, params: Optional[dict[str, Any]] = None) -> Rows:
        sql = str(statement)
        args = dict(params or {})
        self.query_log.append((sql, args))
        if not sql.lstrip().upper().startswith("SELECT "):
            self.writes += 1
            raise AssertionError("SELECT-only fixture: no application database writes")
        if "operator_global_library_documents d JOIN operator_global_library_versions v" in sql:
            assert (
                "d.principal_issuer=:issuer" in sql
                and "d.principal_subject=:owner" in sql
                and "d.deleted_at IS NULL" in sql
                and "v.revision=d.current_revision" in sql
            )
            owned = (
                args.get("issuer") == self.global_issuer and args.get("owner") == self.global_owner
            )
            matched = (
                args.get("query") is None
                or args["query"].lower() in ("needle global record " + self.global_content).lower()
            )
            return Rows(
                [self._global_row()] if owned and matched and not self.global_deleted else []
            )
        if "FROM operator_global_library_documents d" in sql and "FOR UPDATE OF d" in sql:
            assert (
                args.get("issuer") == self.global_issuer or args.get("owner") != self.global_owner
            )
            owned = (
                args.get("issuer") == self.global_issuer and args.get("owner") == self.global_owner
            )
            return Rows(
                [
                    {
                        "id": GLOBAL_ID,
                        "current_revision": 3,
                        "created_at": NOW,
                        "deleted_at": None,
                    }
                ]
                if args.get("id") == GLOBAL_ID and owned and not self.global_deleted
                else []
            )
        if "FROM operator_global_library_versions" in sql:
            return Rows(
                [
                    {
                        "title": "needle global record",
                        "doc_type": "guide",
                        "content": self.global_content,
                        "content_bytes": len(self.global_content.encode()),
                        "sha256": digest(self.global_content),
                        "version_created_at": NOW,
                    }
                ]
                if args.get("id") == GLOBAL_ID and args.get("revision") == 3
                else []
            )
        if sql == "SELECT engagement_id FROM execution_flows WHERE id=:fid":
            return Rows([{"engagement_id": self.flow_tenant}] if args.get("fid") == FLOW else [])
        if "FROM session_states" in sql:
            return Rows(
                [{"created_by": self.flow_owner, "phase": "reconnaissance"}]
                if args.get("sid") == self.flow_tenant
                else []
            )
        if "FROM execution_flows " in sql and "FOR SHARE" in sql:
            return Rows(
                [
                    {
                        "id": FLOW,
                        "engagement_id": self.flow_tenant,
                        "revision": self.flow_revision,
                        "status": "running",
                    }
                ]
                if args.get("fid") == FLOW and args.get("sid") == self.flow_tenant
                else []
            )
        if "FROM operator_knowledge_documents" in sql:
            assert (
                "engagement_id=:sid" in sql
                and "flow_id=:fid" in sql
                and "owner_id=:owner" in sql
                and "deleted_at IS NULL" in sql
            )
            owned = (
                args.get("sid") == self.flow_doc_tenant
                and args.get("fid") == FLOW
                and args.get("owner") == self.flow_doc_owner
            )
            if "authorization_version=:version" in sql:
                owned &= (
                    args.get("version") == self.authorization_version
                    and args.get("auth_sha") == self.flow_doc_auth_sha
                )
            if "id=:id" in sql:
                owned &= args.get("id") == LOCAL_ID
            matched = (
                args.get("needle") is None
                or args["needle"].lower() in ("needle flow record " + self.flow_content).lower()
            )
            return Rows([self._flow_row()] if owned and matched else [])
        raise AssertionError("Unexpected read SQL: " + sql[:180])


@pytest.fixture
def mounted(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[TestClient, OfflineReadOnly, set[str]]:
    """Real main.app routes/auth with a SELECT-only *synthetic* session factory."""
    assert all(
        sum(
            route.path == path and "GET" in (getattr(route, "methods", set()) or set())
            for route in mounted_main.routes
        )
        == 1
        for path in (
            "/operator/library/documents",
            "/operator/search/knowledge",
            "/flows/{flow_id}/operator-knowledge",
        )
    )
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", SECRET)
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "jwt_issuer", None)
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    monkeypatch.setattr(deps, "_oidc_config", lambda: None)
    revoked: set[str] = set()

    class SyntheticRevocations:
        async def assert_active(self, credential: str, principal_data: dict[str, Any]) -> None:
            if credential in revoked or principal_data["sub"] in revoked:
                from ai_osop.memory.operator_revocation import OperatorRevoked

                raise OperatorRevoked("Synthetic credential revoked")

    monkeypatch.setattr(deps, "_operator_revocation_ledger", lambda: SyntheticRevocations())
    db = OfflineReadOnly()
    memory = SimpleNamespace(_async_session=lambda: db)
    monkeypatch.setitem(deps.state, "orchestrator", SimpleNamespace(session_memory=memory))

    async def fake_signed_roe_guard(
        _db: Any,
        session_id: str,
        *,
        expected_version: int,
    ) -> SimpleNamespace:
        # EXPLICIT STUB: no real Ed25519 signature, live ROE, revocation
        # transaction, or external provider. This only checks caller scopes.
        db.fences.append((session_id, expected_version))
        if (
            db.flow_revoked
            or session_id != db.flow_tenant
            or expected_version != db.authorization_version
        ):
            raise AuthorizationDenied(403, "Fixture ROE currently unavailable")
        return SimpleNamespace(policy_sha256=db.flow_auth_sha)

    monkeypatch.setattr(artifacts_store, "guard_sql", fake_signed_roe_guard)
    # Deliberately use the FULL already-mounted app, not a duplicate router
    # registration. No lifespan/startup or external service is initialized.
    client = TestClient(mounted_main, raise_server_exceptions=False)
    try:
        yield client, db, revoked
    finally:
        client.close()


def auth(subject: str = OWNER, **kw: Any) -> dict[str, str]:
    return {"Authorization": "Bearer " + token(subject, **kw)}


def search_url(flow: bool = True) -> str:
    base = "/operator/search/knowledge?query=needle"
    return (
        (base + "&flow_id=" + FLOW + "&expected_flow_revision=4&expected_authorization_version=7")
        if flow
        else base
    )


def require_inert_item(record: dict[str, Any], source: str) -> None:
    assert record["source"] == source
    assert record["trust"] == "untrusted_human_text"
    assert record["approved_for_agent_context"] is False
    assert record["verified_target_evidence"] is False
    assert record["safe_for_execution"] is False
    assert record["reportable"] is False
    assert (
        not {
            "owner_id",
            "engagement_id",
            "content",
            "untrusted_content",
            "target_effect_verified",
            "approval_id",
        }
        & record.keys()
    )
    assert len(record["sha256"]) == 64


def test_actual_mounted_join_runs_real_sql_stores_and_keeps_citations(
    mounted: tuple[TestClient, OfflineReadOnly, set[str]],
) -> None:
    client, db, _ = mounted
    result = client.get(search_url(), headers=auth())
    assert result.status_code == 200, result.text[:300]
    assert result.headers["cache-control"] == "private, no-store"
    body = result.json()
    assert body["status"] == "metadata_only"
    assert set(body["sources"]) == {"user_global_0039", "flow_local_0019_0038"}
    global_item = body["sources"]["user_global_0039"]["items"][0]
    flow_item = body["sources"]["flow_local_0019_0038"]["items"][0]
    require_inert_item(global_item, "user_global_0039")
    require_inert_item(flow_item, "flow_local_0019_0038")
    assert (global_item["id"], global_item["revision"], global_item["sha256"]) == (
        GLOBAL_ID,
        3,
        digest(NOTE),
    )
    assert (flow_item["id"], flow_item["revision"], flow_item["sha256"]) == (
        LOCAL_ID,
        2,
        digest(NOTE),
    )
    assert flow_item["flow_id"] == FLOW
    assert flow_item["source_flow_revision"] == 4
    assert flow_item["authorization_version"] == 7
    assert "needle" in body["query"]
    assert NOTE not in result.text
    assert body["atomic_cross_source_snapshot"] is False
    assert body["synthesis_performed"] is False
    assert body["independent_target_effect_verified"] is False
    assert db.fences == [(SESSION, 7)]
    assert any("JOIN operator_global_library_versions" in sql for sql, _ in db.query_log)
    assert any("FROM operator_knowledge_documents" in sql for sql, _ in db.query_log)
    assert db.writes == 0


def test_owner_tenant_flow_revocation_or_revision_denies_entire_join(
    mounted: tuple[TestClient, OfflineReadOnly, set[str]],
) -> None:
    client, db, _ = mounted
    for changed, value, status in [
        ("flow_revoked", True, 403),
        ("flow_owner", FOREIGN, 403),
        ("flow_tenant", "eng-other-tenant", 200),
        ("flow_revision", 5, 409),
        ("authorization_version", 8, 403),
        ("flow_doc_owner", FOREIGN, 200),
        ("flow_doc_tenant", "eng-other-tenant", 200),
        ("flow_doc_auth_sha", "c" * 64, 200),
    ]:
        old = getattr(db, changed)
        setattr(db, changed, value)
        response = client.get(search_url(), headers=auth())
        assert response.status_code == status, (changed, response.text[:200])
        if status != 200:
            assert "sources" not in response.json() and NOTE not in response.text
        else:
            # SQL-fenced wrong document ownership/lineage cannot be leaked.
            assert response.json()["sources"]["flow_local_0019_0038"]["items"] == []
        setattr(db, changed, old)
    assert db.writes == 0


def test_global_principal_issuer_boundary_and_no_implicit_flow_authority(
    mounted: tuple[TestClient, OfflineReadOnly, set[str]],
) -> None:
    client, db, _ = mounted
    for header in [auth(FOREIGN), auth(OWNER, issuer="other-issuer")]:
        response = client.get(search_url(flow=False), headers=header)
        assert response.status_code == 200
        assert response.json()["sources"]["user_global_0039"]["items"] == []
        assert set(response.json()["sources"]) == {"user_global_0039"}
    one = client.get(search_url(flow=False), headers=auth())
    assert one.status_code == 200
    assert len(one.json()["sources"]["user_global_0039"]["items"]) == 1
    assert all(
        not sql.startswith("SELECT ") or "operator_knowledge_documents" not in sql
        for sql, _ in db.query_log[-1:]
    )
    db.global_deleted = True
    tombstone = client.get(search_url(flow=False), headers=auth())
    assert tombstone.status_code == 200
    assert tombstone.json()["sources"]["user_global_0039"]["items"] == []


def test_source_citation_metadata_does_not_grant_text_without_explicit_owner_get(
    mounted: tuple[TestClient, OfflineReadOnly, set[str]],
) -> None:
    client, db, _ = mounted
    combined = client.get(search_url(), headers=auth())
    assert combined.status_code == 200
    assert NOTE not in combined.text
    global_raw = client.get("/operator/library/documents/" + GLOBAL_ID, headers=auth())
    assert global_raw.status_code == 200, global_raw.text[:200]
    assert global_raw.json()["content"] == NOTE
    assert global_raw.json()["sha256"] == digest(NOTE)
    local_raw = client.get(
        "/flows/" + FLOW + "/operator-knowledge/" + LOCAL_ID,
        params={"expected_revision": 4, "expected_authorization_version": 7},
        headers=auth(),
    )
    assert local_raw.status_code == 200, local_raw.text[:200]
    assert local_raw.json()["untrusted_content"] == NOTE
    assert local_raw.json()["approved_for_agent_context"] is False
    for subject in (FOREIGN,):
        blocked = client.get("/operator/library/documents/" + GLOBAL_ID, headers=auth(subject))
        assert blocked.status_code == 404
        assert NOTE not in blocked.text
        blocked_flow = client.get(
            "/flows/" + FLOW + "/operator-knowledge/" + LOCAL_ID,
            params={"expected_revision": 4, "expected_authorization_version": 7},
            headers=auth(subject),
        )
        assert blocked_flow.status_code == 403
        assert NOTE not in blocked_flow.text
    assert db.writes == 0


def test_real_jwt_invalid_or_revoked_denies_before_sql(
    mounted: tuple[TestClient, OfflineReadOnly, set[str]],
) -> None:
    client, db, revoked = mounted
    for headers in (
        {},
        auth(signing_key="incorrect-signature"),
        auth(expired=True),
        auth(role="viewer"),
    ):
        db.query_log.clear()
        response = client.get(search_url(), headers=headers)
        assert response.status_code in (401, 403), response.text[:200]
        assert db.query_log == []
        assert "sources" not in response.json()
    revoked.add(OWNER)
    db.query_log.clear()
    response = client.get(search_url(), headers=auth())
    assert response.status_code in (401, 403)
    assert "sources" not in response.json()
    assert db.query_log == []


def test_injected_wrong_lineage_row_is_never_promoted_as_cross_source_citation(
    mounted: tuple[TestClient, OfflineReadOnly, set[str]],
) -> None:
    client, db, _ = mounted
    # Simulate a malicious or inconsistent database adapter returning an item
    # despite SQL's WHERE authorization hash. Production _assert_row must
    # reject it, rather than trusting the synthetic adapter's filters.
    original = db.execute

    async def inconsistent(statement: Any, params: Optional[dict[str, Any]] = None) -> Rows:
        rows = await original(statement, params)
        if "FROM operator_knowledge_documents" in str(statement) and rows.records:
            rows.records[0]["authorization_sha256"] = "0" * 64
        return rows

    db.execute = inconsistent  # type: ignore[method-assign]
    response = client.get(search_url(), headers=auth())
    assert response.status_code == 409, response.text[:200]
    assert "sources" not in response.json()
    assert NOTE not in response.text
    assert db.writes == 0


def test_global_projection_checks_actual_sha_not_merely_source_metadata(
    mounted: tuple[TestClient, OfflineReadOnly, set[str]],
) -> None:
    client, db, _ = mounted
    original = db.execute

    async def changed_global_digest(
        statement: Any,
        params: Optional[dict[str, Any]] = None,
    ) -> Rows:
        rows = await original(statement, params)
        if "JOIN operator_global_library_versions" in str(statement):
            for row in rows.records:
                row["sha256"] = "c" * 64
        return rows

    db.execute = changed_global_digest  # type: ignore[method-assign]
    refused = client.get(search_url(), headers=auth())
    assert refused.status_code == 503
    assert "sources" not in refused.json()
    assert not any("operator_knowledge_documents" in sql for sql, _ in db.query_log)
    assert db.writes == 0


@pytest.mark.parametrize(
    "forgery,expected_status",
    [("digest", 503), ("future_flow_revision", 409), ("both", 409)],
)
def test_flow_citation_sha_and_source_revision_checked_before_unified_projection(
    mounted: tuple[TestClient, OfflineReadOnly, set[str]],
    forgery: str,
    expected_status: int,
) -> None:
    """A substituted original digest and future Flow source revision DENY.

    This is a strict synthetic SQL-result test of the real mounted API and
    actual store, NOT a live PostgreSQL constraint or signer qualification.
    """
    client, db, _ = mounted
    original = db.execute

    async def forged_citation_row(
        statement: Any,
        params: Optional[dict[str, Any]] = None,
    ) -> Rows:
        rows = await original(statement, params)
        if "FROM operator_knowledge_documents" in str(statement):
            for row in rows.records:
                if forgery in ("digest", "both"):
                    row["sha256"] = "0" * 64
                if forgery in ("future_flow_revision", "both"):
                    row["source_flow_revision"] = 900
        return rows

    db.execute = forged_citation_row  # type: ignore[method-assign]
    result = client.get(search_url(), headers=auth())
    assert result.status_code == expected_status
    assert "sources" not in result.json()
    assert NOTE not in result.text
    assert db.writes == 0
