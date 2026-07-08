import logging
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.auth.session_store import SessionStore, UserSession
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory


@pytest.mark.asyncio
async def test_session_store_save_session_syncs_to_graph():
    """Verify that save_session awaits GraphMemory.sync_user_session with correct session DTO."""
    db_mock = MagicMock()
    db_mock.execute = AsyncMock()
    db_mock.commit = AsyncMock()

    async_session_mock = MagicMock()
    async_session_mock.__aenter__ = AsyncMock(return_value=db_mock)
    async_session_mock.__aexit__ = AsyncMock(return_value=False)

    mock_sm = MagicMock(spec=SessionMemory)
    mock_sm._async_session = MagicMock(return_value=async_session_mock)

    redis_mock = MagicMock()
    redis_mock.setex = AsyncMock()
    mock_sm._redis = redis_mock

    mock_gm = MagicMock(spec=GraphMemory)
    mock_gm.sync_user_session = AsyncMock()

    store = SessionStore(session_memory=mock_sm, graph_memory=mock_gm)

    await store.save_session(
        engagement_id="eng-123", user_label="admin-user", bearer_token="some-token"
    )

    mock_gm.sync_user_session.assert_awaited_once()
    called_session = mock_gm.sync_user_session.call_args[0][0]
    assert isinstance(called_session, UserSession)
    assert called_session.engagement_id == "eng-123"
    assert called_session.user_label == "admin-user"
    assert called_session.bearer_token == "some-token"


@pytest.mark.asyncio
async def test_session_store_delete_session_syncs_to_graph():
    """Verify that delete_session awaits GraphMemory.delete_user_session_node."""
    db_mock = MagicMock()
    result_mock = MagicMock()
    result_mock.rowcount = 1
    db_mock.execute = AsyncMock(return_value=result_mock)
    db_mock.commit = AsyncMock()

    async_session_mock = MagicMock()
    async_session_mock.__aenter__ = AsyncMock(return_value=db_mock)
    async_session_mock.__aexit__ = AsyncMock(return_value=False)

    mock_sm = MagicMock(spec=SessionMemory)
    mock_sm._async_session = MagicMock(return_value=async_session_mock)

    redis_mock = MagicMock()
    redis_mock.delete = AsyncMock()
    mock_sm._redis = redis_mock

    mock_gm = MagicMock(spec=GraphMemory)
    mock_gm.delete_user_session_node = AsyncMock()

    store = SessionStore(session_memory=mock_sm, graph_memory=mock_gm)

    result = await store.delete_session("eng-123", "admin-user")

    assert result is True
    mock_gm.delete_user_session_node.assert_awaited_once_with("eng-123", "admin-user")


@pytest.mark.asyncio
async def test_session_store_no_graph_memory_no_crash():
    """Verify that omitting GraphMemory allows operations to complete successfully without crash."""
    db_mock = MagicMock()
    result_mock = MagicMock()
    result_mock.rowcount = 1
    db_mock.execute = AsyncMock(return_value=result_mock)
    db_mock.commit = AsyncMock()

    async_session_mock = MagicMock()
    async_session_mock.__aenter__ = AsyncMock(return_value=db_mock)
    async_session_mock.__aexit__ = AsyncMock(return_value=False)

    mock_sm = MagicMock(spec=SessionMemory)
    mock_sm._async_session = MagicMock(return_value=async_session_mock)

    redis_mock = MagicMock()
    redis_mock.setex = AsyncMock()
    redis_mock.delete = AsyncMock()
    mock_sm._redis = redis_mock

    store = SessionStore(session_memory=mock_sm, graph_memory=None)

    # save_session should complete normally
    sess = await store.save_session(
        engagement_id="eng-123", user_label="admin-user", bearer_token="some-token"
    )
    assert sess.engagement_id == "eng-123"

    # delete_session should complete normally
    deleted = await store.delete_session("eng-123", "admin-user")
    assert deleted is True


@pytest.mark.asyncio
async def test_session_store_graph_sync_failure_is_suppressed(caplog):
    """Verify that graph sync failures are caught, logged, and don't block the caller."""
    db_mock = MagicMock()
    result_mock = MagicMock()
    result_mock.rowcount = 1
    db_mock.execute = AsyncMock(return_value=result_mock)
    db_mock.commit = AsyncMock()

    async_session_mock = MagicMock()
    async_session_mock.__aenter__ = AsyncMock(return_value=db_mock)
    async_session_mock.__aexit__ = AsyncMock(return_value=False)

    mock_sm = MagicMock(spec=SessionMemory)
    mock_sm._async_session = MagicMock(return_value=async_session_mock)

    redis_mock = MagicMock()
    redis_mock.setex = AsyncMock()
    redis_mock.delete = AsyncMock()
    mock_sm._redis = redis_mock

    mock_gm = MagicMock(spec=GraphMemory)
    mock_gm.sync_user_session = AsyncMock(side_effect=Exception("Neo4j database connection lost"))
    mock_gm.delete_user_session_node = AsyncMock(
        side_effect=Exception("Neo4j node deletion failed")
    )

    store = SessionStore(session_memory=mock_sm, graph_memory=mock_gm)

    with caplog.at_level(logging.ERROR):
        # save_session doesn't throw and logs error
        sess = await store.save_session(
            engagement_id="eng-123", user_label="admin-user", bearer_token="some-token"
        )
        assert sess.engagement_id == "eng-123"
        assert any("Failed to sync session to GraphMemory" in rec.message for rec in caplog.records)

    caplog.clear()

    with caplog.at_level(logging.ERROR):
        # delete_session doesn't throw and logs error
        deleted = await store.delete_session("eng-123", "admin-user")
        assert deleted is True
        assert any(
            "Failed to delete session in GraphMemory" in rec.message for rec in caplog.records
        )


@pytest.mark.asyncio
async def test_graph_memory_sync_user_session():
    """Verify GraphMemory.sync_user_session constructs and runs correct Cypher query and parameters."""
    queries_run = []

    class MockSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            return False

        async def run(self, query, parameters=None):
            queries_run.append((query, parameters))
            return MagicMock()

    mock_driver = MagicMock()
    mock_driver.session = MagicMock(return_value=MockSession())

    # Build GraphMemory and inject mock driver
    gm = GraphMemory()
    gm._driver = mock_driver

    # 1. Test bearer token session with admin user
    session_bearer = UserSession(
        engagement_id="eng-123",
        user_label="test-admin-user",
        cookies=[],
        bearer_token="secret-token",
        local_storage={},
        session_storage={},
        csrf_token="",
        extra_headers={},
        user_agent="",
        captured_at=datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc),
        expires_at=datetime(2026, 7, 8, 13, 0, 0, tzinfo=timezone.utc),
        metadata_blob={},
    )

    await gm.sync_user_session(session_bearer)

    assert len(queries_run) == 1
    query, params = queries_run[0]

    assert "MERGE (i:Identity {id: $identity_id})" in query
    assert "MERGE (s:Session {id: $session_id})" in query
    assert "MERGE (c:Credential {id: $credential_id})" in query
    assert "MERGE (r:Role {id: $role_id})" in query
    assert "MERGE (s)-[:AUTHENTICATED_AS]->(i)" in query
    assert "MERGE (i)-[:HAS_CREDENTIAL]->(c)" in query
    assert "MERGE (i)-[:HAS_ROLE]->(r)" in query

    assert params["identity_id"] == "identity-eng-123-test-admin-user"
    assert params["session_id"] == "session-eng-123-test-admin-user"
    assert params["credential_id"] == "credential-eng-123-test-admin-user"
    assert params["role_id"] == "role-eng-123-admin"
    assert params["user_label"] == "test-admin-user"
    assert params["engagement_id"] == "eng-123"
    assert params["status"] == "active"
    assert params["captured_at"] == session_bearer.captured_at.isoformat()
    assert params["expires_at"] == session_bearer.expires_at.isoformat()
    assert params["cred_type"] == "bearer"
    assert params["role_name"] == "admin"

    # 2. Test cookie session with standard user
    queries_run.clear()
    session_cookie = UserSession(
        engagement_id="eng-123",
        user_label="test-standard-user",
        cookies=[{"name": "session_id", "value": "xyz"}],
        bearer_token="",
        local_storage={},
        session_storage={},
        csrf_token="",
        extra_headers={},
        user_agent="",
        captured_at=None,
        expires_at=None,
        metadata_blob={},
    )

    await gm.sync_user_session(session_cookie)

    assert len(queries_run) == 1
    _, params = queries_run[0]
    assert params["cred_type"] == "cookie"
    assert params["role_name"] == "standard"
    assert params["captured_at"] is None
    assert params["expires_at"] is None

    # 3. Test anonymous session
    queries_run.clear()
    session_anon = UserSession(
        engagement_id="eng-123",
        user_label="anon-user",
        cookies=[],
        bearer_token="",
        local_storage={},
        session_storage={},
        csrf_token="",
        extra_headers={},
        user_agent="",
        captured_at=None,
        expires_at=None,
        metadata_blob={},
    )

    await gm.sync_user_session(session_anon)

    assert len(queries_run) == 1
    _, params = queries_run[0]
    assert params["cred_type"] == "anonymous"


@pytest.mark.asyncio
async def test_graph_memory_delete_user_session_node():
    """Verify GraphMemory.delete_user_session_node constructs and runs correct Cypher query and parameters."""
    queries_run = []

    class MockSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            return False

        async def run(self, query, parameters=None):
            queries_run.append((query, parameters))
            return MagicMock()

    mock_driver = MagicMock()
    mock_driver.session = MagicMock(return_value=MockSession())

    # Build GraphMemory and inject mock driver
    gm = GraphMemory()
    gm._driver = mock_driver

    await gm.delete_user_session_node("eng-123", "test-user")

    assert len(queries_run) == 1
    query, params = queries_run[0]

    assert "OPTIONAL MATCH (s:Session {id: $session_id})" in query
    assert "SET s.status = 'expired'" in query
    assert "OPTIONAL MATCH (c:Credential {id: $credential_id})" in query
    assert "DETACH DELETE c" in query

    assert params["session_id"] == "session-eng-123-test-user"
    assert params["credential_id"] == "credential-eng-123-test-user"
