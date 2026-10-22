"""Public attack-graph responses must not expose private Neo4j evidence.

No database, network service, model, or target is touched. The real route
serializer runs against explicit hostile in-memory Neo4j-shaped records.
"""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from ai_osop.api.routers import intelligence


SECRET = "PRIVATE_CROSS_IDENTITY_EVIDENCE_and_SESSION_COOKIE_20261018"
ENGAGEMENT = "eng-public-graph-test"


class FakeNode(dict):
    def __init__(self, labels, **properties):
        super().__init__(properties)
        self.labels = labels

    def __iter__(self):
        raise AssertionError("Entire Neo4j property dict must never be serialized")


class FakeRelationship(dict):
    def __init__(self, relation_type, **properties):
        super().__init__(properties)
        self.type = relation_type
        self.element_id = "neo4j-private-" + SECRET

    def __iter__(self):
        raise AssertionError("Relationship properties must never be iterated")


class AsyncRows:
    def __init__(self, values):
        self.values = values

    def __aiter__(self):
        async def records():
            for value in self.values:
                yield value

        return records()


class FakeGraphSession:
    def __init__(self, nodes, relationships):
        self.nodes = nodes
        self.relationships = relationships
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return False

    async def run(self, query, parameters):
        self.calls.append((query, parameters))
        return AsyncRows(self.nodes if "RETURN n ORDER BY" in query else self.relationships)


@pytest.fixture
def graph_harness(monkeypatch):
    graph = FakeGraphSession([], [])
    driver = SimpleNamespace(session=lambda: graph)
    monkeypatch.setitem(
        intelligence.state,
        "orchestrator",
        SimpleNamespace(graph_memory=SimpleNamespace(_driver=driver)),
    )
    before = AsyncMock(return_value=("auth-20261018", "a" * 64, 3))
    after = AsyncMock()
    monkeypatch.setattr(intelligence, "_current_graph_authority", before)
    monkeypatch.setattr(intelligence, "_recheck_graph_authority", after)
    return graph, before, after


@pytest.mark.asyncio
async def test_public_graph_omits_raw_private_node_and_relationship_evidence(graph_harness):
    graph, before, after = graph_harness
    graph.nodes = [
        {
            "n": FakeNode(
                {"Asset", "PrivateRawCredential"},
                id="asset-one",
                engagement_id=ENGAGEMENT,
                name="Public host",
                value="example.test",
                type="domain",
                confidence=0.84,
                status="discovered",
                url=f"https://other-identity.invalid/resource?token={SECRET}",
                request_body={"identity": "foreign", "secret": SECRET},
                response_body=f"GET /private HTTP/1.1 {SECRET}",
                response_headers={"Set-Cookie": SECRET},
                authorization="Bearer " + SECRET,
                metadata=json.dumps({"private_nested": {"secret": SECRET}}),
                proofs=[{"target_effect": SECRET}],
                raw_tool_output=SECRET,
                graphiti_episodes={"agent_messages": [SECRET]},
            )
        },
        {
            "n": FakeNode(
                {"Vulnerability"},
                id="vuln-one",
                engagement_id=ENGAGEMENT,
                title="SQL Injection",
                severity="HIGH",
                confidence=0.9,
                validated=True,
                finding_verified=True,
                independent_effect_verified=True,
                evidence={"cross_identity_body": SECRET},
                private_effect_receipt=SECRET,
                screenshot_path="/private/" + SECRET,
            )
        },
    ]
    graph.relationships = [
        {
            "from_id": "asset-one",
            "to_id": "vuln-one",
            "r": FakeRelationship(
                "HAS_VULNERABILITY",
                evidence={"request": {"body": SECRET}},
                finding_verified=True,
                signed_receipt=SECRET,
                payload='{\\"secret\\": \\"' + SECRET + '\\"}',
            ),
        },
    ]
    result = await intelligence.get_full_graph(ENGAGEMENT, operator={"sub": "operator"})
    assert len(result["nodes"]) == 2
    assert result["nodes"][0] == {
        "id": "asset-one",
        "labels": ["Asset"],
        "properties": {
            "id": "asset-one",
            "type": "Asset",
            "name": "Public host",
            "value": "example.test",
            "status": "discovered",
            "confidence": 0.84,
        },
    }
    assert result["nodes"][1] == {
        "id": "vuln-one",
        "labels": ["Vulnerability"],
        "properties": {
            "id": "vuln-one",
            "type": "Vulnerability",
            "title": "SQL Injection",
            "name": "SQL Injection",
            "severity": "high",
            "confidence": 0.9,
        },
    }
    assert result["edges"] == [
        {
            "id": "edge-1",
            "type": "HAS_VULNERABILITY",
            "from": "asset-one",
            "to": "vuln-one",
            "properties": {},
        },
    ]
    output = json.dumps(result, sort_keys=True)
    for private in (
        SECRET,
        "request_body",
        "response_body",
        "response_headers",
        "authorization",
        "raw_tool_output",
        "finding_verified",
        "evidence",
        "private_effect_receipt",
        "graphiti_episodes",
        "target_effect",
        "PrivateRawCredential",
        "Set-Cookie",
        "screenshot_path",
    ):
        assert private not in output
    before.assert_awaited_once_with(ENGAGEMENT, {"sub": "operator"})
    after.assert_awaited_once_with(ENGAGEMENT, {"sub": "operator"}, ("auth-20261018", "a" * 64, 3))
    assert len(graph.calls) == 2
    assert all(call[1] == {"session_id": ENGAGEMENT, "limit": 501} for call in graph.calls)
    assert "n.engagement_id = $session_id AND m.engagement_id = $session_id" in graph.calls[1][0]


@pytest.mark.asyncio
async def test_graph_rejects_untrusted_display_values_unknown_labels_and_foreign_edges(
    graph_harness,
):
    graph, _, _ = graph_harness
    graph.nodes = [
        {
            "n": FakeNode(
                {"Asset"},
                id="asset-safe",
                engagement_id=ENGAGEMENT,
                name="Bearer " + SECRET,
                value="https://private.invalid/" + SECRET,
                title={"secret": SECRET},
                severity="UNTRUSTED_" + SECRET,
                status={"nested": SECRET},
                confidence=float("inf"),
            )
        },
        {
            "n": FakeNode(
                {"Unknown_PRIVATE_" + SECRET},
                id="asset-hidden",
                engagement_id=ENGAGEMENT,
                name=SECRET,
            )
        },
        {
            "n": FakeNode(
                {"Asset"},
                id="asset-foreign",
                engagement_id="eng-someone-else",
                name="foreign node",
            )
        },
        {
            "n": FakeNode(
                {"Endpoint"},
                id="endpoint-safe",
                engagement_id=ENGAGEMENT,
                name="Simple endpoint",
                confidence=True,
            )
        },
    ]
    graph.relationships = [
        {
            "from_id": "asset-safe",
            "to_id": "asset-foreign",
            "r": FakeRelationship("CAN_ACCESS", secret=SECRET),
        },
        {
            "from_id": "asset-safe",
            "to_id": "asset-hidden",
            "r": FakeRelationship("CAN_ACCESS", secret=SECRET),
        },
        {
            "from_id": "asset-safe",
            "to_id": "endpoint-safe",
            "r": FakeRelationship("PRIVATE_" + SECRET, nested={"secret": SECRET}),
        },
    ]
    output = await intelligence.get_full_graph(ENGAGEMENT, operator={"sub": "operator"})
    assert {node["id"] for node in output["nodes"]} == {"asset-safe", "endpoint-safe"}
    assert output["nodes"][0]["properties"] == {"id": "asset-safe", "type": "Asset"}
    assert output["nodes"][1]["properties"] == {
        "id": "endpoint-safe",
        "type": "Endpoint",
        "name": "Simple endpoint",
    }
    assert output["edges"] == [
        {
            "id": "edge-1",
            "type": "RELATED",
            "from": "asset-safe",
            "to": "endpoint-safe",
            "properties": {},
        },
    ]
    assert SECRET not in json.dumps(output)


@pytest.mark.asyncio
async def test_graph_signed_revocation_after_query_does_not_return_redacted_data(
    graph_harness,
):
    graph, _, final_check = graph_harness
    graph.nodes = [
        {
            "n": FakeNode(
                {"Vulnerability"},
                id="vuln-private",
                engagement_id=ENGAGEMENT,
                title="Safe title",
                evidence=SECRET,
            )
        }
    ]
    final_check.side_effect = HTTPException(status_code=409, detail="authorization revoked")
    with pytest.raises(HTTPException) as failure:
        await intelligence.get_full_graph(ENGAGEMENT, operator={"sub": "operator"})
    assert failure.value.status_code == 409
    assert SECRET not in str(failure.value)


@pytest.mark.asyncio
async def test_graph_rejects_excess_nodes_before_releasing_any_response(graph_harness):
    graph, _, final_check = graph_harness
    graph.nodes = [
        {"n": FakeNode({"Asset"}, id=f"asset-{i:04}", engagement_id=ENGAGEMENT)} for i in range(501)
    ]
    with pytest.raises(HTTPException) as failure:
        await intelligence.get_full_graph(ENGAGEMENT, operator={"sub": "operator"})
    assert failure.value.status_code == 413
    final_check.assert_not_awaited()


def test_graph_display_text_rejects_nested_json_urls_auth_and_unbounded_strings():
    helper = intelligence._display_graph_text
    for value in (
        [SECRET],
        {"private": SECRET},
        "https://private.invalid/?token=" + SECRET,
        "Bearer " + SECRET,
        SECRET,
        "Set-Cookie private",
        "A" * 97,
        "line one\n" + SECRET,
        None,
        True,
        9,
    ):
        assert helper(value) is None
    assert helper("Routine IDOR finding") == "Routine IDOR finding"
