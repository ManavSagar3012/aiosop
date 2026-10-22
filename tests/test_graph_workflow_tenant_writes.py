"""Graph workflow writers cannot link another engagement's nodes by ID."""

from types import SimpleNamespace

import pytest

from ai_osop.core.models import Workflow, WorkflowStep, WorkflowTransition
from ai_osop.memory.graph_memory import GraphMemory


class Session:
    def __init__(self):
        self.statements = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def run(self, cypher, args):
        self.statements.append((cypher, args))
        return SimpleNamespace(single=self.single)

    async def single(self):
        return {"id": "synthetic-record"}


@pytest.mark.asyncio
async def test_workflow_graph_writer_never_reassigns_foreign_unique_id():
    session = Session()
    graph = GraphMemory.__new__(GraphMemory)
    graph._driver = SimpleNamespace(session=lambda: session)
    await graph.add_workflow(Workflow(
        id="wf-original", name="Original source", role="owner-a",
        engagement_id="eng-original",
    ))
    cypher, args = session.statements[-1]
    assert "MERGE (w:Workflow {id: $id, engagement_id: $engagement_id})" in cypher
    assert args["engagement_id"] == "eng-original"


@pytest.mark.asyncio
async def test_step_and_transition_edges_restrict_both_ends_to_same_tenant():
    session = Session()
    graph = GraphMemory.__new__(GraphMemory)
    graph._driver = SimpleNamespace(session=lambda: session)
    await graph.add_workflow_step(WorkflowStep(
        id="step-one", workflow_id="wf-original", endpoint_id="ep-one",
        order=0, action_type="NAVIGATE", engagement_id="eng-original",
    ))
    cypher, args = session.statements[-1]
    assert "MERGE (s:Step {id: $id, engagement_id: $engagement_id," in cypher
    assert "workflow_id: $workflow_id, endpoint_id: $endpoint_id})" in cypher
    assert "Workflow {id: $workflow_id, engagement_id: $engagement_id}" in cypher
    assert "Endpoint {id: $endpoint_id, engagement_id: $engagement_id}" in cypher
    assert args["engagement_id"] == "eng-original"
    await graph.add_workflow_transition(WorkflowTransition(
        id="transition-one", from_step_id="step-one", to_step_id="step-two",
        trigger="navigate", engagement_id="eng-original",
    ))
    cypher, args = session.statements[-1]
    assert "Step {id: $from_step_id, engagement_id: $engagement_id}" in cypher
    assert "Step {id: $to_step_id, engagement_id: $engagement_id}" in cypher
    assert args["engagement_id"] == "eng-original"


@pytest.mark.asyncio
async def test_evidence_writer_cannot_move_or_link_foreign_tenant_artifact():
    session = Session()
    graph = GraphMemory.__new__(GraphMemory)
    graph._driver = SimpleNamespace(session=lambda: session)
    await graph.attach_evidence_to_step(
        step_id="step-one", evidence_type="har", path="evidence/approved.har",
        engagement_id="eng-original", workflow_id="wf-original",
    )
    cypher, args = session.statements[-1]
    assert "MERGE (ev:Evidence {id: $id, engagement_id: $engagement_id})" in cypher
    assert "Step {id: $step_id, engagement_id: $engagement_id" in cypher
    assert "Workflow {id: $workflow_id, engagement_id: $engagement_id}" in cypher
    assert args["engagement_id"] == "eng-original"
