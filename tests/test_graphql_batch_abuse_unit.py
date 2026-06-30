import asyncio
from types import SimpleNamespace

from ai_osop.agents.graphql_agent import GraphQLAgent


def _capture(store, v):
    store.append(v)
    async def _ok():
        return None
    return _ok()


def _agent(executed_aliases, captured):
    a = GraphQLAgent.__new__(GraphQLAgent)
    a.ctx = SimpleNamespace(
        current_task=SimpleNamespace(engagement_id="eng-gql"),
        graph_memory=SimpleNamespace(add_vulnerability=lambda v: _capture(captured, v)),
    )

    async def _post(url, query):
        # Simulate the server executing `executed_aliases` of the requested aliases.
        return {"data": {f"a{i}": {"ok": True} for i in range(executed_aliases)}}
    a._graphql_post = _post
    return a


def test_batch_abuse_confirmed_when_all_aliases_execute():
    captured = []
    agent = _agent(executed_aliases=20, captured=captured)
    res = asyncio.run(agent._execute_batch_abuse({
        "url": "http://t/graphql", "field": 'login(user:"a", pass:"p{i}")',
        "count": 20, "engagement_id": "eng-gql"}))
    assert res["confirmed"] is True and res["executed"] == 20
    v = captured[0]
    assert v.vuln_type.value in ("graphql_security", "graphql") and v.validated is True
    assert v.cwe == "CWE-799" and v.is_simulated() is False


def test_no_abuse_when_server_limits_batch():
    captured = []
    agent = _agent(executed_aliases=1, captured=captured)  # server only ran 1
    res = asyncio.run(agent._execute_batch_abuse({
        "url": "http://t/graphql", "field": 'login(user:"a", pass:"p{i}")',
        "count": 20, "engagement_id": "eng-gql"}))
    assert res["confirmed"] is False and res["findings_count"] == 0
    assert captured == []
