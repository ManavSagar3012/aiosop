"""Isolated opt-in Redis/Neo4j for joined recovery qualification.

Only freshly allocated, uniquely named containers are controlled. All host
bindings are random loopback ports, no volumes or user data are mounted, no
existing database/daemon workload is stopped, and no image is pulled.
"""

import asyncio
import os
import socket
import time
import uuid
from types import SimpleNamespace

import pytest
from neo4j import AsyncGraphDatabase
from redis.asyncio import Redis

from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory

_OPT_IN = "OSOP_DISPOSABLE_REDIS_GRAPH_20261018"
_REDIS_IMAGE = "redis:7-alpine"
_NEO_IMAGE = "neo4j:5.18-community"


def _private_port(container, key, disallowed):
    container.reload()
    bindings = container.attrs["NetworkSettings"]["Ports"][key]
    assert len(bindings) == 1 and bindings[0]["HostIp"] == "127.0.0.1"
    port = int(bindings[0]["HostPort"])
    assert 1024 <= port <= 65535 and port not in disallowed
    return port


@pytest.fixture(scope="module")
def disposable_redis_graph_services():
    if os.environ.get(_OPT_IN) != "1":
        pytest.skip("Explicit isolated Redis/Neo4j Docker opt-in required")
    import docker

    cli = docker.from_env()
    for image in (_REDIS_IMAGE, _NEO_IMAGE):
        try:
            cli.images.get(image)
        except (docker.errors.ImageNotFound, docker.errors.NotFound):
            # `docker image ls` can expose stale tags whose inspect returns
            # 404. Never silently pull or substitute an application image.
            pytest.skip(f"Disposable service image cannot be inspected: {image}")
    marker = uuid.uuid4().hex[:16]
    names = ("osop-joined-rg-redis-" + marker, "osop-joined-rg-neo-" + marker)
    for name in names:
        assert not cli.containers.list(all=True, filters={"name": name})
    created = []
    try:
        redis_container = cli.containers.run(
            _REDIS_IMAGE,
            name=names[0],
            detach=True,
            remove=False,
            command=["redis-server", "--save", "", "--appendonly", "no"],
            ports={"6379/tcp": ("127.0.0.1", None)},
            volumes={},
            labels={"osop.disposable.qualification": "redis-graph-20261018"},
        )
        created.append(redis_container)
        redis_port = _private_port(redis_container, "6379/tcp", {6379, 6380})
        neo_container = cli.containers.run(
            _NEO_IMAGE,
            name=names[1],
            detach=True,
            remove=False,
            environment={
                "NEO4J_AUTH": "none",  # Only on isolated random loopback binding.
                "NEO4J_server_memory_heap_initial__size": "128m",
                "NEO4J_server_memory_heap_max__size": "256m",
                "NEO4J_server_memory_pagecache_size": "128M",
            },
            ports={"7687/tcp": ("127.0.0.1", None)},
            volumes={},
            labels={"osop.disposable.qualification": "redis-graph-20261018"},
        )
        created.append(neo_container)
        neo_port = _private_port(neo_container, "7687/tcp", {7687, 7688})
        # TCP availability alone is NOT a Neo4j Bolt readiness guarantee.
        for _ in range(80):
            try:
                with socket.create_connection(("127.0.0.1", redis_port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            pytest.fail("Disposable Redis never became reachable")
        yield SimpleNamespace(
            redis_url=f"redis://127.0.0.1:{redis_port}/0",
            graph_url=f"bolt://127.0.0.1:{neo_port}",
            neo_container=neo_container,
            redis_container=redis_container,
        )
    finally:
        # Never stop/delete an existing app service; these are exactly the
        # container objects created in this fixture during this invocation.
        for instance in reversed(created):
            try:
                instance.remove(force=True)
            except docker.errors.NotFound:
                pass


@pytest.fixture
async def joined_redis_graph(disposable_redis_graph_services, monkeypatch):
    sources = disposable_redis_graph_services
    memory = SessionMemory()
    # SessionMemory reconnects via settings after a disconnect. Pin its only
    # possible redis_url to the disposable service, never the application Redis.
    import ai_osop.memory.session_memory as memory_module

    monkeypatch.setattr(memory_module.settings, "redis_uri", sources.redis_url)
    memory._redis = Redis.from_url(
        sources.redis_url,
        decode_responses=True,
        socket_connect_timeout=1,
        socket_timeout=1,
    )
    graph = GraphMemory()
    graph._driver = AsyncGraphDatabase.driver(
        sources.graph_url,
        auth=None,
        connection_timeout=2,
        connection_acquisition_timeout=2,
    )
    try:
        for _ in range(85):
            try:
                await asyncio.wait_for(graph._driver.verify_connectivity(), timeout=2)
                await memory._redis.ping()
                break
            except Exception:
                await asyncio.sleep(0.25)
        else:
            pytest.fail("Fresh disposable Neo4j/Redis did not become service-ready")
        await graph._setup_schema()
        yield SimpleNamespace(graph=graph, memory=memory, services=sources)
    finally:
        await graph.close()
        await memory._redis.aclose()
