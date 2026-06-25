"""AI-OSOP Graph Tracing and Observability Instrumentation Script

This script wraps Redis, Postgres, and Neo4j drivers with timing instrumentation
to satisfy Sprint 6.5 Memory Observability requirements.
"""

import os
import re

os.chdir("C:/Users/HP/OneDrive/Desktop/burp_mcp/ai-osop")

# ==================== Session Memory (Redis + Postgres) ====================
with open("src/ai_osop/memory/session_memory.py", "r", encoding="utf-8") as f:
    sm = f.read()

# Add time import if missing in module-level
if "import time\n" not in sm.split("class SessionMemory:")[0]:
    sm = sm.replace("import structlog", "import time\nimport structlog")

# Insert wrapper classes before SessionMemory class
wrapper_code = '''
class _TimedPostgresSession:
    """Wraps an async session context manager to record Postgres latency."""
    def __init__(self, session, operation_name: str = "transaction"):
        self._session = session
        self._operation_name = operation_name
        self._start = None

    async def __aenter__(self):
        self._start = time.perf_counter()
        return await self._session.__aenter__()

    async def __aexit__(self, *args):
        result = await self._session.__aexit__(*args)
        if self._start is not None:
            record_postgres_latency(self._operation_name, time.perf_counter() - self._start)
        return result


class _TimedPostgresSessionMaker:
    """Wraps sessionmaker to return timed sessions."""
    def __init__(self, sessionmaker, operation_name: str = "transaction"):
        self._sm = sessionmaker
        self._operation_name = operation_name

    def __call__(self, *args, **kwargs):
        return _TimedPostgresSession(self._sm(*args, **kwargs), self._operation_name)


def _wrap_redis_for_metrics(redis_client):
    """Monkey-patch common Redis async methods to record latency metrics."""
    import time as _time
    methods = [
        "get", "set", "rpush", "lrange", "keys", "lrem", "delete", "ping",
        "setnx", "eval", "hset", "hgetall", "hincrby", "publish", "zadd",
        "zrange", "zrem", "hget", "hdel", "sadd", "sismember", "smembers",
    ]
    write_methods = {"set", "rpush", "lrem", "delete", "setnx", "hset", "hincrby",
                     "publish", "zadd", "zrem", "hdel", "sadd"}
    for method_name in methods:
        original = getattr(redis_client, method_name, None)
        if original is None:
            continue
        async def _timed_wrapper(*args, __original=original, __name=method_name, **kwargs):
            start = _time.perf_counter()
            result = await __original(*args, **kwargs)
            op_type = "write" if __name in write_methods else "read"
            record_redis_latency(op_type, _time.perf_counter() - start)
            return result
        setattr(redis_client, method_name, _timed_wrapper)
    return redis_client


class SessionMemory:
'''

sm = sm.replace("class SessionMemory:", wrapper_code)

# Wrap _async_session creation in connect()
sm = sm.replace(
    '''self._async_session = sessionmaker(
                self._pg_engine, class_=AsyncSession, expire_on_commit=False
            )''',
    '''self._async_session = _TimedPostgresSessionMaker(
                sessionmaker(
                    self._pg_engine, class_=AsyncSession, expire_on_commit=False
                )
            )'''
)

# Wrap Redis after connection
sm = sm.replace(
    '''self._redis = redis.from_url(
                settings.redis_uri, decode_responses=True, max_connections=50
            )''',
    '''self._redis = redis.from_url(
                settings.redis_uri, decode_responses=True, max_connections=50
            )
            self._redis = _wrap_redis_for_metrics(self._redis)'''
)

with open("src/ai_osop/memory/session_memory.py", "w", encoding="utf-8") as f:
    f.write(sm)

print("session_memory.py instrumented")

# ==================== Graph Memory (Neo4j) ====================
with open("src/ai_osop/memory/graph_memory.py", "r", encoding="utf-8") as f:
    gm = f.read()

# Add time import if missing
if "import time\n" not in gm.split("class GraphMemory:")[0]:
    gm = gm.replace("import structlog", "import time\nimport structlog")

# Add imports for observability if missing
if "record_graph_latency" not in gm:
    gm = gm.replace(
        "from ai_osop.core.tracing import trace_span",
        "from ai_osop.core.tracing import trace_span\nfrom ai_osop.core.observability import record_graph_latency"
    )

# Insert Neo4j wrappers before GraphMemory class
neo_wrapper = '''
class _TimedNeo4jSession:
    """Wraps a Neo4j async session to record graph latency."""
    def __init__(self, session, operation_name: str = "query"):
        self._session = session
        self._operation_name = operation_name
        self._start = None

    async def __aenter__(self):
        self._start = time.perf_counter()
        return await self._session.__aenter__()

    async def __aexit__(self, *args):
        result = await self._session.__aexit__(*args)
        if self._start is not None:
            record_graph_latency(self._operation_name, time.perf_counter() - self._start)
        return result


class _TimedNeo4jDriver:
    """Wraps a Neo4j driver to return timed sessions."""
    def __init__(self, driver):
        self._driver = driver

    def session(self, *args, **kwargs):
        return _TimedNeo4jSession(self._driver.session(*args, **kwargs), "query")

    async def verify_connectivity(self, *args, **kwargs):
        return await self._driver.verify_connectivity(*args, **kwargs)

    async def close(self, *args, **kwargs):
        return await self._driver.close(*args, **kwargs)


class GraphMemory:
'''

gm = gm.replace("class GraphMemory:", neo_wrapper)

# Wrap driver creation in connect()
gm = gm.replace(
    '''self._driver = AsyncGraphDatabase.driver(
                settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
            )''',
    '''self._driver = _TimedNeo4jDriver(
                AsyncGraphDatabase.driver(
                    settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
                )
            )'''
)

with open("src/ai_osop/memory/graph_memory.py", "w", encoding="utf-8") as f:
    f.write(gm)

print("graph_memory.py instrumented")
