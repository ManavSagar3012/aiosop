import sys
import json
import asyncio
from neo4j import AsyncGraphDatabase
from typing import Any, Dict

# Neo4j Driver (shared with AI-OSOP Core if possible, but for MCP it's isolated)
URI = "bolt://127.0.0.1:7687"
AUTH = ("neo4j", "password")

async def execute_query(query, params=None):
    async with AsyncGraphDatabase.driver(URI, auth=AUTH) as driver:
        async with driver.session() as session:
            result = await session.run(query, params or {})
            return await result.data()

async def handle_request(tool, params):
    if tool == "health":
        return {"status": "healthy"}
    elif tool == "query_graph":
        try:
            return await execute_query(params["query"], params.get("params"))
        except Exception as e:
            return {"error": str(e)}
    elif tool == "get_neighbors":
        try:
            query = "MATCH (n {id: $node_id})-[r]->(m) RETURN r, m"
            return await execute_query(query, {"node_id": params["node_id"]})
        except Exception as e:
            return {"error": str(e)}
    return {"error": f"unknown tool: {tool}"}

if __name__ == "__main__":
    import socket
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8093)
    args = parser.parse_args()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", args.port))
    server.listen(1)
    print(f"Attack Graph MCP running on port {args.port}")
    sys.stdout.flush()
    
    loop = asyncio.get_event_loop()
    
    while True:
        conn, addr = server.accept()
        with conn:
            data = conn.recv(65536)
            if not data: continue
            try:
                req = json.loads(data.decode())
                if "method" in req:
                    result = loop.run_until_complete(handle_request(req["method"], req.get("params", {})))
                    conn.send(json.dumps({"jsonrpc": "2.0", "result": result, "id": req.get("id")}).encode())
            except Exception as e:
                conn.send(json.dumps({"error": str(e)}).encode())
