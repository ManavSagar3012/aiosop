import sys
import json
import asyncio
import aiohttp
from typing import Any, Dict

async def execute_spa(target_url: str, method: str, headers: dict, body: str, concurrent_requests: int) -> Dict[str, Any]:
    """Execute real single-packet race condition attack."""
    # Use a TCPConnector with limit to allow high concurrency
    connector = aiohttp.TCPConnector(limit=concurrent_requests)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for _ in range(concurrent_requests):
            tasks.append(session.request(method, target_url, headers=headers, data=body))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        results = []
        for i, resp in enumerate(responses):
            if isinstance(resp, Exception):
                results.append({"index": i, "status": "error", "error": str(resp)})
            else:
                results.append({"index": i, "status": resp.status, "length": resp.content_length})
                
        return {"results": results}

async def handle_request(tool, params):
    if tool == "health":
        return {"status": "healthy"}
    elif tool == "execute_single_packet_attack":
        try:
            return await execute_spa(
                params["target_url"],
                params.get("method", "GET"),
                params.get("headers", {}),
                params.get("body", ""),
                params.get("concurrent_requests", 10)
            )
        except Exception as e:
            return {"error": str(e)}
    return {"error": f"unknown tool: {tool}"}

if __name__ == "__main__":
    # Same simple socket server loop
    import socket
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8098)
    args = parser.parse_args()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", args.port))
    server.listen(1)
    
    loop = asyncio.get_event_loop()
    print(f"Turbo Intruder MCP running on port {args.port}")
    sys.stdout.flush()
    
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
