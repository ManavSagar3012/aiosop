import sys
import json
import asyncio
import socket
import argparse
from ai_osop.payload_engine.engine import AdaptivePayloadEngine, PayloadTemplateLibrary
from ai_osop.core.config import VulnClass
from ai_osop.adapters.payload_mcp import PayloadMCPAdapter

class MockPayloadMCPAdapter(PayloadMCPAdapter):
    def __init__(self):
        pass

def handle_request(tool, params):
    engine = AdaptivePayloadEngine(mcp_adapter=MockPayloadMCPAdapter())
    
    if tool == "health":
        return {"status": "healthy"}
    elif tool == "generate_payload":
        try:
            vuln_type = VulnClass(params["vuln_type"])
            templates = PayloadTemplateLibrary.get_templates(vuln_type, params.get("context"))
            return {"payloads": templates}
        except Exception as e:
            return {"error": str(e)}
    elif tool == "evaluate_fitness":
        try:
            fitness = engine.evaluate(params["payload"], params["response"])
            return {"fitness": fitness}
        except Exception as e:
            return {"error": str(e)}
    return {"error": f"unknown tool: {tool}"}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8083)
    args = parser.parse_args()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", args.port))
    server.listen(1)
    print(f"Payload MCP running on port {args.port}")
    sys.stdout.flush()
    
    loop = asyncio.get_event_loop()
    
    while True:
        conn, addr = server.accept()
        with conn:
            data = conn.recv(65536)
            if not data: continue
            try:
                # Basic HTTP request parsing to find JSON body
                raw = data.decode()
                parts = raw.split("\r\n\r\n", 1)
                if len(parts) < 2:
                    conn.send("HTTP/1.1 400 Bad Request\r\n\r\n".encode())
                    continue
                req = json.loads(parts[1])
                if "method" in req:
                    result = loop.run_until_complete(handle_request(req["method"], req.get("params", {})))
                    body = json.dumps({"jsonrpc": "2.0", "result": result, "id": req.get("id")}).encode()
                    resp = (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        "\r\n"
                    ).encode() + body
                    conn.send(resp)
                else:
                    conn.send("HTTP/1.1 400 Bad Request\r\n\r\n".encode())
            except Exception as e:
                err = json.dumps({"error": str(e)}).encode()
                resp = (
                    "HTTP/1.1 500 Internal Server Error\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(err)}\r\n"
                    "\r\n"
                ).encode() + err
                conn.send(resp)
