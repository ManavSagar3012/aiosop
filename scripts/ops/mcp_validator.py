import asyncio
import httpx

MCP_SERVERS = {
    "burp-mcp": 8081,
    "recon-mcp": 8082,
    "payload-mcp": 8083,
    "nuclei-mcp": 8084,
    "shodan-mcp": 8085,
    "threat-intel-mcp": 8086,
    "security-bridge": 8087,
    "browser-mcp": 8091,
    "source-map-mcp": 8096,
    "cloud-mcp": 8097,
    "turbo-intruder-mcp": 8098
}

async def validate_mcps():
    print("PHASE 5 — MCP VALIDATION\\n")
    async with httpx.AsyncClient(timeout=3.0) as client:
        for name, port in MCP_SERVERS.items():
            print(f"Testing {name} on port {port}...")
            
            # Test 1: Reachable and Initialized
            try:
                init_resp = await client.post(f"http://127.0.0.1:{port}/mcp/initialize", json={})
                if init_resp.status_code == 200:
                    init_data = init_resp.json()
                    tools = init_data.get("tools", [])
                    print(f"  [+] Init successful. Tools available: {[t.get('name') for t in tools]}")
                    
                    if not tools:
                        print(f"  [-] No tools provided by {name}")
                        continue
                        
                    first_tool = tools[0]["name"]
                    
                    # Test 2: Execute test request
                    exec_payload = {
                        "tool_name": first_tool,
                        "parameters": {} # Sending empty params expecting controlled error or success
                    }
                    exec_resp = await client.post(f"http://127.0.0.1:{port}/mcp/execute", json=exec_payload)
                    
                    if exec_resp.status_code in [200, 400, 422, 500]: # Accepting any valid API response structure
                        try:
                            exec_data = exec_resp.json()
                            status = exec_data.get("status", "unknown")
                            if status in ["success", "error", "failed"]:
                                print(f"  [+] Execution response valid. Status: {status}")
                            else:
                                print(f"  [-] Invalid execution response format: {exec_data}")
                        except Exception as e:
                            print(f"  [-] Failed to parse execution JSON: {e}")
                    else:
                        print(f"  [-] Execution request failed with HTTP {exec_resp.status_code}")
                else:
                    print(f"  [-] Init failed with HTTP {init_resp.status_code}")
            except httpx.ConnectError:
                print(f"  [!] DEAD: Connection refused on port {port}")
            except Exception as e:
                print(f"  [!] UNKNOWN ERROR: {type(e).__name__} - {e}")
            print("")

if __name__ == "__main__":
    asyncio.run(validate_mcps())
