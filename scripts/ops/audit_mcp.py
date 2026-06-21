import httpx

try:
    r = httpx.get('http://127.0.0.1:8091/health', timeout=5.0)
    print(f'Browser MCP Health: {r.status_code}')
    r2 = httpx.post('http://127.0.0.1:8091/mcp/initialize', json={'server_id': 'browser-mcp'})
    print(f'Browser MCP Initialization: {r2.status_code}')
    print(f'Capabilities: {r2.json().get("capabilities")}')
except Exception as e:
    print(f'Browser MCP Error: {e}')
