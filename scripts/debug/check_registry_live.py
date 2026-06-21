
import asyncio
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.core.config import settings

async def check_registry():
    registry = MCPRegistry()
    
    # Simulate api/main.py registration
    servers = [
        ("burp-mcp", settings.burp_mcp_host, settings.burp_mcp_port, settings.burp_api_key),
        ("recon-mcp", settings.recon_mcp_host, settings.recon_mcp_port, None),
        ("payload-mcp", settings.payload_mcp_host, settings.payload_mcp_port, None),
        ("nuclei-mcp", settings.nuclei_mcp_host, settings.nuclei_mcp_port, None),
        ("shodan-mcp", settings.shodan_mcp_host, settings.shodan_mcp_port, settings.shodan_api_key),
        ("browser-mcp", "127.0.0.1", 8091, None),
        ("security-bridge", "127.0.0.1", 8087, None),
        ("threat-intel-mcp", "127.0.0.1", 8086, None),
    ]
    
    print("Attempting to register servers...")
    for server_id, host, port, token in servers:
        try:
            await registry.register_server(server_id, host, port, token)
            print(f"Registered {server_id} at {host}:{port}")
        except Exception as e:
            print(f"Failed to register {server_id}: {e}")
            
    print("\nMCP Registry servers:", list(registry._servers.keys()))
    
    if "browser-mcp" in registry._servers:
        print("browser-mcp appears in registry.")
    else:
        print("browser-mcp MISSING from registry.")

if __name__ == "__main__":
    asyncio.run(check_registry())
