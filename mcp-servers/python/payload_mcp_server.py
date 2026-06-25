import sys
import json
import asyncio
from typing import Any, Dict

# Simple MCP protocol implementation for our tool server
async def run_server():
    # Use standard library to minimize dependencies
    # This server will communicate over stdin/stdout
    from mcp.server.fastmcp import FastMCP
    from ai_osop.payload_engine.engine import AdaptivePayloadEngine, PayloadTemplateLibrary
    from ai_osop.core.config import VulnClass

    mcp = FastMCP("payload-mcp")
    engine = AdaptivePayloadEngine()

    @mcp.tool()
    def generate_payload(vuln_type: str, context: str = None) -> Dict[str, Any]:
        """Generate payload templates."""
        try:
            v_type = VulnClass(vuln_type)
            templates = PayloadTemplateLibrary.get_templates(v_type, context)
            return {"payloads": templates}
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    def evaluate_fitness(payload: str, response: str) -> Dict[str, Any]:
        """Evaluate payload effectiveness."""
        try:
            fitness = engine.evaluate(payload, response)
            return {"fitness": fitness}
        except Exception as e:
            return {"error": str(e)}

    # This server expects to be run by an MCP client that pipes I/O
    await mcp.run_stdio()

if __name__ == "__main__":
    asyncio.run(run_server())
