#!/usr/bin/env python3
"""Woke MCP server for POC."""

import json
import os
from mcp_server_wke import WKE, Tool


def load_settings():
    settings_path = r"C:\Users\HP\AppData\Local\.burp_mcp\config.json"
    if not os.path(settings_path):
        # Fallback to environment variables or defaults
        return {"model": "qwen3.5", "system_prompt": "", "max_tokens": 2000}

    with open(settings_path) as f:
        settings = json.load(f)
    return settings


def main():
    os.environ["CORE_API_KEY"] = os.environ.get("CORE_API_KEY") or "<YOUR_ANTHROPIC_API_KEY>"
    os.environ["CORE_MODEL"] = os.environ.get("CORE_MODEL") or "qwen3.5"

    settings = load_settings()

    client = WKE(
        model=os.environ["CORE_MODEL"],
        api_key=os.environ["CORE_API_KEY"],
        system_prompt=settings.get("system_prompt"),
        max_tokens_per_message=settings.get("max_tokens", 2000),
        temperature=0.5,
        debug=True,
        history_file="C:/Users/HP/AppData/Local/burp_mcp/wke_history.json"
    )

    tools = [
        Tool(
            name="send_mcp_result",
            description="Send MCP output back to Burp MCP",
            input_schema={
                "content": {"type": "string"}
            },
            output_schema={"status": str, "message": str},
            executable=True,
            # args=["-f"] for streaming output to console
        )
    ]

    server = WKE(tools=tools)
    print("Starting Woke MCP server...")
    await server.run()
