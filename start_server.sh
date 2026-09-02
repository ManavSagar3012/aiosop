#!/bin/bash
cd "C:/Users/HP/OneDrive/Desktop/burp_mcp/ai-osop"
poetry run uvicorn ai_osop.api.main:app --host 127.0.0.1 --port 8201 2>&1
