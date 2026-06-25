Start-Process python -ArgumentList "mcp-servers/python/mcp_stub.py --port 8082" -WindowStyle Hidden
Start-Process python -ArgumentList "mcp-servers/python/mcp_stub.py --port 8083" -WindowStyle Hidden
Start-Process python -ArgumentList "mcp-servers/python/mcp_stub.py --port 8084" -WindowStyle Hidden
Start-Process python -ArgumentList "mcp-servers/python/mcp_stub.py --port 8085" -WindowStyle Hidden
Start-Process python -ArgumentList "mcp-servers/python/mcp_stub.py --port 8086" -WindowStyle Hidden
Start-Process python -ArgumentList "mcp-servers/python/mcp_stub.py --port 8087" -WindowStyle Hidden
Start-Process python -ArgumentList "mcp-servers/python/mcp_stub.py --port 8091" -WindowStyle Hidden
Start-Process python -ArgumentList "mcp-servers/python/mcp_stub.py --port 8090" -WindowStyle Hidden
Start-Process python -ArgumentList "mcp-servers/python/mcp_stub.py --port 8092" -WindowStyle Hidden
Start-Process python -ArgumentList "mcp-servers/python/mcp_stub.py --port 8093" -WindowStyle Hidden
Start-Process python -ArgumentList "mcp-servers/python/mcp_stub.py --port 8096" -WindowStyle Hidden
Start-Process python -ArgumentList "mcp-servers/python/mcp_stub.py --port 8097" -WindowStyle Hidden
Start-Process python -ArgumentList "mcp-servers/python/mcp_stub.py --port 8098" -WindowStyle Hidden
Start-Sleep -Seconds 20
Start-Process poetry -ArgumentList "run uvicorn ai_osop.api.main:app --port 8200" -WindowStyle Hidden
