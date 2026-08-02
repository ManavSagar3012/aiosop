# DEPRECATED (AIOSOP-LAUNCHER-001, 2026-07-03): this launcher starts mcp_stub.py
# (tools: []) on EVERY MCP port, then the API — i.e. the WHOLE platform on no-op stubs.
# Health/readiness pass while nothing real runs (every scan gets zero tools, no findings).
# Use launch_real.ps1 (validated real servers + honest stubs only where the real impl
# would fabricate) or launch_all_mcp_fixed.ps1. This script now refuses to run without
# -Force so it cannot be used by accident.
param([switch]$Force)
if (-not $Force) {
    Write-Warning "launch_all.ps1 is DEPRECATED: it starts all-stub mcp_stub.py (tools:[]) on every port. Use launch_real.ps1. Re-run with -Force only if you deliberately want an all-stub tier for a transport smoke test."
    exit 1
}

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
