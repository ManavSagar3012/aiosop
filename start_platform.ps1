Write-Host "Cleaning up previous processes..."
taskkill /F /IM python.exe /T 2>
taskkill /F /IM node.exe /T 2>

Write-Host "Starting MCP Servers..."
# We assume the stubs are located in mcp-servers/python/
 = @(8081, 8082, 8083, 8084, 8085, 8086, 8087, 8090, 8091, 8092, 8093, 8096, 8097, 8098)
foreach ( in ) {
    Start-Process python -ArgumentList "mcp-servers/python/mcp_stub.py --port " -WindowStyle Hidden
}

Write-Host "Starting API..."
Start-Process poetry -ArgumentList "run uvicorn ai_osop.api.main:app --port 8200" -WindowStyle Hidden

Write-Host "Starting UI..."
Start-Process npm -ArgumentList "--prefix ui run dev" -WindowStyle Hidden

Write-Host "Platform started."
