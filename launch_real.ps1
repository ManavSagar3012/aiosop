# launch_real.ps1 — start AI-OSOP with the REAL tooling layer.
#
# Supersedes launch_all.ps1, which started mcp_stub.py (a no-op returning an empty
# toolset) on every port. This launcher starts the validated-real servers and only
# falls back to a stub where no real implementation exists yet. See
# TOOLING_CAPABILITY_MATRIX.md / TOOLING_CERTIFICATE.md for the reality evidence.
#
# Reality status per server (2026-06-24):
#   recon-mcp         8082  REAL  (native Go: TCP connect scan, httpx probe, crt.sh, wayback)
#   nuclei-mcp        8084  REAL  (Go: exec real nuclei engine; honors -t templates)
#   browser-mcp       8091  REAL  (Playwright/Chromium; playwright now installed in .venv)
#   burp-mcp          8081  REAL  (Burp Suite app + MCP extension — started separately by operator)
#   source-map-mcp    8096  REAL  (Python: real HTTP fetch, regex parse, sourcemap extraction)
#   shodan-mcp        8085  REAL  (Go: real api.shodan.io calls; honest-empty without key)
#   threat-intel-mcp  8086  REAL  (Go: real NVD + CISA KEV REST calls)
#   security-bridge   8087  PARTIAL (Go: real os/exec for sqlmap/nmap; honest-error if missing;
#                         masscan/gobuster/nikto/wpscan/katana/js_analyze are stubbed)
#   turbo-intruder    8098  STUB  (Python: simulated race-condition responses, not real raw sockets)
#   payload-mcp       8083  STUB  (Go binary is a mock returning hardcoded XSS payload & fitness 0.8;
#                         real engine exists in src/ai_osop/payload_engine/engine.py but unwired)
#   cloud-mcp         8097  STUB  (Python: hardcoded AWS IAM findings, no live cloud API)
#   session-memory    8090  STUB  (Python: returns simulated "Operation successful" message)
#   reporting-mcp     8092  STUB  (Python: returns fake internal report URL)
#   attack-graph      8093  STUB  (Python: returns empty simulated graph)
#
# Usage:  powershell -ExecutionPolicy Bypass -File launch_real.ps1

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$venvPy = Join-Path $root ".venv\Scripts\python.exe"
$goDir  = Join-Path $root "mcp-servers\go"

Write-Host "[1/5] Ensuring backing services (Redis/Neo4j/Postgres) are up..."
docker compose up -d neo4j redis postgres | Out-Null

Write-Host "[2/5] Building real Go MCP servers (recon-mcp, nuclei-mcp)..."
Push-Location $goDir
go build -o recon-mcp.exe ./cmd/recon-mcp
go build -o nuclei-mcp.exe ./cmd/nuclei-mcp
Pop-Location

Write-Host "[3/5] Starting REAL MCP servers..."
# Ensure nuclei binary is discoverable by nuclei-mcp (Go binary shells out to `nuclei`)
# Ensure sqlmap binary is discoverable by security-bridge (Python .venv provides sqlmap.exe)
# Ensure ffuf binary is discoverable by security-bridge (Go bin provides ffuf.exe)
$env:PATH = "C:\Users\HP\go\bin;" + (Join-Path $root ".venv\Scripts") + ";" + $env:PATH

# Core Go servers (hardcoded ports in their main.go)
Start-Process -FilePath (Join-Path $goDir "recon-mcp.exe")  -WindowStyle Hidden
Start-Process -FilePath (Join-Path $goDir "nuclei-mcp.exe") -WindowStyle Hidden
# Real auxiliary Go servers (root .exe built from mcp-servers/go/cmd/*)
Start-Process -FilePath (Join-Path $root "shodan-mcp.exe") -WindowStyle Hidden
Start-Process -FilePath (Join-Path $root "threat-intel-mcp.exe") -WindowStyle Hidden
Start-Process -FilePath (Join-Path $root "security-bridge.exe") -WindowStyle Hidden

# browser-mcp (real Playwright) on :8091
Start-Process -FilePath $venvPy -ArgumentList "mcp-servers/python/browser_mcp.py --port 8091" -WindowStyle Hidden
# source-map (real .js.map fetch+parse) on :8096
Start-Process -FilePath $venvPy -ArgumentList "mcp-servers/python/source_map_mcp.py --port 8096" -WindowStyle Hidden
# turbo-intruder (SIMULATED — not real raw sockets) on :8098. Left running for API compatibility,
# but classified STUB in all certificates. Do NOT mark REAL without rewriting execute_spa to raw sockets.
Start-Process -FilePath $venvPy -ArgumentList "mcp-servers/python/turbo_intruder_mcp.py --port 8098" -WindowStyle Hidden

Write-Host "[4/5] Starting stubs ONLY for ports without a validated real server..."
# Deliberately stubbed because the available "real" implementations are mocks/simulations
# that would be LESS honest than a stub (which returns tools: []).
# payload-mcp: Go binary is a mock; real engine exists but unwired.
# cloud-mcp: hardcoded AWS data.
# session-memory / reporting / attack-graph: simulated responses.
foreach ($port in 8090, 8092, 8093, 8097) {
    Start-Process -FilePath $venvPy -ArgumentList "mcp-servers/python/mcp_stub.py --port $port" -WindowStyle Hidden
}
Start-Process -FilePath $venvPy -ArgumentList "mcp-servers/python/payload_mcp.py --port 8083" -WindowStyle Hidden

Start-Sleep -Seconds 8

Write-Host "[5/5] Starting AI-OSOP API on :8200..."
Start-Process -FilePath $venvPy -ArgumentList "-m uvicorn ai_osop.api.main:app --host 127.0.0.1 --port 8200" -WindowStyle Hidden

Start-Sleep -Seconds 20
Write-Host "Done. Verify tooling reality with:  curl http://127.0.0.1:8200/health/tooling"
