# start_stack_liveverify.ps1 - start the real MCP servers + API for live verification.
# Mirrors launch_real.ps1 but: no Go rebuild (binaries already built), API on 8200
# (the port the UI + scripts/ops expect), all output logged to .runtime/.
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $root   # scripts/ -> repo root
Set-Location $root

$venvPy = Join-Path $root ".venv\Scripts\python.exe"
$goDir  = Join-Path $root "mcp-servers\go"
$logDir = Join-Path $root ".runtime"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

# Match .env port config (recon on 18082: 8082 is squatted on this host).
$env:OSOP_RECON_MCP_PORT        = "18082"
$env:OSOP_NUCLEI_MCP_PORT       = "8084"
$env:OSOP_SECURITY_BRIDGE_PORT  = "8087"
$env:OSOP_SHODAN_MCP_PORT       = "8085"
$env:OSOP_THREAT_INTEL_MCP_PORT = "8086"
$env:PATH = "C:\Users\HP\go\bin;" + (Join-Path $root ".venv\Scripts") + ";" + $env:PATH

function Start-Mcp {
    param($Name, $Exe, $ProcArgs = @())
    $p = Start-Process -FilePath $Exe -ArgumentList $ProcArgs -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $logDir "$Name.out.log") `
        -RedirectStandardError  (Join-Path $logDir "$Name.err.log") -PassThru
    Write-Host "started $Name pid=$($p.Id)"
}

# Go servers (ports from env above)
Start-Mcp "recon-mcp"        (Join-Path $goDir "recon-mcp.exe")
Start-Mcp "nuclei-mcp"       (Join-Path $goDir "nuclei-mcp.exe")
Start-Mcp "shodan-mcp"       (Join-Path $goDir "shodan-mcp.exe")
Start-Mcp "threat-intel-mcp" (Join-Path $goDir "threat-intel-mcp.exe")
Start-Mcp "security-bridge"  (Join-Path $goDir "security-bridge.exe")

# Python servers (ports via --port; they read OSOP_*_MCP_* only for clients)
Start-Mcp "browser-mcp"     $venvPy "mcp-servers/python/browser_mcp.py --port 8091"
Start-Mcp "source-map-mcp"  $venvPy "mcp-servers/python/source_map_mcp.py --port 8096"
Start-Mcp "turbo-intruder"  $venvPy "mcp-servers/python/turbo_intruder_mcp.py --port 8098"
Start-Mcp "oast-mcp"        $venvPy "mcp-servers/python/oast_mcp.py --port 8099"
Start-Mcp "payload-mcp"     $venvPy "mcp-servers/python/payload_mcp_server.py --port 8083"
Start-Mcp "cloud-mcp"       $venvPy "mcp-servers/python/cloud_mcp.py --port 8097"

Start-Sleep -Seconds 6

# API on 8200 (UI + scripts/ops expect 127.0.0.1:8200)
Start-Mcp "api" $venvPy "-m uvicorn ai_osop.api.main:app --host 127.0.0.1 --port 8200"
Write-Host "API starting on :8200 (log: .runtime\api.err.log)"
