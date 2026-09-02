# Launch all MCP servers.
# Go MCPs ship as .exe alongside this script.
# session-memory-mcp / reporting-mcp / attack-graph-mcp have no .exe — launch via python.
#
# Critical Python MCPs (8096-8098) are registered as boot-critical by the API.
# browser-mcp requires Playwright Chromium — install once if missing.

# Ensure Playwright Chromium is present (browser-mcp fails fast without it).
try {
    $pwCheck = python -c "from playwright.sync_api import sync_playwright; p=sync_playwright().start(); b=p.chromium.launch(headless=True); b.close(); p.stop()" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Playwright Chromium missing — running 'playwright install chromium'..."
        playwright install chromium
    }
} catch {
    Write-Warning "Could not verify Playwright: $_"
}

$mcpServers = @{
    "burp-mcp" = 8081
    "recon-mcp" = 8082
    "payload-mcp" = 8083
    "nuclei-mcp" = 8084
    "shodan-mcp" = 8085
    "browser-mcp" = 8091
    "security-bridge" = 8087
    "threat-intel-mcp" = 8086
    "session-memory-mcp" = 8090
    "reporting-mcp" = 8092
    "attack-graph-mcp" = 8093
}

$pythonOnly = @{
    "browser-mcp"        = "mcp-servers/python/browser_mcp.py"
    "session-memory-mcp" = "mcp-servers/python/session_memory_mcp.py"
    "reporting-mcp"      = "mcp-servers/python/reporting_mcp.py"
    "attack-graph-mcp"   = "mcp-servers/python/attack_graph_mcp.py"
}

# Critical Python MCPs not in the table above (API boot-critical on 8096-8098).
$extraPython = @{
    "source-map-mcp"     = @{ script = "mcp-servers/python/source_map_mcp.py"; port = 8096 }
    "cloud-mcp"          = @{ script = "mcp-servers/python/cloud_mcp.py"; port = 8097 }
    "turbo-intruder-mcp" = @{ script = "mcp-servers/python/turbo_intruder_mcp.py"; port = 8098 }
}

foreach ($name in $mcpServers.Keys) {
    $port = $mcpServers[$name]
    Write-Host "Launching $name on port $port..."
    if ($pythonOnly.ContainsKey($name)) {
        $script = $pythonOnly[$name]
        if (-not (Test-Path $script)) {
            Write-Warning ("Python script missing for {0}: {1}" -f $name, $script)
            continue
        }
        $absScript = (Resolve-Path $script).Path
        Start-Process -FilePath "python" -ArgumentList "$absScript --port $port" -WorkingDirectory $PSScriptRoot -WindowStyle Hidden
    } else {
        $exe = "./$name.exe"
        if (-not (Test-Path $exe)) {
            Write-Warning ("Executable missing for {0}: {1}" -f $name, $exe)
            continue
        }
        $absExe = (Resolve-Path $exe).Path
        Start-Process -FilePath $absExe -ArgumentList "--port $port" -WorkingDirectory $PSScriptRoot -WindowStyle Hidden
    }
}

foreach ($name in $extraPython.Keys) {
    $info = $extraPython[$name]
    $port = $info.port
    $script = $info.script
    Write-Host "Launching $name on port $port..."
    if (-not (Test-Path $script)) {
        Write-Warning ("Python script missing for {0}: {1}" -f $name, $script)
        continue
    }
    $absScript = (Resolve-Path $script).Path
    Start-Process -FilePath "python" -ArgumentList "$absScript --port $port" -WorkingDirectory $PSScriptRoot -WindowStyle Hidden
}
