# Launch script for MCP servers
$mcpServers = @{
    "burp-mcp" = 8081
    "recon-mcp" = 8082
    "payload-mcp" = 8083
    "nuclei-mcp" = 8084
    "shodan-mcp" = 8085
}

foreach ($name in $mcpServers.Keys) {
    $port = $mcpServers[$name]
    echo "Launching $name on port $port..."
    Start-Process -FilePath "go" -ArgumentList "run mcp-servers/go/cmd/$name/main.go --port $port" -WindowStyle Hidden
}

# Python MCP Servers
$pythonMcpServers = @{
    "source_map_mcp" = 8096
    "cloud_mcp" = 8097
    "turbo_intruder_mcp" = 8098
}

foreach ($name in $pythonMcpServers.Keys) {
    $port = $pythonMcpServers[$name]
    echo "Launching Python $name on port $port..."
    Start-Process -FilePath "python" -ArgumentList "mcp-servers/python/$name.py --port $port" -WindowStyle Hidden
}
