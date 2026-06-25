package main

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/ai-osop/mcp-servers/sdk"
)

func main() {
	server := sdk.NewServer("security-bridge")

	// SQLMap Tool
	server.Register(sdk.Tool{
		Name:           "sqlmap",
		Description:    "Automated SQL injection and database takeover tool.",
		TimeoutSeconds: 1800,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "url", "type": "string", "description": "Target URL", "required": true},
			{"name": "data", "type": "string", "description": "Data string to be sent through POST", "required": false},
			{"name": "batch", "type": "boolean", "description": "Never ask for user input, use the default behavior", "required": false},
			{"name": "dump", "type": "boolean", "description": "Dump DBMS database table entries", "required": false},
		},
		Returns: map[string]any{"data": "object", "status": "string"},
		Handler: func(params map[string]any) any {
			url, _ := params["url"].(string)
			
			// Check if sqlmap is installed
			_, err := exec.LookPath("sqlmap")
			if err != nil {
				return map[string]any{"status": "error", "error": "sqlmap not installed"}
			}

			// Real execution (simplified)
			args := []string{"-u", url, "--batch", "--random-agent"}
			if dump, ok := params["dump"].(bool); ok && dump {
				args = append(args, "--dump")
			}
			output, execErr := exec.Command("sqlmap", args...).CombinedOutput()
			return map[string]any{"status": "success", "raw": string(output), "error": fmt.Sprintf("%v", execErr)}
		},
	})

	// Nmap Tool
	server.Register(sdk.Tool{
		Name:           "nmap",
		Description:    "Network mapper for port scanning and service discovery.",
		TimeoutSeconds: 600,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "target", "type": "string", "description": "Target IP or hostname", "required": true},
			{"name": "fast", "type": "boolean", "description": "Scan fewer ports than the default scan", "required": false},
		},
		Returns: map[string]any{"hosts": "array", "status": "string"},
		Handler: func(params map[string]any) any {
			target, _ := params["target"].(string)
			
			_, err := exec.LookPath("nmap")
			if err != nil {
				return map[string]any{"status": "error", "error": "nmap not installed"}
			}

			args := []string{"-sV", "-T4", "-oJ", "-", target}
			output, _ := exec.Command("nmap", args...).Output()
			var res any
			_ = json.Unmarshal(output, &res)
			return map[string]any{"status": "success", "data": res}
		},
	})

	// FFUF Tool
	server.Register(sdk.Tool{
		Name:           "ffuf",
		Description:    "Fast web fuzzer written in Go.",
		TimeoutSeconds: 600,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "url", "type": "string", "description": "Target URL with FUZZ keyword", "required": true},
			{"name": "wordlist", "type": "string", "description": "Path to wordlist", "required": false},
		},
		Returns: map[string]any{"results": "array", "status": "string"},
		Handler: func(params map[string]any) any {
			url, _ := params["url"].(string)
			wordlist, ok := params["wordlist"].(string)
			if !ok || wordlist == "" {
				wordlist = "common_wordlist.txt"
			}
			
			_, err := exec.LookPath("ffuf")
			if err != nil {
				return map[string]any{"status": "error", "error": "ffuf not installed"}
			}

			// Real execution of ffuf
			args := []string{"-u", url, "-w", wordlist, "-s"}
			output, execErr := exec.Command("ffuf", args...).CombinedOutput()
			var errStr string
			if execErr != nil {
				errStr = execErr.Error()
			}
			return map[string]any{"status": "success", "raw": string(output), "error": errStr}
		},
	})
	// Masscan Tool
	server.Register(sdk.Tool{
		Name:           "masscan",
		Description:    "High-speed port scanner.",
		TimeoutSeconds: 600,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "target", "type": "string", "description": "Target IP range", "required": true},
			{"name": "ports", "type": "string", "description": "Ports to scan", "required": true},
		},
		Returns: map[string]any{"status": "string", "raw": "string"},
		Handler: func(params map[string]any) any {
			target, _ := params["target"].(string)
			ports, _ := params["ports"].(string)
			output, err := exec.Command("masscan", target, "-p", ports).CombinedOutput()
			if err != nil {
				return map[string]any{"status": "error", "error": err.Error()}
			}
			return map[string]any{"status": "success", "raw": string(output)}
		},
	})
	
	// Gobuster Tool
	server.Register(sdk.Tool{
		Name:           "gobuster",
		Description:    "Directory/File busting tool.",
		TimeoutSeconds: 600,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "url", "type": "string", "description": "Target URL", "required": true},
		},
		Returns: map[string]any{"status": "string", "raw": "string"},
		Handler: func(params map[string]any) any {
			url, _ := params["url"].(string)
			output, err := exec.Command("gobuster", "dir", "-u", url, "-w", "common_wordlist.txt").CombinedOutput()
			if err != nil {
				return map[string]any{"status": "error", "error": err.Error()}
			}
			return map[string]any{"status": "success", "raw": string(output)}
		},
	})
	_ = server.Run(":8087")
}
