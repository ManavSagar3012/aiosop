package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"

	"github.com/ai-osop/mcp-servers/sdk"
)

func main() {
	server := sdk.NewServer("security-bridge")

	// SQLMap Tool
	server.Register(sdk.Tool{
		Name:           "sqlmap",
		Description:    "Automated SQL injection and database takeover tool. Returns a parsed verdict (injectable, parameter, dbms, techniques, payloads).",
		TimeoutSeconds: 1800,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "url", "type": "string", "description": "Target URL", "required": true},
			{"name": "data", "type": "string", "description": "Data string to be sent through POST (whitespace-free)", "required": false},
			{"name": "level", "type": "number", "description": "Detection depth 1-5 (default 1). Higher tests more params/headers.", "required": false},
			{"name": "risk", "type": "number", "description": "Risk of tests 1-3 (default 1). Higher includes heavier payloads.", "required": false},
			{"name": "batch", "type": "boolean", "description": "Never ask for user input, use the default behavior", "required": false},
			{"name": "dump", "type": "boolean", "description": "Dump DBMS database table entries", "required": false},
		},
		Returns: map[string]any{"data": "object", "status": "string"},
		Handler: func(params map[string]any) any {
			url, _ := params["url"].(string)
			_, err := exec.LookPath("sqlmap")
			if err != nil {
				return map[string]any{"status": "error", "error": "sqlmap not installed"}
			}
			args := []string{"-u", url, "--batch", "--random-agent"}
			// level/risk arrive as JSON numbers (float64). Clamp to sqlmap's valid
			// ranges and format as integer flags here so they never pass through the
			// string argument-injection sanitizer and can't be tampered with.
			if lvl, ok := params["level"].(float64); ok {
				args = append(args, fmt.Sprintf("--level=%d", clampInt(int(lvl), 1, 5)))
			}
			if rk, ok := params["risk"].(float64); ok {
				args = append(args, fmt.Sprintf("--risk=%d", clampInt(int(rk), 1, 3)))
			}
			if data, ok := params["data"].(string); ok && data != "" {
				args = append(args, fmt.Sprintf("--data=%s", data))
			}
			if dump, ok := params["dump"].(bool); ok && dump {
				args = append(args, "--dump")
			}
			output, execErr := exec.Command("sqlmap", args...).CombinedOutput()
			raw := string(output)
			data := parseSqlmapOutput(raw)
			return map[string]any{
				"status": "success",
				"data":   data,
				"raw":    raw,
				"error":  fmt.Sprintf("%v", execErr),
			}
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
			wordlist, _ := params["wordlist"].(string)
			if wordlist == "" {
				wordlist = "common.txt"
			}
			_, err := exec.LookPath("ffuf")
			if err != nil {
				return map[string]any{"status": "error", "error": "ffuf not installed"}
			}
			args := []string{"-u", url, "-w", wordlist, "-o", "-", "-of", "json"}
			output, execErr := exec.Command("ffuf", args...).CombinedOutput()
			var res any
			_ = json.Unmarshal(output, &res)
			return map[string]any{"status": "success", "data": res, "raw": string(output), "error": fmt.Sprintf("%v", execErr)}
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
		Returns: map[string]any{"status": "string", "hosts": "array"},
		Handler: func(params map[string]any) any {
			target, _ := params["target"].(string)
			ports, _ := params["ports"].(string)
			_, err := exec.LookPath("masscan")
			if err != nil {
				return map[string]any{"status": "error", "error": "masscan not installed"}
			}
			args := []string{target, "-p", ports, "-oJ", "-"}
			output, execErr := exec.Command("masscan", args...).CombinedOutput()
			var res any
			_ = json.Unmarshal(output, &res)
			return map[string]any{"status": "success", "data": res, "raw": string(output), "error": fmt.Sprintf("%v", execErr)}
		},
	})

	// Gobuster Tool
	server.Register(sdk.Tool{
		Name:           "gobuster",
		Description:    "Directory/File, DNS and VHost busting tool.",
		TimeoutSeconds: 600,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "url", "type": "string", "description": "Target URL", "required": true},
			{"name": "wordlist", "type": "string", "description": "Path to wordlist", "required": false},
			{"name": "mode", "type": "string", "description": "Mode: dir, dns, fuzz, vhost (default: dir)", "required": false},
		},
		Returns: map[string]any{"status": "string", "found": "array"},
		Handler: func(params map[string]any) any {
			url, _ := params["url"].(string)
			wordlist, _ := params["wordlist"].(string)
			mode, _ := params["mode"].(string)
			if mode == "" {
				mode = "dir"
			}
			if wordlist == "" {
				wordlist = "common.txt"
			}
			_, err := exec.LookPath("gobuster")
			if err != nil {
				return map[string]any{"status": "error", "error": "gobuster not installed"}
			}
			args := []string{mode, "-u", url, "-w", wordlist, "-o", "-"}
			output, execErr := exec.Command("gobuster", args...).CombinedOutput()
			var res any
			_ = json.Unmarshal(output, &res)
			return map[string]any{"status": "success", "data": res, "raw": string(output), "error": fmt.Sprintf("%v", execErr)}
		},
	})

	// Nikto Tool
	server.Register(sdk.Tool{
		Name:           "nikto",
		Description:    "Web server scanner which performs comprehensive tests.",
		TimeoutSeconds: 1200,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "host", "type": "string", "description": "Target host", "required": true},
		},
		Returns: map[string]any{"status": "string", "vulnerabilities": "array"},
		Handler: func(params map[string]any) any {
			host, _ := params["host"].(string)
			_, err := exec.LookPath("nikto")
			if err != nil {
				return map[string]any{"status": "error", "error": "nikto not installed"}
			}
			output, execErr := exec.Command("nikto", "-h", host, "-Format", "json").CombinedOutput()
			var res any
			_ = json.Unmarshal(output, &res)
			return map[string]any{"status": "success", "data": res, "raw": string(output), "error": fmt.Sprintf("%v", execErr)}
		},
	})

	// WPScan Tool
	server.Register(sdk.Tool{
		Name:           "wpscan",
		Description:    "WordPress security scanner.",
		TimeoutSeconds: 1200,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "url", "type": "string", "description": "Target WordPress URL", "required": true},
		},
		Returns: map[string]any{"status": "string", "findings": "array"},
		Handler: func(params map[string]any) any {
			url, _ := params["url"].(string)
			_, err := exec.LookPath("wpscan")
			if err != nil {
				return map[string]any{"status": "error", "error": "wpscan not installed"}
			}
			output, execErr := exec.Command("wpscan", "--url", url, "--format", "json").CombinedOutput()
			var res any
			_ = json.Unmarshal(output, &res)
			return map[string]any{"status": "success", "data": res, "raw": string(output), "error": fmt.Sprintf("%v", execErr)}
		},
	})

	// Katana Crawler Tool
	server.Register(sdk.Tool{
		Name:           "katana_crawl",
		Description:    "Deep web crawler to discover hidden endpoints and JS files.",
		TimeoutSeconds: 600,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "url", "type": "string", "description": "Starting URL", "required": true},
			{"name": "depth", "type": "integer", "description": "Crawl depth", "required": false},
			{"name": "js_crawl", "type": "boolean", "description": "Enable JavaScript crawling", "required": false},
		},
		Returns: map[string]any{"status": "string", "endpoints": "array", "js_files": "array"},
		Handler: func(params map[string]any) any {
			url, _ := params["url"].(string)
			depth, _ := params["depth"].(float64)
			jsCrawl, _ := params["js_crawl"].(bool)
			if depth == 0 {
				depth = 3
			}
			_, err := exec.LookPath("katana")
			if err != nil {
				return map[string]any{"status": "error", "error": "katana not installed"}
			}
			args := []string{"-u", url, "-d", fmt.Sprintf("%d", int(depth)), "-j"}
			if jsCrawl {
				args = append(args, "-js-crawl")
			}
			output, execErr := exec.Command("katana", args...).CombinedOutput()
			var res any
			_ = json.Unmarshal(output, &res)
			return map[string]any{"status": "success", "data": res, "raw": string(output), "error": fmt.Sprintf("%v", execErr)}
		},
	})

	// JS Analyzer Tool (Pure Go - no external dependency)
	server.Register(sdk.Tool{
		Name:           "js_analyze",
		Description:    "Extract API routes, secrets, and variables from JS files.",
		TimeoutSeconds: 300,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "js_url", "type": "string", "description": "URL of the JS file to analyze", "required": true},
		},
		Returns: map[string]any{"status": "string", "routes": "array", "secrets": "array", "metadata": "object"},
		Handler: func(params map[string]any) any {
			jsURL, _ := params["js_url"].(string)
			if jsURL == "" {
				return map[string]any{"status": "error", "error": "js_url is required"}
			}
			resp, err := http.Get(jsURL)
			if err != nil {
				return map[string]any{"status": "error", "error": fmt.Sprintf("failed to fetch JS: %v", err)}
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return map[string]any{"status": "error", "error": fmt.Sprintf("HTTP %d", resp.StatusCode)}
			}
			var body []byte
			buf := make([]byte, 1024*1024)
			n, _ := resp.Body.Read(buf)
			body = buf[:n]
			jsContent := string(body)

			routeRe := regexp.MustCompile(`[\x27\x22](/api/[a-zA-Z0-9_\\-\\/]+)[\x27\x22]`)
			routes := routeRe.FindAllStringSubmatch(jsContent, -1)
			var routeList []string
			for _, match := range routes {
				if len(match) > 1 {
					routeList = append(routeList, match[1])
				}
			}

			apiKeyRe := regexp.MustCompile(`(?i)(api[_-]?key|apikey)[\\s]*[:=][\\s]*[\x27\x22]([a-zA-Z0-9_-]{16,})[\x27\x22]`)
			bearerRe := regexp.MustCompile(`(?i)(bearer|token)[\\s]*[:=][\\s]*[\x27\x22]([a-zA-Z0-9_.-]{20,})[\x27\x22]`)
			awsRe := regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`)
			jwtRe := regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*`)
			secretPatterns := map[string]*regexp.Regexp{
				"api_key":      apiKeyRe,
				"bearer_token": bearerRe,
				"aws_key":      awsRe,
				"jwt":          jwtRe,
			}
			var secrets []map[string]any
			for spName, spPattern := range secretPatterns {
				matches := spPattern.FindAllStringSubmatch(jsContent, -1)
				for _, match := range matches {
					var val string
					if len(match) > 2 {
						val = match[2]
					} else if len(match) > 1 {
						val = match[1]
					} else {
						val = match[0]
					}
					secrets = append(secrets, map[string]any{
						"type":    spName,
						"value":   val,
						"context": jsURL,
					})
				}
			}
			return map[string]any{
				"status":   "success",
				"routes":   routeList,
				"secrets":  secrets,
				"metadata": map[string]any{"url": jsURL, "size_bytes": len(body)},
			}
		},
	})

	_ = server.Run(":8087")
}

// clampInt bounds v to the inclusive range [lo, hi].
func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

var (
	// sqlmap prints one "Parameter:" header per injectable parameter, then one or
	// more "Type:/Title:/Payload:" blocks beneath it.
	reSqlmapParam   = regexp.MustCompile(`(?m)^\s*Parameter:\s*(.+?)\s*$`)
	reSqlmapType    = regexp.MustCompile(`(?m)^\s*Type:\s*(.+?)\s*$`)
	reSqlmapPayload = regexp.MustCompile(`(?m)^\s*Payload:\s*(.+?)\s*$`)
	reSqlmapDBMS    = regexp.MustCompile(`(?i)back-end DBMS:\s*(.+)`)
)

// parseSqlmapOutput turns sqlmap's human-readable stdout into a structured verdict.
// The decisive signal is the "sqlmap identified the following injection point(s)"
// banner (and/or the per-parameter "Parameter:/Type:/Payload:" block) — a 500 or a
// reflected error string is NOT proof of injection, so we never infer injectable
// from HTTP status alone.
func parseSqlmapOutput(raw string) map[string]any {
	lower := strings.ToLower(raw)
	injectable := strings.Contains(lower, "sqlmap identified the following injection point") ||
		strings.Contains(lower, "is vulnerable") ||
		(reSqlmapParam.MatchString(raw) && reSqlmapPayload.MatchString(raw))

	params := firstGroups(reSqlmapParam.FindAllStringSubmatch(raw, -1))
	techniques := firstGroups(reSqlmapType.FindAllStringSubmatch(raw, -1))
	payloads := firstGroups(reSqlmapPayload.FindAllStringSubmatch(raw, -1))

	dbms := ""
	if m := reSqlmapDBMS.FindStringSubmatch(raw); len(m) > 1 {
		dbms = strings.TrimSpace(m[1])
	}

	parameter := ""
	if len(params) > 0 {
		parameter = params[0]
	}

	return map[string]any{
		"injectable": injectable,
		"parameter":  parameter,
		"parameters": params,
		"dbms":       dbms,
		"techniques": techniques,
		"payloads":   payloads,
	}
}

// firstGroups collects capture-group 1 from each regex match, skipping empties.
func firstGroups(matches [][]string) []string {
	out := []string{}
	for _, m := range matches {
		if len(m) > 1 && strings.TrimSpace(m[1]) != "" {
			out = append(out, strings.TrimSpace(m[1]))
		}
	}
	return out
}
