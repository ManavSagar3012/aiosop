package main

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ai-osop/mcp-servers/sdk"
)

func main() {
	server := sdk.NewServer("nuclei-mcp")

	// scan: run nuclei against scoped targets, optionally restricting templates,
	// severity, and tags — all forwarded to the real nuclei engine.
	server.Register(sdk.Tool{
		Name:           "scan",
		Description:    "Run nuclei against scoped targets with optional template/severity/tag filters.",
		TimeoutSeconds: 900,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "targets", "type": "array", "description": "Target URLs or hosts", "required": true},
			{"name": "templates", "type": "array", "description": "Optional template IDs or paths", "required": false},
			{"name": "severity", "type": "string", "description": "Optional severity filter: info,low,medium,high,critical (comma-separated)", "required": false},
			{"name": "tags", "type": "string", "description": "Optional tag filter (comma-separated)", "required": false},
		},
		Returns: map[string]any{"findings": "array"},
		Handler: func(params map[string]any) any {
			targets := stringSlice(params["targets"])
			if len(targets) == 0 {
				return map[string]any{"findings": []any{}, "error": "target parameter is required and cannot be empty"}
			}
			// Concurrency and rate-limit are tunable via params so the orchestrator
			// can scan within its task budget. Previously these were hardcoded at
			// -c 10 / -rate-limit 15, which throttled scans to ~15 req/s — full
			// template runs then overran the agent timeout, got cancelled, and
			// retried, orphaning nuclei subprocesses (the NUCLEI-FANOUT storm).
			// Faster scans complete well within budget, so retries never fire.
			concurrency := intParam(params["concurrency"], 25)
			rateLimit := intParam(params["rate_limit"], 150)
			args := []string{
				"-jsonl", "-silent",
				"-c", strconv.Itoa(concurrency),
				"-rate-limit", strconv.Itoa(rateLimit),
				"-no-mhe",
			}
			for _, target := range targets {
				args = append(args, "-target", target)
			}
			// Honor the optional `templates` parameter. Previously it was declared
			// but never forwarded to nuclei, so every MCP scan silently ran the full
			// template set (~13k templates) — turning targeted capability tests into
			// multi-minute full scans. Pass each requested template via -t.
			for _, tmpl := range stringSlice(params["templates"]) {
				args = append(args, "-t", tmpl)
			}
			// Severity filter (-severity) and tag filter (-tags) forwarded to nuclei.
			if sev, ok := params["severity"].(string); ok && strings.TrimSpace(sev) != "" {
				args = append(args, "-severity", strings.TrimSpace(sev))
			}
			if tags, ok := params["tags"].(string); ok && strings.TrimSpace(tags) != "" {
				args = append(args, "-tags", strings.TrimSpace(tags))
			}
			// Hard ceiling: kill nuclei if it overruns the scan budget so a slow
			// scan can never become an orphaned subprocess after the client
			// disconnects. Mirrors the tool's declared 900s TimeoutSeconds.
			ctx, cancel := context.WithTimeout(context.Background(), 900*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, "nuclei", args...).CombinedOutput()
			if ctx.Err() == context.DeadlineExceeded {
				return map[string]any{"findings": []any{}, "error": "nuclei scan exceeded 900s budget and was terminated", "raw": string(output)}
			}
			if err != nil {
				return map[string]any{"findings": []any{}, "error": err.Error(), "raw": string(output)}
			}
			lines := []string{}
			for _, l := range strings.Split(strings.TrimSpace(string(output)), "\n") {
				if strings.TrimSpace(l) != "" {
					lines = append(lines, l)
				}
			}
			return map[string]any{"findings": lines, "count": len(lines)}
		},
	})

	// list_templates: enumerate available templates (optionally filtered), via the
	// real nuclei template store (-tl). Proves template-list capability through MCP.
	server.Register(sdk.Tool{
		Name:           "list_templates",
		Description:    "List available nuclei templates, optionally filtered by tags or severity.",
		TimeoutSeconds: 120,
		ScopeCheck:     false,
		Parameters: []map[string]any{
			{"name": "tags", "type": "string", "description": "Optional tag filter (comma-separated)", "required": false},
			{"name": "severity", "type": "string", "description": "Optional severity filter", "required": false},
			{"name": "limit", "type": "integer", "description": "Optional max templates to return (default 100)", "required": false},
		},
		Returns: map[string]any{"templates": "array", "total": "integer"},
		Handler: func(params map[string]any) any {
			args := []string{"-tl", "-silent"}
			if tags, ok := params["tags"].(string); ok && strings.TrimSpace(tags) != "" {
				args = append(args, "-tags", strings.TrimSpace(tags))
			}
			if sev, ok := params["severity"].(string); ok && strings.TrimSpace(sev) != "" {
				args = append(args, "-severity", strings.TrimSpace(sev))
			}
			output, err := exec.Command("nuclei", args...).CombinedOutput()
			if err != nil {
				return map[string]any{"templates": []any{}, "error": err.Error(), "raw": string(output)[:min(len(string(output)), 300)]}
			}
			all := []string{}
			for _, l := range strings.Split(strings.TrimSpace(string(output)), "\n") {
				if strings.TrimSpace(l) != "" {
					all = append(all, strings.TrimSpace(l))
				}
			}
			limit := 100
			if lf, ok := params["limit"].(float64); ok && int(lf) > 0 {
				limit = int(lf)
			}
			shown := all
			if len(shown) > limit {
				shown = shown[:limit]
			}
			return map[string]any{"templates": shown, "total": len(all), "returned": len(shown)}
		},
	})

	_ = server.Run(":8084")
}

func stringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// intParam coerces a JSON-decoded parameter (float64, int, or numeric string)
// into an int, falling back to def when absent or unparseable.
func intParam(value any, def int) int {
	switch v := value.(type) {
	case float64:
		if v > 0 {
			return int(v)
		}
	case int:
		if v > 0 {
			return v
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}
	return def
}
