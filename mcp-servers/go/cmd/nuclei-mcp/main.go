package main

import (
	"os/exec"
	"strings"

	"github.com/ai-osop/mcp-servers/sdk"
)

func main() {
	server := sdk.NewServer("nuclei-mcp")
	server.Register(sdk.Tool{
		Name:           "scan",
		Description:    "Run nuclei against scoped targets.",
		TimeoutSeconds: 900,
		ScopeCheck:      true,
		Parameters: []map[string]any{
			{"name": "targets", "type": "array", "description": "Target URLs or hosts", "required": true},
			{"name": "templates", "type": "array", "description": "Optional template IDs or paths", "required": false},
		},
		Returns: map[string]any{"findings": "array"},
		Handler: func(params map[string]any) any {
			targets := stringSlice(params["targets"])
			if len(targets) == 0 {
				return map[string]any{"findings": []any{}, "error": "target parameter is required and cannot be empty"}
			}
			args := []string{"-jsonl", "-silent"}
			for _, target := range targets {
				args = append(args, "-target", target)
			}
			output, err := exec.Command("nuclei", args...).CombinedOutput()
			if err != nil {
				return map[string]any{"findings": []any{}, "error": err.Error(), "raw": string(output)}
			}
			return map[string]any{"findings": strings.Split(strings.TrimSpace(string(output)), "\n")}
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
