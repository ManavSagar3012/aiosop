package main

import (
	"github.com/ai-osop/mcp-servers/sdk"
)

func main() {
	server := sdk.NewServer("payload-mcp")

	// Generate Payload Tool
	server.Register(sdk.Tool{
		Name:           "generate_payload",
		Description:    "Mock payload generation tool.",
		TimeoutSeconds: 30,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "vuln_type", "type": "string", "description": "Type of vulnerability", "required": true},
			{"name": "context", "type": "object", "description": "Injection context", "required": true},
		},
		Returns: map[string]any{"payload": "string", "encoding": "array"},
		Handler: func(params map[string]any) any {
			return map[string]any{
				"payload":  "<script>alert('mock-xss')</script>",
				"encoding": []string{"none"},
			}
		},
	})

	// Mutate Payload Tool
	server.Register(sdk.Tool{
		Name:           "mutate_payload",
		Description:    "Mutate a payload for bypass.",
		TimeoutSeconds: 30,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "payload", "type": "object", "description": "Payload object", "required": true},
            {"name": "strategy", "type": "string", "description": "Mutation strategy", "required": true},
		},
		Returns: map[string]any{"payload": "object"},
		Handler: func(params map[string]any) any {
            p, _ := params["payload"].(map[string]any)
			return map[string]any{
				"payload":  p,
			}
		},
	})

    // Evaluate Fitness Tool
	server.Register(sdk.Tool{
		Name:           "evaluate_fitness",
		Description:    "Evaluate payload fitness.",
		TimeoutSeconds: 30,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "payload", "type": "object", "description": "Payload object", "required": true},
            {"name": "result", "type": "object", "description": "Exploit result", "required": true},
		},
		Returns: map[string]any{"fitness_score": "number"},
		Handler: func(params map[string]any) any {
			return map[string]any{
				"fitness_score": 0.8,
			}
		},
	})

	_ = server.Run(":8083")
}
