package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/ai-osop/mcp-servers/sdk"
)

func main() {
	server := sdk.NewServer("shodan-mcp")
	server.Register(sdk.Tool{
		Name:           "shodan_lookup",
		Description:    "Query Shodan host search for a scoped domain.",
		TimeoutSeconds: 120,
		ScopeCheck:      true,
		Parameters: []map[string]any{
			{"name": "domain", "type": "string", "description": "Domain to search", "required": true},
		},
		Returns: map[string]any{"matches": "array"},
		Handler: func(params map[string]any) any {
			key := os.Getenv("OSOP_SHODAN_API_KEY")
			domain, _ := params["domain"].(string)
			if key == "" || domain == "" {
				return map[string]any{"matches": []any{}, "error": "missing OSOP_SHODAN_API_KEY or domain"}
			}
			url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=hostname:%s", key, domain)
			resp, err := http.Get(url)
			if err != nil {
				return map[string]any{"matches": []any{}, "error": err.Error()}
			}
			defer resp.Body.Close()
			var body map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&body)
			return body
		},
	})
	_ = server.Run(":8085")
}
