package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ai-osop/mcp-servers/sdk"
)

func main() {
	server := sdk.NewServer("threat-intel-mcp")

	// CVE Lookup Tool
	server.Register(sdk.Tool{
		Name:           "cve_lookup",
		Description:    "Query NVD API for CVE details.",
		TimeoutSeconds: 120,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "cve_id", "type": "string", "description": "CVE ID (e.g., CVE-2023-1234)", "required": true},
		},
		Returns: map[string]any{"data": "object"},
		Handler: func(params map[string]any) any {
			cveID, _ := params["cve_id"].(string)
			if cveID == "" {
				return map[string]any{"error": "missing cve_id"}
			}
			url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)
			resp, err := http.Get(url)
			if err != nil {
				return map[string]any{"error": err.Error()}
			}
			defer resp.Body.Close()
			var body map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&body)
			return body
		},
	})

	// KEV Check Tool
	server.Register(sdk.Tool{
		Name:           "kev_check",
		Description:    "Check if a CVE is in CISA KEV catalog.",
		TimeoutSeconds: 120,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "cve_id", "type": "string", "description": "CVE ID", "required": true},
		},
		Returns: map[string]any{"in_kev": "boolean"},
		Handler: func(params map[string]any) any {
			cveID, _ := params["cve_id"].(string)
			if cveID == "" {
				return map[string]any{"error": "missing cve_id"}
			}
			resp, err := http.Get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
			if err != nil {
				return map[string]any{"error": err.Error()}
			}
			defer resp.Body.Close()
			var body map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&body)

			vulnerabilities, ok := body["vulnerabilities"].([]any)
			if !ok {
				return map[string]any{"in_kev": false}
			}

			for _, v := range vulnerabilities {
				vuln, ok := v.(map[string]any)
				if ok && vuln["cveID"] == cveID {
					return map[string]any{"in_kev": true}
				}
			}
			return map[string]any{"in_kev": false}
		},
	})

	_ = server.Run(":8086")
}
