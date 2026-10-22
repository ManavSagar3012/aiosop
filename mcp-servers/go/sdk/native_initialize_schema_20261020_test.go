package sdk

import (
	"net/http"
	"strings"
	"testing"
)

func TestAllNativeGoInitializeRequiresCanonicalTypedSchema(t *testing.T) {
	f := newGrantFixture(t)
	valid := []string{
		`{"scope":{},"auth_credentials":{},"session_id":"api-bootstrap","metadata":{}}`,
		`{"scope":{},"credentials":{},"session_id":"legacy-qualified"}`,
		`{"scope":{"domains":["controlled.example"]},"session_id":"basic-qualified"}`,
	}
	for _, body := range valid {
		response := request(f.server.Handler(), http.MethodPost, "/mcp/initialize", body, map[string]string{"Content-Type": "application/json"})
		if response.Code != http.StatusOK || decoded(t, response)["status"] != "ready" {
			t.Fatalf("typed inert MCP negotiation failed: %d", response.Code)
		}
	}
	for _, body := range []string{
		`{}`,
		`{"scope":{},"session_id":"api-bootstrap","untrusted_execute":true}`,
		`{"scope":{},"session_id":"api-bootstrap","session_id":"other"}`,
		`{"scope":[],"session_id":"api-bootstrap"}`,
		`{"scope":null,"session_id":"api-bootstrap"}`,
		`{"scope":{},"session_id":"api-bootstrap","auth_credentials":"secret"}`,
		`{"scope":{},"session_id":"api-bootstrap","auth_credentials":{},"credentials":{}}`,
		`{"scope":{},"session_id":"api\nbootstrap"}`,
		`{"scope":{},"session_id":"api-bootstrap"}{} `,
		`{"scope":{},"session_id":"` + strings.Repeat("X", 129) + `"}`,
	} {
		response := request(f.server.Handler(), http.MethodPost, "/mcp/initialize", body, map[string]string{"Content-Type": "application/json"})
		if response.Code != http.StatusBadRequest {
			t.Fatalf("untrusted MCP init accepted: %d; %s", response.Code, body)
		}
		if strings.Contains(response.Body.String(), "secret") || strings.Contains(response.Body.String(), "untrusted_execute") {
			t.Fatal("private initialize input disclosed")
		}
	}
	noType := request(f.server.Handler(), http.MethodPost, "/mcp/initialize", valid[0], nil)
	if noType.Code != http.StatusBadRequest {
		t.Fatal("missing JSON content type negotiated ready")
	}
}
