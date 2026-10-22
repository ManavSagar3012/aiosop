package sdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func securedServer(counter *atomic.Int64) *Server {
	s := NewServer("nuclei-mcp")
	s.Register(Tool{
		Name: "scan", Description: "An untrusted native network scanner",
		Parameters: []map[string]any{
			{"name": "targets", "type": "array", "required": true},
		},
		Returns:    map[string]any{"findings": "array"},
		ScopeCheck: true,
		// Legacy SDK declares no SideEffectClass; under NO circumstances may
		// the Python parser silently promote this native tool to READ_ONLY.
		Handler: func(params map[string]any) any {
			counter.Add(1)
			panic("MUST NEVER CALL NATIVE TOOL")
		},
	})
	return s
}

func request(handler http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, req)
	return result
}

func decoded(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if w.Header().Get("Cache-Control") != "no-store" ||
		w.Header().Get("X-Content-Type-Options") != "nosniff" ||
		w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("unsafe response headers: %#v", w.Header())
	}
	return value
}

func TestMissingBearerForgedSignedActionAndStaticTokenNeverReachHandler(t *testing.T) {
	calls := new(atomic.Int64)
	handler := securedServer(calls).Handler()
	variants := []struct {
		name   string
		body   string
		header map[string]string
	}{
		{"empty request", "", nil},
		{"simple registered tool", `{"tool_name":"scan","parameters":{"targets":["example.test"]},"request_id":"req-01"}`, nil},
		{"static bearer cannot provide per-call ROE", `{"tool_name":"scan","parameters":{"targets":["example.test"]}}`,
			map[string]string{"Authorization": "Bearer shared-static-secret"}},
		{"bad header", `{"tool_name":"scan"}`, map[string]string{"Authorization": "Basic abc"}},
		{"forged current owner role", `{"tool_name":"scan","engagement_id":"eng-a","flow_id":"flow-a","task_id":"task-a","action_id":"action-a","approved":true,"scope":{"domains":["example.test"]},"parameters":{"targets":["example.test"]}}`, nil},
		{"forged bound source authority", `{"tool_name":"scan","execution_binding":{"tenant":"eng-x","flow_id":"flow-x","signed_roe":true,"signature":"fake","action_id":"action-x","nonce":"fresh"},"parameters":{"targets":["example.test"]}}`, nil},
		{"expired authority", `{"tool_name":"scan","expires_at":1,"nonce":"replay","approved":true}`, nil},
		{"future timestamp fake signature", `{"tool_name":"scan","expires_at":9999999999,"nonce":"valid","signature":"attacker"}`, nil},
		{"mismatched identities", `{"tool_name":"scan","engagement_id":"eng-a","task_id":"task-b","flow_id":"flow-a","action_id":"action-b","roe_sha256":"xyz"}`, nil},
		{"malformed JSON", `{"tool_name":"scan","parameters":{"targets":[`, nil},
		{"unknown tool", `{"tool_name":"not-registered","parameters":{}}`, nil},
		{"unbounded body ignored", strings.Repeat("secret", 50000), nil},
	}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			res := request(handler, http.MethodPost, "/mcp/execute", variant.body, variant.header)
			if res.Code != http.StatusServiceUnavailable {
				t.Fatalf("expected fail-closed 503, got %d", res.Code)
			}
			got := decoded(t, res)
			if got["error"] != "native_execution_not_authorized" ||
				got["status"] != "error" || got["execution_enabled"] != false {
				t.Fatalf("dispatch denial not explicit: %#v", got)
			}
			for _, secret := range []string{"shared-static-secret", "example.test", "attacker", "eng-x", "task-b", "password", "secretsecret"} {
				if strings.Contains(res.Body.String(), secret) {
					t.Fatalf("untrusted request content echoed: %q", secret)
				}
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("tool handler ran %d times in spite of missing trust", calls.Load())
	}
}

func TestReadOnlyClaimDoesNotGrantExecution(t *testing.T) {
	calls := new(atomic.Int64)
	s := NewServer("passive-mcp")
	s.Register(Tool{
		Name:            "read_local",
		SideEffectClass: SideEffectReadOnly,
		ScopeCheck:      true,
		Handler:         func(map[string]any) any { calls.Add(1); return map[string]any{"ok": true} },
	})
	body := `{"tool_name":"read_local","parameters":{},"signed":true}`
	res := request(s.Handler(), http.MethodPost, "/mcp/execute", body, nil)
	if res.Code != 503 || calls.Load() != 0 {
		t.Fatalf("unsafe READ_ONLY call: %d %d", res.Code, calls.Load())
	}
}

func TestHighEffectNativeToolsNeverExecuteInParallelIncludingDuplicateNonce(t *testing.T) {
	calls := new(atomic.Int64)
	handler := securedServer(calls).Handler()
	const parallel = 128
	var wg sync.WaitGroup
	failures := make(chan string, parallel)
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(
				`{"tool_name":"scan","request_id":"req-%d","nonce":"repeated","scope":{"approved":true},"parameters":{"targets":["example.test"]}}`,
				i,
			)
			response := request(handler, http.MethodPost, "/mcp/execute", body,
				map[string]string{"Authorization": "Bearer not-an-action-signature"})
			if response.Code != http.StatusServiceUnavailable ||
				!strings.Contains(response.Body.String(), "native_execution_not_authorized") {
				failures <- response.Body.String()
			}
		}(i)
	}
	wg.Wait()
	close(failures)
	for failure := range failures {
		t.Fatalf("unsafe parallel response: %s", failure)
	}
	if calls.Load() != 0 {
		t.Fatalf("parallel requests reached native handler %d times", calls.Load())
	}
}

func TestHealthNeverClaimsOperationalReadiness(t *testing.T) {
	calls := new(atomic.Int64)
	s := securedServer(calls)
	response := request(s.Handler(), http.MethodGet, "/health", "", nil)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("health advertised a usable native provider: %d", response.Code)
	}
	got := decoded(t, response)
	if got["server_id"] != "nuclei-mcp" || got["status"] != "unavailable" ||
		got["execution_enabled"] != false || got["authority_verified"] != false {
		t.Fatalf("fake native readiness: %#v", got)
	}
	wrong := request(s.Handler(), http.MethodPost, "/health", "", nil)
	if wrong.Code != http.StatusMethodNotAllowed {
		t.Fatalf("health accepted wrong method: %d", wrong.Code)
	}
	if calls.Load() != 0 {
		t.Fatal("health touched native handler")
	}
}

func TestInitializeRetainsCanonicalSchemaButRefusesToAuthorizeAndClassifiesLegacyTools(t *testing.T) {
	calls := new(atomic.Int64)
	s := securedServer(calls)
	init := `{"scope":{"domains":["example.test"]},"auth_credentials":{"api_key":"sensitive-example"},"session_id":"api-bootstrap","metadata":{"foo":"bar"}}`
	response := request(s.Handler(), http.MethodPost, "/mcp/initialize", init,
		map[string]string{"Content-Type": "application/json", "Authorization": "Bearer even-if-static"})
	if response.Code != http.StatusOK {
		t.Fatalf("canonical nonexecuting initialize failed: %d", response.Code)
	}
	got := decoded(t, response)
	if got["server_id"] != "nuclei-mcp" || got["version"] != "0.1.0" ||
		got["status"] != "unavailable" || got["execution_enabled"] != false ||
		got["authority_verified"] != false {
		t.Fatalf("missing inert initialization state: %#v", got)
	}
	caps, ok := got["capabilities"].([]any)
	if !ok || len(caps) != 0 {
		t.Fatalf("unsafe capabilities advertised: %#v", got["capabilities"])
	}
	tools, ok := got["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("legacy schema not preserved: %#v", got["tools"])
	}
	tool := tools[0].(map[string]any)
	if tool["name"] != "scan" || tool["side_effect_class"] != SideEffectInvasiveExploit ||
		tool["requires_approval"] != true || tool["scope_check"] != true {
		t.Fatalf("dangerous default tools accepted as READ_ONLY: %#v", tool)
	}
	if _, ok := tool["Handler"]; ok {
		t.Fatal("handler exposed in tool manifest")
	}
	if strings.Contains(response.Body.String(), "sensitive-example") ||
		strings.Contains(response.Body.String(), "example.test") ||
		strings.Contains(response.Body.String(), "api-bootstrap") {
		t.Fatal("initialize echoed untrusted credentials or scope")
	}
	if calls.Load() != 0 {
		t.Fatal("initialize executed native handler")
	}
}

func TestUntrustedSideEffectDeclarationsCannotBePromotedToReadOnly(t *testing.T) {
	for _, value := range []string{"", "read_only", "UNKNOWN", "WRONG", "nil", "RECON_ACTIVE", "READ_ONLY", "INVASIVE_EXPLOIT"} {
		got := safeSideEffect(value)
		if value == "READ_ONLY" || value == "RECON_ACTIVE" || value == "INVASIVE_EXPLOIT" {
			if got != value {
				t.Fatalf("valid enum corrupted: %s -> %s", value, got)
			}
		} else if got != SideEffectInvasiveExploit {
			t.Fatalf("unknown side effect promoted to: %q", got)
		}
	}
}

func TestInitializeMalformedOversizedAndBadMethodAreSafe(t *testing.T) {
	s := NewServer("go-mcp")
	for _, tc := range []struct {
		body     string
		expected int
	}{
		{"", http.StatusBadRequest},
		{"null", http.StatusBadRequest},
		{"[]", http.StatusBadRequest},
		{"{}", http.StatusBadRequest},
		{`{"auth_credentials":"sensitive-UNTRUSTED" `, http.StatusBadRequest},
		{strings.Repeat("X", maxInitBodyBytes+1), http.StatusBadRequest},
	} {
		res := request(s.Handler(), http.MethodPost, "/mcp/initialize", tc.body, nil)
		if res.Code != tc.expected {
			t.Fatalf("body len %d: code %d", len(tc.body), res.Code)
		}
		_ = decoded(t, res)
		if strings.Contains(res.Body.String(), "sensitive-UNTRUSTED") {
			t.Fatal("secret echoed in parse error")
		}
	}
	for _, path := range []string{"/mcp/initialize", "/mcp/execute"} {
		res := request(s.Handler(), http.MethodGet, path, "", nil)
		if res.Code != http.StatusMethodNotAllowed || res.Header().Get("Allow") != "POST" {
			t.Fatalf("unexpected method accepted: %s %d", path, res.Code)
		}
	}
}

type brokenBody struct{}

func (brokenBody) Read(p []byte) (int, error) {
	return 0, errors.New("private-secret-buffer-read-failed")
}
func (brokenBody) Close() error { return nil }

func TestBrokenBodyDoesNotLeakParsingErrorOrTriggerHandlers(t *testing.T) {
	calls := new(atomic.Int64)
	s := securedServer(calls)
	req := httptest.NewRequest(http.MethodPost, "/mcp/initialize", nil)
	req.Body = brokenBody{}
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, req)
	if response.Code != 400 {
		t.Fatalf("broken init body: %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "private-secret") {
		t.Fatal("I/O error leaked secret")
	}
	if calls.Load() != 0 {
		t.Fatal("native handler ran after broken body")
	}
}

func TestWildcardBindingsAreCoercedToLoopbackOnlyAndRemoteDenied(t *testing.T) {
	cases := map[string]string{
		":8084":          "127.0.0.1:8084",
		"0.0.0.0:8087":   "127.0.0.1:8087",
		"[::]:8083":      "127.0.0.1:8083",
		"localhost:8086": "127.0.0.1:8086",
		"127.0.0.1:8085": "127.0.0.1:8085",
		"[::1]:8085":     "[::1]:8085",
	}
	for raw, want := range cases {
		actual, err := localAddress(raw)
		if err != nil || actual != want {
			t.Fatalf("loopback %q: %q %v", raw, actual, err)
		}
	}
	for _, raw := range []string{
		"192.0.2.1:8085", "example.org:8084", "[2001:db8::1]:8083",
		":0", ":65536", ":-1", "[::1", "127.0.0.1:not-a-port",
	} {
		if got, err := localAddress(raw); err == nil {
			t.Fatalf("unsafe listener %q accepted: %q", raw, got)
		}
	}
}

func TestMultipleServerInstancesUseIndependentMuxes(t *testing.T) {
	a := NewServer("first-mcp")
	b := NewServer("second-mcp")
	for _, tc := range []struct {
		s    *Server
		want string
	}{{a, "first-mcp"}, {b, "second-mcp"}} {
		res := request(tc.s.Handler(), http.MethodGet, "/health", "", nil)
		if decoded(t, res)["server_id"] != tc.want {
			t.Fatal("global ServeMux contamination")
		}
	}
}

func TestResponseDoesNotEchoRawAuthorizationOrRequestMetadata(t *testing.T) {
	count := new(atomic.Int64)
	server := securedServer(count)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(method, "/mcp/execute", bytes.NewReader([]byte(`{"tool_name":"scan","payload":"super-private"}`)))
		req.Header.Set("Authorization", "Bearer hidden-token")
		req.Header.Set("X-ROE-Signature", "misleading-signed-ROE")
		writer := httptest.NewRecorder()
		server.Handler().ServeHTTP(writer, req)
		if strings.Contains(writer.Body.String(), "hidden-token") ||
			strings.Contains(writer.Body.String(), "super-private") ||
			strings.Contains(writer.Body.String(), "misleading-signed-ROE") {
			t.Fatal("raw sensitive action metadata escaped rejection")
		}
	}
	if count.Load() != 0 {
		t.Fatal("handler executed without independent grants")
	}
}

// Verify that even an io.Reader streaming untrusted bytes cannot be promoted
// to an invocation; the denied execute handler never parses native arguments.
func TestExecuteDeniedWithoutConsumingUntrustedStream(t *testing.T) {
	calls := new(atomic.Int64)
	s := securedServer(calls)
	poisoned := io.NopCloser(strings.NewReader(`{"tool_name":"scan","parameters":{"targets":["example.test"]}}`))
	req := httptest.NewRequest(http.MethodPost, "/mcp/execute", nil)
	req.Body = poisoned
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, req)
	if response.Code != 503 || calls.Load() != 0 {
		t.Fatalf("native execution unexpectedly admitted: %d", response.Code)
	}
}
