package sdk

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestSanitizeParamsBlocksArgInjection(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
		bad    string // expected offending key, "" if should pass
	}{
		{"flag-injection", map[string]any{"target": "--script=evil"}, "target"},
		{"leading-dash-url", map[string]any{"url": "-oN/tmp/x"}, "url"},
		{"whitespace-split", map[string]any{"host": "a.com b.com"}, "host"},
		{"newline-inject", map[string]any{"url": "a.com\n--dump"}, "url"},
		{"legit-url", map[string]any{"url": "https://my-site.com/a?b=1&c=2"}, ""},
		{"legit-target", map[string]any{"target": "scanme.nmap.org", "fast": true}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, _ := sanitizeParams(c.params)
			if k != c.bad {
				t.Fatalf("sanitizeParams(%v) offending key = %q, want %q", c.params, k, c.bad)
			}
		})
	}
}

func TestScopeValidation(t *testing.T) {
	s := NewServer("test-scope")
	s.HasScope = true
	s.Scope = ScopeDefinition{
		EngagementID: "test-eng-1",
		Domains:      []string{"example.com", "target.local"},
		IPs:          []string{"192.168.1.1", "10.0.0.0/24"},
		Exclusions:   []string{"evil.example.com", "192.168.1.50"},
	}

	cases := []struct {
		target string
		want   bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"target.local", true},
		{"evil.example.com", false},
		{"out.com", false},
		{"192.168.1.1", true},
		{"192.168.1.50", false},
		{"10.0.0.5", true},
		{"10.0.1.5", false},
		{"http://sub.example.com/index.html", true},
		{"http://evil.example.com:8080/index.html", false},
	}

	for _, c := range cases {
		got := s.isTargetInScope(c.target)
		if got != c.want {
			t.Errorf("isTargetInScope(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}

func TestAuthMiddleware(t *testing.T) {
	tokenKey := "OSOP_API_TOKEN"
	origToken := os.Getenv(tokenKey)
	defer os.Setenv(tokenKey, origToken)

	os.Setenv(tokenKey, "my-super-secret-mcp-token")
	expected := loadEnvToken()
	if expected != "my-super-secret-mcp-token" {
		t.Fatalf("loadEnvToken() = %q, want %q", expected, "my-super-secret-mcp-token")
	}

	// Test authorized request
	req, _ := http.NewRequest("GET", "/health", nil)
	req.Header.Set("Authorization", "Bearer my-super-secret-mcp-token")
	rr := httptest.NewRecorder()
	if !checkAuth(rr, req, expected) {
		t.Errorf("checkAuth failed for valid token")
	}

	// Test unauthorized request
	req, _ = http.NewRequest("GET", "/health", nil)
	rr = httptest.NewRecorder()
	if checkAuth(rr, req, expected) {
		t.Errorf("checkAuth succeeded for missing token")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("checkAuth response status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}
