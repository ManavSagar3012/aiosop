package main

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/ai-osop/mcp-servers/sdk"
)

type searchTransport func(*http.Request) (*http.Response, error)

func (f searchTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fakeSearchClient(body string, status int) *http.Client {
	return &http.Client{Transport: searchTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Hostname() != "search.example.com" || r.URL.Path != "/search" {
			panic("unexpected search endpoint")
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, ContentLength: int64(len(body))}, nil
	})}
}

func params() map[string]any {
	return map[string]any{"domain": "example.org", "query": "site:example.org admin", "mode": "links", "max_results": float64(3)}
}

func status(value map[string]any) string { return value["status"].(string) }

func TestRealToolRegistrationIsScopedOptionalAndUnverified(t *testing.T) {
	t.Setenv("OSOP_RECON_SEARXNG_URL", "")
	server := sdk.NewServer("recon-mcp")
	registerWebSearch(server)
	tool, present := server.Tools["web_search"]
	if !present || !tool.ScopeCheck || tool.RequiresApproval || tool.Handler == nil {
		t.Fatal("passive scoped optional web search was not registered")
	}
	if len(tool.Parameters) != 4 || len(tool.Returns) == 0 {
		t.Fatal("required search schema was not advertised")
	}
	outcome := tool.Handler(params()).(map[string]any)
	if status(outcome) != "unknown" || len(outcome["results"].([]map[string]any)) != 0 {
		t.Fatal("unconfigured search engine claimed successful discovery")
	}
}

func TestUnauthenticatedReconSDKCannotBindNonLocalInterfaces(t *testing.T) {
	t.Setenv("OSOP_RECON_MCP_BIND", "0.0.0.0:8082")
	t.Setenv("OSOP_RECON_MCP_ALLOW_REMOTE_BIND", "true")
	if got := reconListenAddress(); got != "127.0.0.1:8082" {
		t.Fatalf("unsigned recon transport exposed beyond loopback: %s", got)
	}
}

func TestNotConfiguredOrMalformedSearxURLNeverCallsProvider(t *testing.T) {
	client := &http.Client{Transport: searchTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("HTTP called without valid search deployment")
		return nil, nil
	})}
	for _, raw := range []string{"", "http://search.example.com", "https://localhost/search", "https://127.0.0.1/search", "https://search.example.com:1234/search", "https://user:pw@search.example.com/search", "https://search.example.com/redirect", "https://search.example.com/?q=secret"} {
		if value := searchSearxNG(params(), raw, client); status(value) != "unknown" {
			t.Fatalf("unsafe endpoint %q accepted", raw)
		}
	}
}

func TestOperatorExplicitLoopbackSearxOptInIsFixedAddressOnly(t *testing.T) {
	t.Setenv("OSOP_RECON_SEARXNG_ALLOW_LOCAL_HTTP", "")
	client := &http.Client{Transport: searchTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("disabled local search made an HTTP request")
		return nil, nil
	})}
	if status(searchSearxNG(params(), "http://127.0.0.1:8080/search", client)) != "unknown" {
		t.Fatal("unsafe implicit local HTTP backend allowed")
	}
	t.Setenv("OSOP_RECON_SEARXNG_ALLOW_LOCAL_HTTP", "true")
	for _, raw := range []string{"http://localhost:8080/search", "http://127.0.0.1:80/search", "http://127.0.0.2:8080/search", "http://169.254.169.254:8080/search", "http://127.0.0.1:8080/admin", "http://127.0.0.1:8080/search?secret=x"} {
		if _, accepted := searchEndpoint(raw); accepted {
			t.Fatalf("alternate local search destination accepted: %s", raw)
		}
	}
	if _, accepted := searchEndpoint("http://127.0.0.1:8080/search"); !accepted {
		t.Fatal("opted-in fixed local SearXNG unavailable")
	}
	response := &http.Client{Transport: searchTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "127.0.0.1:8080" || r.URL.Path != "/search" {
			t.Fatal("unexpected local endpoint")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"results":[{"title":"example","url":"https://example.org/"}]}`)), Header: http.Header{}}, nil
	})}
	if status(searchSearxNG(params(), "http://127.0.0.1:8080/search", response)) != "success" {
		t.Fatal("explicit local backend did not parse public source links")
	}
}

func TestSearxStrictScopeSanitizationAndStableProvenance(t *testing.T) {
	client := fakeSearchClient(`{"results":[{"title":"A","url":"https://example.org/one?access_token=secret#fragment"},{"title":"Off scope","url":"https://evil.org/"},{"title":"Subdomain","url":"https://app.example.org/two"},{"title":"Duplicate","url":"https://example.org/one"},{"title":"Spoof","url":"https://example.org.evil.org/"}]}`, 200)
	result := searchSearxNG(params(), "https://search.example.com/search", client)
	if status(result) != "success" {
		t.Fatal(result)
	}
	list := result["results"].([]map[string]any)
	if len(list) != 2 || list[0]["url"] != "https://example.org/one" || list[1]["url"] != "https://app.example.org/two" {
		t.Fatal(list)
	}
	if result["provenance"].(map[string]any)["target_side_evidence_verified"] != false {
		t.Fatal("listing marked as target proof")
	}
	if result["provenance"].(map[string]any)["query_sha256"] == "" {
		t.Fatal("query digest absent")
	}
}

func TestInputRejectionBeforeSearchDispatch(t *testing.T) {
	client := &http.Client{Transport: searchTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("HTTP called for unsafe input")
		return nil, nil
	})}
	for _, bad := range []map[string]any{
		{"domain": "outside.example.com", "query": "site:evil.org", "mode": "links", "max_results": 1},
		{"domain": "127.0.0.1", "query": "test", "mode": "links", "max_results": 1},
		{"domain": "example.org", "query": "hello\nworld", "mode": "links", "max_results": 1},
		{"domain": "example.org", "query": "site:evil.org", "mode": "links", "max_results": 1},
		{"domain": "example.org", "query": "test", "mode": "exploit", "max_results": 1},
		{"domain": "example.org", "query": "test", "mode": "links", "max_results": 11},
		{"domain": "example.org", "query": "test", "mode": "links", "max_results": 0.5},
	} {
		if value := searchSearxNG(bad, "https://search.example.com/search", client); status(value) != "unknown" {
			t.Fatalf("unsafe search input admitted: %#v", bad)
		}
	}
}

func TestProviderFailuresRemainUnknownNotZeroFindings(t *testing.T) {
	for _, tt := range []struct {
		body string
		code int
	}{
		{`{"results":[]}`, 503},
		{`not json`, 200},
		{`{"error":"upstream unavailable"}`, 200},
		{`{"results":null}`, 200},
		{strings.Repeat("x", maxSearchResponseBytes+1), 200},
		{`{"results":[]}`, 302},
	} {
		value := searchSearxNG(params(), "https://search.example.com/search", fakeSearchClient(tt.body, tt.code))
		if status(value) != "unknown" || len(value["results"].([]map[string]any)) != 0 {
			t.Fatal(value)
		}
	}
}

func TestPublicDialPolicyDeniesPrivateAndReservedIPv4IPv6(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.4", "100.64.0.8", "169.254.169.254", "192.0.2.1", "203.0.113.4", "198.18.0.1", "::1", "fc00::1", "fe80::1", "2001:db8::1"} {
		if allowedPublicIP(net.ParseIP(address)) {
			t.Fatalf("reserved destination allowed: %s", address)
		}
	}
	for _, address := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !allowedPublicIP(net.ParseIP(address)) {
			t.Fatalf("public DNS destination rejected: %s", address)
		}
	}
}
