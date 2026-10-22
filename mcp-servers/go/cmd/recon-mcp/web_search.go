package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/ai-osop/mcp-servers/sdk"
)

const maxSearchResponseBytes = 131072

func reconListenAddress() string {
	// Fail closed: a raw unauthenticated MCP SDK must not accept untrusted
	// network-origin execution even when a deployment sets broad bind hints.
	// A separately operator-selected local port permits isolated QA instances
	// to coexist with the default native service without binding to a LAN.
	// Never accept a host, wildcard, zero or privileged port from this hint.
	if raw := os.Getenv("OSOP_RECON_MCP_LOCAL_PORT"); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1024 || port > 65535 || strconv.Itoa(port) != raw {
			return "127.0.0.1:0" // SDK Run refuses invalid port; never fall back.
		}
		return "127.0.0.1:" + raw
	}
	return "127.0.0.1:8082"
}

var searchDomainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var searchTerms = regexp.MustCompile(`^[a-zA-Z0-9 _.-]{0,180}$`)

// Only candidate links are returned. The gateway must apply signed scope,
// TaskORM and human approval checks before dispatch. Neither this searcher nor
// a search engine has trusted target-side authority or validation privileges.
func registerWebSearch(server *sdk.Server) {
	server.Register(sdk.Tool{
		Name:             "web_search",
		Description:      "Optional passive SearXNG links for an approved domain; unverified public search listings, never vulnerability evidence.",
		TimeoutSeconds:   8,
		ScopeCheck:       true,
		RequiresApproval: false,
		Parameters: []map[string]any{
			{"name": "domain", "type": "string", "required": true},
			{"name": "query", "type": "string", "required": true},
			{"name": "mode", "type": "string", "required": true},
			{"name": "max_results", "type": "integer", "required": true},
		},
		Returns: map[string]any{"results": "array", "status": "string", "engine": "string", "provenance": "object"},
		Handler: func(params map[string]any) any {
			backend := os.Getenv("OSOP_RECON_SEARXNG_URL")
			client := safeSearchClient()
			if trustedLocalSearx(backend) {
				client = safeLocalSearchClient()
			}
			return searchSearxNG(params, backend, client)
		},
	})
}

func unknownSearch(reason string) map[string]any {
	return map[string]any{
		"status": "unknown", "reason": reason, "engine": "searxng",
		"results": []map[string]any{},
		"provenance": map[string]any{
			"source": "unverified_external_search", "target_side_evidence_verified": false,
			"provider_native_cost_verified": false,
		},
	}
}

func verifiedDomain(input string) (string, bool) {
	domain := strings.ToLower(strings.TrimSpace(input))
	if len(domain) < 3 || len(domain) > 253 || strings.ContainsAny(domain, "/:@\\ ") || net.ParseIP(domain) != nil {
		return "", false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 || len(labels[len(labels)-1]) < 2 || domain == "localhost" || strings.HasSuffix(domain, ".local") || strings.HasSuffix(domain, ".internal") {
		return "", false
	}
	for _, label := range labels {
		if !searchDomainLabel.MatchString(label) {
			return "", false
		}
	}
	return domain, true
}

func searchEndpoint(raw string) (*url.URL, bool) {
	if len(raw) < 12 || len(raw) > 1024 || strings.TrimSpace(raw) != raw {
		return nil, false
	}
	// The only plaintext exception is a specifically opted-in SearXNG on the
	// operator's own loopback port. No hostname/DNS, arbitrary port, private
	// address, metadata IP, proxy or redirect is permitted for this exception.
	if trustedLocalSearx(raw) {
		local, err := url.Parse(raw)
		return local, err == nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, false
	}
	if u.Port() != "" && u.Port() != "443" {
		return nil, false
	}
	if _, ok := verifiedDomain(u.Hostname()); !ok {
		return nil, false
	}
	if u.Path != "" && u.Path != "/" && u.Path != "/search" {
		return nil, false
	}
	u.Path = "/search"
	return u, true
}

func trustedLocalSearx(raw string) bool {
	return raw == "http://127.0.0.1:8080/search" &&
		os.Getenv("OSOP_RECON_SEARXNG_ALLOW_LOCAL_HTTP") == "true"
}

func safeLocalSearchClient() *http.Client {
	return &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			Proxy: nil, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 1,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "127.0.0.1:8080" {
					return nil, errors.New("local search destination denied")
				}
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", address)
			},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func allowedPublicIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	// IsGlobalUnicast by itself includes several reserved and internal ranges.
	for _, text := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.0.0.0/24",
		"192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4", "2001:db8::/32", "2001::/32",
	} {
		prefix := netip.MustParsePrefix(text)
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func safeSearchClient() *http.Client {
	transport := &http.Transport{
		Proxy: nil, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 1,
		TLSHandshakeTimeout: 3 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || port != "443" {
				return nil, errors.New("search destination denied")
			}
			if _, ok := verifiedDomain(host); !ok {
				return nil, errors.New("search destination denied")
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil || len(ips) == 0 {
				return nil, errors.New("search name resolution unavailable")
			}
			for _, ip := range ips {
				if !allowedPublicIP(ip.IP) {
					return nil, errors.New("search destination denied")
				}
			}
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
	}
	return &http.Client{
		Timeout: 6 * time.Second, Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func resultLimit(value any) (int, bool) {
	switch n := value.(type) {
	case int:
		return n, n >= 1 && n <= 10
	case float64:
		v := int(n)
		return v, n == float64(v) && v >= 1 && v <= 10
	default:
		return 0, false
	}
}

func searchSearxNG(params map[string]any, rawURL string, client *http.Client) map[string]any {
	endpoint, configured := searchEndpoint(rawURL)
	if !configured {
		return unknownSearch("not_configured")
	}
	domain, ok := verifiedDomain(fmt.Sprint(params["domain"]))
	if !ok || params["domain"] == nil {
		return unknownSearch("invalid_target")
	}
	mode, _ := params["mode"].(string)
	maxResults, validLimit := resultLimit(params["max_results"])
	query, validQuery := params["query"].(string)
	if mode != "links" || !validLimit || !validQuery || len(query) > 250 {
		return unknownSearch("invalid_request")
	}
	query = strings.TrimSpace(query)
	if strings.HasPrefix(query, "site:"+domain) {
		query = strings.TrimSpace(strings.TrimPrefix(query, "site:"+domain))
	}
	if strings.Contains(strings.ToLower(query), "site:") || !searchTerms.MatchString(query) {
		return unknownSearch("invalid_request")
	}
	search := "site:" + domain
	if query != "" {
		search += " " + query
	}
	hash := sha256.Sum256([]byte(search))
	values := url.Values{}
	values.Set("q", search)
	values.Set("format", "json")
	values.Set("language", "en")
	endpoint.RawQuery = values.Encode()
	if client == nil {
		return unknownSearch("transport_unavailable")
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return unknownSearch("invalid_request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AI-OSOP-Authorized-Passive-Search/1.0")
	response, err := client.Do(req)
	if err != nil {
		return unknownSearch("backend_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > maxSearchResponseBytes {
		return unknownSearch("backend_unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxSearchResponseBytes+1))
	if err != nil || len(data) > maxSearchResponseBytes {
		return unknownSearch("backend_unavailable")
	}
	var body struct {
		Results []struct {
			Title string `json:"title"`
			URL   string `json:"url"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &body); err != nil || len(body.Results) > 100 {
		return unknownSearch("invalid_backend_response")
	}
	// A backend error envelope such as {"error":"rate limited"} must not
	// silently turn into a successful empty search. Empty results are valid
	// only when the upstream explicitly returned a JSON results array.
	var envelope map[string]json.RawMessage
	if json.Unmarshal(data, &envelope) != nil || len(envelope) == 0 ||
		len(envelope["results"]) == 0 ||
		strings.TrimSpace(string(envelope["results"])) == "null" ||
		!strings.HasPrefix(strings.TrimSpace(string(envelope["results"])), "[") {
		return unknownSearch("invalid_backend_response")
	}
	results := make([]map[string]any, 0, maxResults)
	seen := make(map[string]bool)
	for _, item := range body.Results {
		u, err := url.Parse(item.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Opaque != "" || u.Hostname() == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host != domain && !strings.HasSuffix(host, "."+domain) {
			continue
		}
		if u.Port() != "" && !((u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80")) {
			continue
		}
		// Public search indexes sometimes retain expired bearer/token query
		// values. Return only the scoped path: never feed indexed credentials
		// back into agent context, bus notifications, or reports.
		u.RawQuery, u.ForceQuery, u.Fragment = "", false, ""
		cleanURL := u.String()
		if len(cleanURL) > 1024 || seen[cleanURL] {
			continue
		}
		seen[cleanURL] = true
		cleanTitle := make([]rune, 0, 160)
		for _, char := range strings.TrimSpace(item.Title) {
			if !unicode.IsControl(char) && len(cleanTitle) < 160 {
				cleanTitle = append(cleanTitle, char)
			}
		}
		results = append(results, map[string]any{
			"url": cleanURL, "title": string(cleanTitle), "source": "searxng",
		})
		if len(results) >= maxResults {
			break
		}
	}
	return map[string]any{
		"status": "success", "engine": "searxng", "results": results,
		"provenance": map[string]any{
			"source": "unverified_external_search", "query_sha256": hex.EncodeToString(hash[:]),
			"target_side_evidence_verified": false, "provider_native_cost_verified": false,
			"result_count": strconv.Itoa(len(results)),
		},
	}
}
