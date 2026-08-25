// recon-mcp: REAL reconnaissance MCP server.
//
// Replaces the previous mock implementation (see main.go.mock.bak) whose handlers
// returned hardcoded data (e.g. nmap_scan always returned 127.0.0.1:80,443). Every
// tool here performs real work using only the Go standard library, so it has no
// dependency on external binaries (nmap/subfinder/httpx) that may be absent:
//
//   nmap_scan        -> native TCP connect scan (real connections, real open ports)
//   httpx_probe      -> native HTTP(S) probing (status, title, length, tech)
//   tech_fingerprint -> native header/body signature fingerprinting
//   subfinder_enum   -> real passive subdomain enum via crt.sh certificate transparency
//   wayback_urls     -> real historical URL discovery via the Wayback CDX API
//   amass_passive/active -> shells out to amass IF installed, else honest empty
//   shodan_lookup    -> real Shodan API IF OSOP_SHODAN_API_KEY set, else honest empty
//
// Tool names, parameters, and return shapes match ReconMCPAdapter
// (src/ai_osop/adapters/recon_mcp.py): subfinder_enum/amass_* -> {subdomains:[...]},
// nmap_scan -> {hosts:[...]}, httpx_probe -> {results:[...]},
// tech_fingerprint -> {fingerprints:{url:[...]}}, wayback_urls -> {urls:[...]},
// shodan_lookup -> {matches:[...]}.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ai-osop/mcp-servers/sdk"
)

func main() {
	server := sdk.NewServer("recon-mcp")

	// ---- subfinder_enum: real passive subdomain enum via crt.sh CT logs ----
	server.Register(sdk.Tool{
		Name:           "subfinder_enum",
		Description:    "Passive subdomain enumeration via crt.sh certificate transparency logs.",
		TimeoutSeconds: 60,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "domain", "type": "string", "description": "Domain to enumerate", "required": true},
		},
		Returns: map[string]any{"subdomains": "array"},
		Handler: func(params map[string]any) any {
			domain, _ := params["domain"].(string)
			if domain == "" {
				return map[string]any{"subdomains": []any{}, "error": "domain is required"}
			}
			subs, err := crtshEnum(domain)
			if err != nil {
				return map[string]any{"subdomains": []any{}, "error": err.Error(), "source": "crtsh"}
			}
			return map[string]any{"subdomains": subs, "source": "crtsh", "count": len(subs)}
		},
	})

	// ---- amass_passive: real if amass installed, else honest empty ----
	server.Register(sdk.Tool{
		Name:           "amass_passive",
		Description:    "Passive subdomain enumeration via amass (if installed).",
		TimeoutSeconds: 300,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "domain", "type": "string", "description": "Domain to enumerate", "required": true},
		},
		Returns: map[string]any{"subdomains": "array"},
		Handler: func(params map[string]any) any {
			domain, _ := params["domain"].(string)
			return amassEnum(domain, false)
		},
	})

	// ---- amass_active ----
	server.Register(sdk.Tool{
		Name:           "amass_active",
		Description:    "Active subdomain enumeration via amass (if installed).",
		TimeoutSeconds: 600,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "domain", "type": "string", "description": "Domain to enumerate", "required": true},
			{"name": "depth", "type": "integer", "description": "Recursion depth", "required": false},
		},
		Returns: map[string]any{"subdomains": "array"},
		Handler: func(params map[string]any) any {
			domain, _ := params["domain"].(string)
			return amassEnum(domain, true)
		},
	})

	// ---- nmap_scan: native TCP connect scan ----
	server.Register(sdk.Tool{
		Name:           "nmap_scan",
		Description:    "TCP connect port scan with service-name mapping (native, no nmap binary required).",
		TimeoutSeconds: 600,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "targets", "type": "array", "description": "Target IPs or hostnames", "required": true},
			{"name": "ports", "type": "string", "description": "Port spec: 'top-100', 'top-1000', or '80,443,8080'", "required": false},
		},
		Returns: map[string]any{"hosts": "array"},
		Handler: func(params map[string]any) any {
			targets := stringSlice(params["targets"])
			if len(targets) == 0 {
				return map[string]any{"hosts": []any{}, "error": "targets parameter is required and cannot be empty"}
			}
			portSpec, _ := params["ports"].(string)
			ports := parsePorts(portSpec)
			hosts := make([]map[string]any, 0, len(targets))
			for _, target := range targets {
				hosts = append(hosts, connectScan(target, ports))
			}
			return map[string]any{"hosts": hosts, "scan_type": "tcp-connect", "ports_scanned": len(ports)}
		},
	})

	// ---- httpx_probe: native HTTP(S) probing ----
	server.Register(sdk.Tool{
		Name:           "httpx_probe",
		Description:    "Probe URLs for status code, title, content length, and detected technologies.",
		TimeoutSeconds: 600,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "urls", "type": "array", "description": "URLs to probe", "required": true},
		},
		Returns: map[string]any{"results": "array"},
		Handler: func(params map[string]any) any {
			urls := stringSlice(params["urls"])
			if len(urls) == 0 {
				return map[string]any{"results": []any{}, "error": "urls parameter is required and cannot be empty"}
			}
			results := make([]map[string]any, 0, len(urls))
			for _, u := range urls {
				results = append(results, httpProbe(u))
			}
			return map[string]any{"results": results}
		},
	})

	// ---- tech_fingerprint: native header/body fingerprint ----
	server.Register(sdk.Tool{
		Name:           "tech_fingerprint",
		Description:    "Identify technologies on URLs from response headers and body markers.",
		TimeoutSeconds: 300,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "urls", "type": "array", "description": "URLs to fingerprint", "required": true},
		},
		Returns: map[string]any{"fingerprints": "object"},
		Handler: func(params map[string]any) any {
			urls := stringSlice(params["urls"])
			fps := map[string]any{}
			for _, u := range urls {
				res := httpProbe(u)
				if techs, ok := res["technologies"].([]string); ok {
					fps[u] = techs
				} else {
					fps[u] = []string{}
				}
			}
			return map[string]any{"fingerprints": fps}
		},
	})

	// ---- shodan_lookup: real if key present, else honest empty ----
	server.Register(sdk.Tool{
		Name:           "shodan_lookup",
		Description:    "Shodan host search (requires OSOP_SHODAN_API_KEY; honest empty otherwise).",
		TimeoutSeconds: 120,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "domain", "type": "string", "description": "Domain to search", "required": true},
		},
		Returns: map[string]any{"matches": "array"},
		Handler: func(params map[string]any) any {
			if os.Getenv("OSOP_SHODAN_API_KEY") == "" {
				return map[string]any{"matches": []any{}, "note": "OSOP_SHODAN_API_KEY not set; no Shodan enrichment"}
			}
			domain, _ := params["domain"].(string)
			return shodanLookup(domain)
		},
	})

	// ---- wayback_urls: real Wayback CDX historical URLs ----
	server.Register(sdk.Tool{
		Name:           "wayback_urls",
		Description:    "Historical URL discovery via the Internet Archive Wayback CDX API.",
		TimeoutSeconds: 120,
		ScopeCheck:     true,
		Parameters: []map[string]any{
			{"name": "domain", "type": "string", "description": "Domain to search", "required": true},
		},
		Returns: map[string]any{"urls": "array"},
		Handler: func(params map[string]any) any {
			domain, _ := params["domain"].(string)
			if domain == "" {
				return map[string]any{"urls": []any{}, "error": "domain is required"}
			}
			urls, err := waybackURLs(domain)
			if err != nil {
				return map[string]any{"urls": []any{}, "error": err.Error()}
			}
			return map[string]any{"urls": urls, "count": len(urls)}
		},
	})

		// FIX (mcp-port-env-2026-08-23): port was hardcoded, so the binary could not
	// be moved off a conflicting host port without a rebuild-by-edit. Read the
	// platform env (same var the Python settings use); fall back to the default.
	port := os.Getenv("OSOP_RECON_MCP_PORT")
	if port == "" {
		port = "8082"
	}
	_ = server.Run(":" + port)
}

// ============================ helpers ============================

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

// commonPorts is a curated "top ~100" TCP service-port list.
var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443, 445,
	465, 587, 636, 993, 995, 1025, 1433, 1521, 1723, 2049, 2082, 2083, 2375,
	2376, 3000, 3128, 3306, 3389, 4444, 5000, 5432, 5601, 5672, 5900, 5984,
	6379, 6443, 7001, 7077, 7474, 7687, 8000, 8008, 8009, 8080, 8081, 8082,
	8083, 8084, 8085, 8086, 8087, 8088, 8090, 8091, 8092, 8093, 8096, 8097,
	8098, 8161, 8200, 8443, 8500, 8888, 9000, 9042, 9092, 9200, 9300, 9443,
	9999, 10000, 11211, 15672, 27017, 27018, 5439, 5050, 4443, 8181,
}

var serviceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp",
	389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
	636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
	2049: "nfs", 3306: "mysql", 3389: "rdp", 5000: "http-alt", 5432: "postgresql",
	5601: "kibana", 5672: "amqp", 5900: "vnc", 6379: "redis", 6443: "kube-api",
	7474: "neo4j-http", 7687: "neo4j-bolt", 8080: "http-proxy", 8200: "http-osop-api",
	8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
	15672: "rabbitmq-mgmt", 8888: "http-alt",
}

func parsePorts(spec string) []int {
	spec = strings.TrimSpace(strings.ToLower(spec))
	switch spec {
	case "", "top-100", "top100", "top-1000", "top1000", "default":
		return commonPorts
	}
	// explicit comma list, e.g. "80,443,8080" (ranges a-b supported)
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, e1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if e1 == nil && e2 == nil && lo <= hi && hi-lo < 65536 {
				for p := lo; p <= hi; p++ {
					ports = append(ports, p)
				}
			}
			continue
		}
		if p, err := strconv.Atoi(part); err == nil {
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return commonPorts
	}
	return ports
}

// validHostnameRe matches a syntactically valid DNS hostname (labels of
// [a-z0-9-] separated by dots, no spaces or other punctuation).
var validHostnameRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func isValidHostname(name string) bool {
	if len(name) == 0 || len(name) > 253 || strings.ContainsAny(name, " \t\r\n") {
		return false
	}
	return validHostnameRe.MatchString(name)
}

func serviceFor(port int) string {
	if s, ok := serviceNames[port]; ok {
		return s
	}
	return "unknown"
}

// connectScan performs a real TCP connect scan against host across ports,
// bounded concurrency, and returns a {ip, hostnames, ports:[{port,service,state}]} map.
func connectScan(host string, ports []int) map[string]any {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	if i := strings.IndexAny(host, "/:"); i >= 0 {
		host = host[:i]
	}

	ip := host
	if addrs, err := net.LookupHost(host); err == nil && len(addrs) > 0 {
		ip = addrs[0]
	}

	type openPort struct {
		port    int
		service string
	}
	results := make(chan openPort, len(ports))
	sem := make(chan struct{}, 100) // cap concurrency
	var wg sync.WaitGroup

	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			conn, err := net.DialTimeout("tcp", addr, 1500*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				results <- openPort{port: port, service: serviceFor(port)}
			}
		}(p)
	}
	go func() { wg.Wait(); close(results) }()

	open := make([]map[string]any, 0)
	for r := range results {
		open = append(open, map[string]any{"port": r.port, "service": r.service, "state": "open"})
	}
	sort.Slice(open, func(i, j int) bool {
		return open[i]["port"].(int) < open[j]["port"].(int)
	})

	hostnames := []string{}
	if names, err := net.LookupAddr(ip); err == nil {
		for _, n := range names {
			hostnames = append(hostnames, strings.TrimSuffix(n, "."))
		}
	}

	return map[string]any{
		"ip":        ip,
		"hostnames": hostnames,
		"ports":     open,
		"os":        "",
	}
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func insecureClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		// Do not follow redirects automatically; record the first response.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// httpProbe performs a real GET and extracts status, title, length, technologies.
func httpProbe(rawURL string) map[string]any {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}
	out := map[string]any{
		"url":            rawURL,
		"method":         "GET",
		"status_code":    0,
		"title":          "",
		"content_length": 0,
		"technologies":   []string{},
		"webserver":      "",
	}
	client := insecureClient(15 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	req.Header.Set("User-Agent", "ai-osop-recon/1.0")
	resp, err := client.Do(req)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	out["status_code"] = resp.StatusCode
	out["content_length"] = len(body)
	out["webserver"] = resp.Header.Get("Server")
	if m := titleRe.FindSubmatch(body); m != nil {
		out["title"] = strings.TrimSpace(unescapeHTML(string(m[1])))
	}
	out["technologies"] = fingerprint(resp.Header, body)
	if loc := resp.Header.Get("Location"); loc != "" {
		out["redirect"] = loc
	}
	return out
}

// fingerprint detects technologies from response headers and body markers.
func fingerprint(h http.Header, body []byte) []string {
	techs := map[string]bool{}
	add := func(t string) {
		if t != "" {
			techs[t] = true
		}
	}
	if s := h.Get("Server"); s != "" {
		add(s)
	}
	if x := h.Get("X-Powered-By"); x != "" {
		add(x)
	}
	if h.Get("X-AspNet-Version") != "" {
		add("ASP.NET")
	}
	if strings.Contains(h.Get("Set-Cookie"), "laravel_session") {
		add("Laravel")
	}
	if strings.Contains(h.Get("Set-Cookie"), "PHPSESSID") {
		add("PHP")
	}
	if strings.Contains(h.Get("Set-Cookie"), "JSESSIONID") {
		add("Java")
	}
	b := strings.ToLower(string(body))
	if strings.Contains(b, "wp-content") || strings.Contains(b, "wp-includes") {
		add("WordPress")
	}
	if strings.Contains(b, "__next_data__") || strings.Contains(b, "/_next/") {
		add("Next.js")
	}
	if strings.Contains(b, "ng-version") {
		add("Angular")
	}
	if strings.Contains(b, "data-reactroot") || strings.Contains(b, "_reactrootcontainer") {
		add("React")
	}
	if strings.Contains(b, "drupal") {
		add("Drupal")
	}
	if strings.Contains(b, "csrf-token") {
		add("CSRF-protected")
	}
	out := make([]string, 0, len(techs))
	for t := range techs {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// unescapeHTML unescapes the few entities common in <title> tags.
func unescapeHTML(s string) string {
	r := strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", "\"", "&#39;", "'")
	return r.Replace(s)
}

// crtshEnum queries crt.sh certificate transparency logs for subdomains.
func crtshEnum(domain string) ([]map[string]any, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	client := insecureClient(45 * time.Second)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh returned HTTP %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh JSON parse: %v", err)
	}
	seen := map[string]bool{}
	subs := make([]map[string]any, 0)
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "*.")))
			// Reject non-hostnames: crt.sh name_value can contain certificate
			// common-names like "as207960 test intermediate - example.com" (spaces,
			// punctuation) that are NOT real subdomains. Only accept valid DNS names.
			if name == "" || seen[name] || !strings.HasSuffix(name, domain) || !isValidHostname(name) {
				continue
			}
			seen[name] = true
			subs = append(subs, map[string]any{"domain": name, "source": "crtsh", "confidence": 0.8})
		}
	}
	sort.Slice(subs, func(i, j int) bool {
		return subs[i]["domain"].(string) < subs[j]["domain"].(string)
	})
	return subs, nil
}

// waybackURLs queries the Internet Archive Wayback CDX API for historical URLs.
func waybackURLs(domain string) ([]map[string]any, error) {
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey&limit=1000", domain)
	client := insecureClient(60 * time.Second)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("wayback JSON parse: %v", err)
	}
	urls := make([]map[string]any, 0)
	for i, row := range rows {
		if i == 0 || len(row) == 0 { // first row is the header
			continue
		}
		urls = append(urls, map[string]any{"url": row[0], "method": "GET"})
	}
	return urls, nil
}

// amassEnum shells out to amass only if it is installed; otherwise returns an
// honest empty result (never fabricated data).
func amassEnum(domain string, active bool) map[string]any {
	if domain == "" {
		return map[string]any{"subdomains": []any{}, "error": "domain is required"}
	}
	path, err := exec.LookPath("amass")
	if err != nil {
		return map[string]any{"subdomains": []any{}, "note": "amass not installed; subfinder_enum (crt.sh) provides passive coverage"}
	}
	args := []string{"enum", "-d", domain, "-silent"}
	if !active {
		args = append(args, "-passive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).Output()
	if err != nil {
		return map[string]any{"subdomains": []any{}, "error": err.Error()}
	}
	subs := make([]map[string]any, 0)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			subs = append(subs, map[string]any{"domain": line, "source": "amass", "confidence": 0.7})
		}
	}
	return map[string]any{"subdomains": subs, "source": "amass"}
}

// shodanLookup performs a real Shodan DNS lookup when an API key is set.
func shodanLookup(domain string) map[string]any {
	key := os.Getenv("OSOP_SHODAN_API_KEY")
	url := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, key)
	client := insecureClient(30 * time.Second)
	resp, err := client.Get(url)
	if err != nil {
		return map[string]any{"matches": []any{}, "error": err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return map[string]any{"matches": []any{}, "error": "shodan JSON parse"}
	}
	return map[string]any{"matches": []any{parsed}}
}
