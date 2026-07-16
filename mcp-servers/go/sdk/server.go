package sdk

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// sanitizeParams blocks argument-injection (OSOP-P1-09): these tools pass param values
// straight into exec.Command argv (sqlmap/nmap/ffuf/nuclei/...). A value that begins with
// "-" would be reinterpreted as a tool FLAG, and embedded whitespace/newlines can split or
// inject additional argv. None of the legitimate inputs (url, target, host, ports, wordlist,
// mode, js_url) ever start with "-" or contain whitespace, so we reject those globally.
// Returns the offending key + reason, or "" if all string params are safe.
func sanitizeParams(params map[string]any) (string, string) {
	for k, v := range params {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if strings.HasPrefix(s, "-") {
			return k, "value may not start with '-' (argument injection blocked)"
		}
		if strings.ContainsAny(s, " \t\r\n") {
			return k, "value may not contain whitespace"
		}
	}
	return "", ""
}

type Tool struct {
	Name             string                   `json:"name"`
	Description      string                   `json:"description"`
	Parameters       []map[string]any         `json:"parameters"`
	Returns          map[string]any           `json:"returns"`
	TimeoutSeconds   int                      `json:"timeout_seconds"`
	RequiresApproval bool                     `json:"requires_approval"`
	ScopeCheck        bool                     `json:"scope_check"`
	Handler           func(map[string]any) any `json:"-"`
}

type ScopeDefinition struct {
	EngagementID      string   `json:"engagement_id"`
	Domains           []string `json:"domains"`
	IPs               []string `json:"ips"`
	Exclusions        []string `json:"exclusions"`
	AllowedTechniques []string `json:"allowed_techniques"`
}

type Server struct {
	ID        string
	Version   string
	Tools     map[string]Tool
	StartedAt time.Time
	mu        sync.RWMutex
	Scope     ScopeDefinition
	HasScope  bool
}

func NewServer(id string) *Server {
	return &Server{ID: id, Version: "0.1.0", Tools: map[string]Tool{}, StartedAt: time.Now()}
}

func (s *Server) Register(tool Tool) {
	s.Tools[tool.Name] = tool
}

// loadEnvToken retrieves OSOP_API_TOKEN from the environment or searches upwards for a .env file.
func loadEnvToken() string {
	if token := os.Getenv("OSOP_API_TOKEN"); token != "" {
		return token
	}
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for i := range 5 {
		envPath := filepath.Join(dir, fmt.Sprintf(".env%d", i))
		_ = envPath // just mapping
		envPath = filepath.Join(dir, ".env")
		if _, err := os.Stat(envPath); err == nil {
			file, err := os.Open(envPath)
			if err == nil {
				defer file.Close()
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if strings.HasPrefix(line, "#") || line == "" {
						continue
					}
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						key := strings.TrimSpace(parts[0])
						val := strings.TrimSpace(parts[1])
						if (strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"")) ||
							(strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'")) {
							val = val[1 : len(val)-1]
						}
						if key == "OSOP_API_TOKEN" {
							return val
						}
					}
				}
			}
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func checkAuth(w http.ResponseWriter, r *http.Request, expectedToken string) bool {
	if expectedToken == "" {
		return true
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Unauthorized: Missing Authorization header", http.StatusUnauthorized)
		return false
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		http.Error(w, "Unauthorized: Invalid Authorization header format", http.StatusUnauthorized)
		return false
	}
	presentedToken := parts[1]
	if !secureCompare(presentedToken, expectedToken) {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return false
	}
	return true
}

func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range len(a) {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

func extractHost(target string) string {
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err == nil {
			host := u.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				return h
			}
			return host
		}
	}
	if h, _, err := net.SplitHostPort(target); err == nil {
		return h
	}
	return target
}

func ipInList(ipStr string, list []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, item := range list {
		if _, ipnet, err := net.ParseCIDR(item); err == nil {
			if ipnet.Contains(ip) {
				return true
			}
		} else {
			allowedIP := net.ParseIP(item)
			if allowedIP != nil && allowedIP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func domainMatches(domain string, allowed []string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, item := range allowed {
		item = strings.ToLower(strings.TrimSpace(item))
		// Strip port from allowed domain (e.g. "localhost:3000" → "localhost")
		// so the Go server matches against the bare hostname extracted by
		// extractHost(), which strips the port from the target URL.
		if h, _, err := net.SplitHostPort(item); err == nil {
			item = h
		}
		if item == domain {
			return true
		}
		if strings.HasSuffix(domain, "."+item) {
			return true
		}
	}
	return false
}

func (s *Server) isTargetInScope(target string) bool {
	host := extractHost(target)

	// 1. Check exclusions first
	if ipInList(host, s.Scope.Exclusions) {
		return false
	}
	if domainMatches(host, s.Scope.Exclusions) {
		return false
	}

	// 2. Check allowed IPs
	if ipInList(host, s.Scope.IPs) {
		return true
	}

	// 3. Check allowed domains
	if domainMatches(host, s.Scope.Domains) {
		return true
	}

	return false
}

func (s *Server) ValidateParams(params map[string]any) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.HasScope || s.Scope.EngagementID == "api-bootstrap" {
		return nil
	}

	targetKeys := []string{"domain", "target", "targets", "url", "host", "hosts", "ip", "ips"}
	for _, key := range targetKeys {
		val, ok := params[key]
		if !ok {
			continue
		}
		if strVal, ok := val.(string); ok {
			if strVal != "" && !s.isTargetInScope(strVal) {
				return fmt.Errorf("target '%s' is out of scope for engagement '%s'", strVal, s.Scope.EngagementID)
			}
		}
		if sliceVal, ok := val.([]any); ok {
			for _, item := range sliceVal {
				if strItem, ok := item.(string); ok {
					if strItem != "" && !s.isTargetInScope(strItem) {
						return fmt.Errorf("target '%s' is out of scope for engagement '%s'", strItem, s.Scope.EngagementID)
					}
				}
			}
		}
	}
	return nil
}

func (s *Server) Run(addr string) error {
	expectedToken := loadEnvToken()

	// Enforce loopback binding: if unspecified or starts with :, bind strictly to 127.0.0.1
	if !strings.Contains(addr, ":") {
		addr = "127.0.0.1:" + addr
	} else if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"status": "ready", "server_id": s.ID})
	})

	http.HandleFunc("/mcp/initialize", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r, expectedToken) {
			return
		}
		var initReq struct {
			Scope     ScopeDefinition `json:"scope"`
			SessionID string          `json:"session_id"`
		}
		if r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&initReq); err == nil {
				s.mu.Lock()
				s.Scope = initReq.Scope
				s.HasScope = true
				s.mu.Unlock()
				log.Printf("[%s] Initialized scope for engagement %s (session %s)", s.ID, s.Scope.EngagementID, initReq.SessionID)
			}
		}

		tools := make([]Tool, 0, len(s.Tools))
		for _, tool := range s.Tools {
			tools = append(tools, tool)
		}
		writeJSON(w, map[string]any{
			"server_id":    s.ID,
			"version":      s.Version,
			"capabilities": []string{"tools"},
			"tools":        tools,
			"status":       "ready",
		})
	})

	http.HandleFunc("/mcp/execute", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r, expectedToken) {
			return
		}
		var req struct {
			ToolName   string         `json:"tool_name"`
			Parameters map[string]any `json:"parameters"`
			RequestID  string         `json:"request_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		tool, ok := s.Tools[req.ToolName]
		if !ok {
			writeJSON(w, map[string]any{"request_id": req.RequestID, "status": "error", "error": "unknown tool"})
			return
		}
		if badKey, reason := sanitizeParams(req.Parameters); badKey != "" {
			writeJSON(w, map[string]any{
				"request_id": req.RequestID,
				"status":     "error",
				"error":      "rejected unsafe parameter '" + badKey + "': " + reason,
			})
			return
		}
		if tool.ScopeCheck {
			if err := s.ValidateParams(req.Parameters); err != nil {
				writeJSON(w, map[string]any{
					"request_id": req.RequestID,
					"status":     "error",
					"error":      "out of scope: " + err.Error(),
				})
				return
			}
		}
		writeJSON(w, map[string]any{"request_id": req.RequestID, "status": "success", "result": tool.Handler(req.Parameters)})
	})

	log.Printf("%s listening on %s", s.ID, addr)
	return http.ListenAndServe(addr, nil)
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}
