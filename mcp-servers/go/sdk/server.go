// Package sdk exposes the legacy AI-OSOP JSON-over-HTTP MCP-compatible catalog.
//
// SECURITY: All registered native Tool.Handler dispatch stays DISABLED.
// An optional, explicitly configured, pinned validator can redeem signed
// one-use grants for a single built-in inert authority_status query only.
// A shared token, caller-supplied claims, and a local nonce map never suffice.
package sdk

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// The Python MCPToolDefinition parser recognizes these exact enums.
	// Unknown/unclassified native handlers must never inherit READ_ONLY.
	SideEffectReadOnly        = "READ_ONLY"
	SideEffectReconActive     = "RECON_ACTIVE"
	SideEffectInvasiveExploit = "INVASIVE_EXPLOIT"

	maxInitBodyBytes = 8192
)

type Tool struct {
	Name             string                   `json:"name"`
	Description      string                   `json:"description"`
	Parameters       []map[string]any         `json:"parameters"`
	Returns          map[string]any           `json:"returns"`
	TimeoutSeconds   int                      `json:"timeout_seconds"`
	RequiresApproval bool                     `json:"requires_approval"`
	ScopeCheck       bool                     `json:"scope_check"`
	SideEffectClass  string                   `json:"side_effect_class"`
	Handler          func(map[string]any) any `json:"-"`
}

type Server struct {
	ID         string
	Version    string
	Tools      map[string]Tool
	StartedAt  time.Time
	mu         sync.RWMutex
	native     *nativeAuthority
	supervisor *nativeSupervisorAdmission
}

func NewServer(id string) *Server {
	return &Server{
		ID: id, Version: "0.1.0", Tools: map[string]Tool{}, StartedAt: time.Now(),
	}
}

// Register records *declarations*, not remotely executable capabilities. The
// legacy Go cmd registrations intentionally keep their source metadata, while
// the outbound catalog below conservatively classifies unqualified handlers.
func (s *Server) Register(tool Tool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Never let cmd-registered native handlers shadow SDK-owned status.
	if tool.Name == NativeAuthorityStatusTool {
		return
	}
	if s.Tools == nil {
		s.Tools = make(map[string]Tool)
	}
	s.Tools[tool.Name] = tool
}

func safeSideEffect(value string) string {
	switch value {
	case SideEffectReadOnly, SideEffectReconActive, SideEffectInvasiveExploit:
		return value
	default:
		return SideEffectInvasiveExploit
	}
}

// snapshotTools is used ONLY for inert schema discovery. Never trust a Go cmd
// tool's ScopeCheck/RequiresApproval metadata as server-side enforcement.
// Every declaration is shown as high-risk until independently classified.
func (s *Server) snapshotTools() []Tool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.native != nil {
		// Do not even negotiate legacy native cmd tools in an enabled
		// inert-probe session. They lack independent source-side Task authority
		// and some have incomplete or misleading legacy parameter schemas.
		return []Tool{authorityStatusTool()}
	}
	tools := make([]Tool, 0, len(s.Tools))
	for _, definition := range s.Tools {
		item := definition
		item.SideEffectClass = safeSideEffect(item.SideEffectClass)
		item.RequiresApproval = true
		item.ScopeCheck = true
		item.Handler = nil // never include a function or executable reference
		tools = append(tools, item)
	}
	return tools
}

func reply(w http.ResponseWriter, code int, message any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(message) // fixed, nonsecret values only
}

func methodPOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		reply(w, http.StatusMethodNotAllowed, map[string]any{
			"status": "error", "error": "method_not_allowed",
		})
		return false
	}
	return true
}

// Handler provides an isolated mux for httptest and Run. It is deliberately
// impossible to execute any Tool.Handler via this HTTP transport. Only the
// built-in inert authority_status may confirm a signed, durably redeemed grant.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			reply(w, http.StatusMethodNotAllowed, map[string]any{
				"status": "error", "error": "method_not_allowed",
			})
			return
		}
		// Only the explicitly configured inert status diagnostic can initialize.
		// This 200 reports local trust CONFIGURATION, never live redemption,
		// native scanner capability or independently verified target effect.
		if s.nativeConfig() != nil {
			reply(w, http.StatusOK, map[string]any{
				"status": "configured_unverified", "server_id": s.ID,
				"execution_enabled": false, "authority_verified": false,
				"native_scanners_enabled": false,
			})
			return
		}
		reply(w, http.StatusServiceUnavailable, map[string]any{
			"status": "unavailable", "server_id": s.ID,
			"execution_enabled": false, "authority_verified": false,
			"reason": "source_side_signed_authority_unavailable",
		})
	})
	mux.HandleFunc("/mcp/initialize", func(w http.ResponseWriter, r *http.Request) {
		if !methodPOST(w, r) {
			return
		}
		// Canonical Python MCPInitializeRequest contains scope, auth_credentials,
		// session_id and metadata. It is *not* a signed approval. Bounded JSON
		// parse is solely a shape/DoS check; no credential field is inspected or
		// promoted to authorization.
		body, err := io.ReadAll(io.LimitReader(r.Body, maxInitBodyBytes+1))
		if err != nil || len(body) == 0 || len(body) > maxInitBodyBytes ||
			strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])) != "application/json" ||
			validNativeInitialize(body) != nil {
			reply(w, http.StatusBadRequest, map[string]any{
				"status": "error", "error": "invalid_initialize_metadata",
			})
			return
		}
		if s.nativeConfig() != nil {
			reply(w, http.StatusOK, map[string]any{
				"server_id": s.ID, "version": s.Version,
				"capabilities": []string{"native_grant_probe_v1"},
				"tools":        s.snapshotTools(), "status": "ready",
				"execution_enabled": false, "authority_verified": false,
				"native_scanners_enabled": false,
			})
			return
		}
		reply(w, http.StatusOK, map[string]any{
			"server_id": s.ID, "version": s.Version,
			"capabilities": []string{}, "tools": s.snapshotTools(),
			"status": "unavailable", "execution_enabled": false,
			"authority_verified": false,
			"reason":             "source_side_signed_authority_unavailable",
		})
	})
	mux.HandleFunc("/mcp/execute", func(w http.ResponseWriter, r *http.Request) {
		if !methodPOST(w, r) {
			return
		}
		// Default-deny remains unchanged for all legacy cmd binaries with
		// no explicitly provisioned per-server native trust root.
		if s.nativeConfig() != nil {
			grantHeaders := r.Header.Values(nativeGrantHeader)
			contentType := strings.ToLower(strings.TrimSpace(strings.Split(
				r.Header.Get("Content-Type"), ";",
			)[0]))
			if len(grantHeaders) == 1 && contentType == "application/json" {
				// Supervisor credentials must arrive through the independent
				// signed provisioning channel, NEVER via an MCP caller.
				if len(r.Header.Values("X-OSOP-Native-Supervisor-Proof")) != 0 {
					reply(w, http.StatusServiceUnavailable, map[string]any{
						"status": "error", "error": "native_execution_not_authorized",
						"execution_enabled": false,
					})
					return
				}
				if requestID, err := s.verifyAndRedeemAuthorityStatus(
					r.Context(), r.Body, grantHeaders[0],
				); err == nil {
					// This is ONLY native worker in-memory integrity testimony.
					// The source's durable PostgreSQL OFFER separately proves the
					// original bytes were offered, not that a target was contacted.
					reviewedBytes := false
					if issued, e := decodeNativeGrant(grantHeaders[0]); e == nil {
						reviewedBytes = issued.Claims.ResourceSHA256 != nil
					}
					nativeResult := map[string]any{
						"status":                          "grant_durably_redeemed",
						"tool_name":                       NativeAuthorityStatusTool,
						"native_target_execution_enabled": false,
						"target_contacted":                false,
						"provider_contacted":              false,
					}
					if reviewedBytes {
						nativeResult["resource_bytes_received_verified"] = true
					}
					reply(w, http.StatusOK, map[string]any{
						"request_id": requestID, "status": "success",
						"result": nativeResult,
					})
					return
				}
			}
		}
		// Do not parse or echo caller-controlled request IDs, parameters,
		// authorization, alleged signed scopes or private validator errors.
		reply(w, http.StatusServiceUnavailable, map[string]any{
			"status": "error", "error": "native_execution_not_authorized",
			"execution_enabled": false,
		})
	})
	// This separate ingress accepts only *independently signed* short-lived
	// supervisor testimony. It cannot issue a native grant or dispatch tools.
	mux.HandleFunc("/native-supervisor/provision", s.handleSupervisorProvision)
	return mux
}

// localAddress ensures legacy cmd server.Run(":808x") binds loopback only.
// Services cannot opt into public interfaces without a new audited transport.
func localAddress(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", errors.New("MCP loopback bind required")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", errors.New("MCP bounded loopback port required")
	}
	switch strings.ToLower(host) {
	case "", "0.0.0.0", "::", "[::]", "127.0.0.1", "localhost":
		return net.JoinHostPort("127.0.0.1", port), nil
	case "::1":
		return net.JoinHostPort("::1", port), nil
	default:
		return "", errors.New("MCP non-loopback bind denied")
	}
}

func (s *Server) Run(addr string) error {
	safeAddr, err := localAddress(addr)
	if err != nil {
		return err
	}
	if err := s.configureNativeGrantFromEnvironment(); err != nil {
		return err
	}
	if err := s.configureNativeSupervisorFromEnvironment(); err != nil {
		return err
	}
	// The standalone production listener requires both independently pinned
	// HTTPS redemption and a distinct server credential. Tests may exercise
	// Handler() with a controlled fake validator, never a production bypass.
	if current := s.nativeConfig(); current != nil && current.serviceSecret == "" {
		return errors.New("independent native MCP server credential unavailable")
	}
	// A bound port allows inert discovery only, never native execution.
	log.Printf("%s metadata-only MCP listener on %s (execution denied)", s.ID, safeAddr)
	httpServer := &http.Server{
		Addr:              safeAddr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    8192,
	}
	return httpServer.ListenAndServe()
}

func writeJSON(w http.ResponseWriter, data any) {
	reply(w, http.StatusOK, data)
}
