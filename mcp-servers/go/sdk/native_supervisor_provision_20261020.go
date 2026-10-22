package sdk

// A separately signed supervisor admission is provisioned through an isolated
// loopback-only channel. Ordinary MCP callers cannot supply an independent
// worker proof; they can only present an original centrally signed grant.
// A successful local provision DOES NOT replace source-side 0033 authority:
// PostgreSQL must revalidate the exact worker, source and one-time grant.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

const nativeSupervisorDomain = "ai-osop/native-grant-worker-redemption/v1\x00"
const nativeSupervisorTrustEnv = "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON"

var nativeHex32 = regexp.MustCompile(`^[a-f0-9]{32}$`)
var nativeHex64 = regexp.MustCompile(`^[a-f0-9]{64}$`)

type NativeSupervisorPublicIdentity struct {
	KeyID     string
	PublicKey ed25519.PublicKey
}

type nativeSupervisorAdmission struct {
	mu      sync.Mutex
	trusted map[string]NativeSupervisorPublicIdentity
	pending map[string]nativePendingProof
	used    map[string]int64
}

type nativePendingProof struct {
	claims nativeSupervisorProofClaims
	raw    []byte
}

// The exact independent source-side 23-field proof contract, never arbitrary
// tool-supplied metadata. Its signature and original claim digest are required.
type nativeSupervisorProofClaims struct {
	Version             int64  `json:"version"`
	GrantID             string `json:"grant_id"`
	RequestID           string `json:"request_id"`
	EngagementID        string `json:"engagement_id"`
	FlowID              string `json:"flow_id"`
	TaskID              string `json:"task_id"`
	SubtaskID           string `json:"subtask_id"`
	ActionID            string `json:"action_id"`
	OwnerID             string `json:"owner_id"`
	ServerID            string `json:"server_id"`
	WorkerID            string `json:"worker_id"`
	ContainerID         string `json:"container_id"`
	SupervisorID        string `json:"supervisor_id"`
	Epoch               int64  `json:"epoch"`
	Revision            int64  `json:"revision"`
	ApprovalID          string `json:"approval_id"`
	LeaseID             string `json:"lease_id"`
	AuthorizationSHA256 string `json:"authorization_sha256"`
	ClaimsSHA256        string `json:"claims_sha256"`
	ResourceSHA256      string `json:"resource_sha256"`
	Nonce               string `json:"nonce"`
	IssuedAt            int64  `json:"issued_at"`
	ExpiresAt           int64  `json:"expires_at"`
}

var nativeSupervisorClaimKeys = map[string]bool{
	"version": true, "grant_id": true, "request_id": true, "engagement_id": true,
	"flow_id": true, "task_id": true, "subtask_id": true, "action_id": true,
	"owner_id": true, "server_id": true, "worker_id": true, "container_id": true,
	"supervisor_id": true, "epoch": true, "revision": true, "approval_id": true,
	"lease_id": true, "authorization_sha256": true, "claims_sha256": true,
	"resource_sha256": true, "nonce": true, "issued_at": true, "expires_at": true,
}

// ConfigureNativeSupervisorTrust accepts independently provisioned public
// keys only. No signing seeds, API tokens or caller-selected keys enter here.
func (s *Server) ConfigureNativeSupervisorTrust(roots map[string]NativeSupervisorPublicIdentity) error {
	if len(roots) == 0 || len(roots) > 8 {
		return errors.New("bounded independent supervisor trust required")
	}
	trusted := make(map[string]NativeSupervisorPublicIdentity, len(roots))
	for id, identity := range roots {
		if !nativeIdentifierRE.MatchString(id) || len(id) > 96 || !nativeKidRE.MatchString(identity.KeyID) || len(identity.PublicKey) != ed25519.PublicKeySize {
			return errors.New("invalid independent supervisor trust root")
		}
		if config := s.nativeConfig(); config != nil {
			for _, issuer := range config.keys {
				if bytes.Equal(issuer, identity.PublicKey) {
					return errors.New("grant issuer cannot also be native supervisor")
				}
			}
		}
		trusted[id] = NativeSupervisorPublicIdentity{KeyID: identity.KeyID, PublicKey: append(ed25519.PublicKey(nil), identity.PublicKey...)}
	}
	s.mu.Lock()
	s.supervisor = &nativeSupervisorAdmission{trusted: trusted, pending: make(map[string]nativePendingProof), used: make(map[string]int64)}
	s.mu.Unlock()
	return nil
}

func (s *Server) configureNativeSupervisorFromEnvironment() error {
	raw := os.Getenv(nativeSupervisorTrustEnv)
	if raw == "" {
		return nil
	} // resource-bound grants will fail closed
	if len(raw) > 8192 {
		return errors.New("supervisor trust exceeds safe bound")
	}
	outer, err := decodeExactObject([]byte(raw), mapFromTrustNames(raw))
	if err != nil || len(outer) == 0 || len(outer) > 8 {
		return errors.New("invalid independent supervisor trust")
	}
	roots := make(map[string]NativeSupervisorPublicIdentity, len(outer))
	for supervisorID, item := range outer {
		parts, err := decodeExactObject(item, map[string]bool{"kid": true, "public_key": true, "secret_sha256": true})
		if err != nil {
			return errors.New("invalid independent supervisor entry")
		}
		var kid, encoded, secretHash string
		if json.Unmarshal(parts["kid"], &kid) != nil || json.Unmarshal(parts["public_key"], &encoded) != nil || json.Unmarshal(parts["secret_sha256"], &secretHash) != nil || !nativeHex64.MatchString(secretHash) {
			return errors.New("invalid independent supervisor trust parameters")
		}
		pub, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(pub) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(pub) != encoded {
			return errors.New("noncanonical independent supervisor public key")
		}
		roots[supervisorID] = NativeSupervisorPublicIdentity{KeyID: kid, PublicKey: pub}
	}
	return s.ConfigureNativeSupervisorTrust(roots)
}

// Discover names without trusting their values: duplicate keys and unknown
// nested fields still fail on the second, exact JSON decoder.
func mapFromTrustNames(raw string) map[string]bool {
	var names map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &names) != nil || len(names) == 0 || len(names) > 8 {
		return nil
	}
	result := make(map[string]bool, len(names))
	for name := range names {
		result[name] = true
	}
	return result
}

func canonicalSupervisorProof(claims nativeSupervisorProofClaims) ([]byte, error) {
	// JSON map recursion sorts keys exactly like source Python canonical JSON.
	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	var plain map[string]any
	if json.Unmarshal(raw, &plain) != nil {
		return nil, errors.New("invalid canonical supervisor claims")
	}
	return json.Marshal(plain)
}

func (s *Server) supervisorAdmission() *nativeSupervisorAdmission {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.supervisor
}

func (s *Server) handleSupervisorProvision(w http.ResponseWriter, r *http.Request) {
	if !methodPOST(w, r) {
		return
	}
	address, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(address) == nil || !net.ParseIP(address).IsLoopback() || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" {
		reply(w, http.StatusForbidden, map[string]any{"status": "error", "error": "independent_supervisor_loopback_required"})
		return
	}
	if len(r.Header.Values("Authorization")) != 0 || len(r.Header.Values("X-OSOP-Native-Grant")) != 0 || len(r.Header.Values("X-OSOP-Native-Supervisor-Proof")) != 0 || r.Header.Get("Content-Type") != "application/json" {
		reply(w, http.StatusForbidden, map[string]any{"status": "error", "error": "independent_supervisor_only"})
		return
	}
	if s.nativeConfig() == nil || s.supervisorAdmission() == nil {
		reply(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "execution_enabled": false})
		return
	}
	value, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil || len(value) == 0 || len(value) > 4096 {
		reply(w, http.StatusForbidden, map[string]any{"status": "error", "error": "invalid_supervisor_proof"})
		return
	}
	proof, err := decodeExactObject(value, map[string]bool{"claims": true, "kid": true, "signature": true})
	if err != nil {
		reply(w, http.StatusForbidden, map[string]any{"status": "error", "error": "invalid_supervisor_proof"})
		return
	}
	if _, err = decodeExactObject(proof["claims"], nativeSupervisorClaimKeys); err != nil {
		reply(w, http.StatusForbidden, map[string]any{"status": "error", "error": "invalid_supervisor_claims"})
		return
	}
	var claims nativeSupervisorProofClaims
	var kid, signature string
	if json.Unmarshal(proof["claims"], &claims) != nil || json.Unmarshal(proof["kid"], &kid) != nil || json.Unmarshal(proof["signature"], &signature) != nil || !s.validSupervisorClaims(claims, time.Now().Unix()) {
		reply(w, http.StatusForbidden, map[string]any{"status": "error", "error": "invalid_supervisor_claims"})
		return
	}
	admission := s.supervisorAdmission()
	identity, ok := admission.trusted[claims.SupervisorID]
	if !ok || identity.KeyID != kid || len(signature) != 86 {
		reply(w, http.StatusForbidden, map[string]any{"status": "error", "error": "untrusted_supervisor"})
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(sig) != signature {
		reply(w, http.StatusForbidden, map[string]any{"status": "error", "error": "invalid_supervisor_signature"})
		return
	}
	canonical, err := canonicalSupervisorProof(claims)
	if err != nil || !ed25519.Verify(identity.PublicKey, append([]byte(nativeSupervisorDomain), canonical...), sig) {
		reply(w, http.StatusForbidden, map[string]any{"status": "error", "error": "untrusted_supervisor_signature"})
		return
	}
	// This local admission is bounded and one-shot; central PostgreSQL is the
	// independent authority for global duplicate redemption and source revokes.
	admission.mu.Lock()
	defer admission.mu.Unlock()
	for id, p := range admission.pending {
		if p.claims.ExpiresAt <= time.Now().Unix() {
			delete(admission.pending, id)
		}
	}
	for id, exp := range admission.used {
		if exp <= time.Now().Unix() {
			delete(admission.used, id)
		}
	}
	if _, exists := admission.pending[claims.GrantID]; exists || admission.used[claims.GrantID] > time.Now().Unix() || len(admission.pending) >= 64 || len(admission.used) >= 128 {
		reply(w, http.StatusConflict, map[string]any{"status": "error", "error": "supervisor_admission_already_used"})
		return
	}
	admission.pending[claims.GrantID] = nativePendingProof{claims: claims, raw: append([]byte(nil), value...)}
	reply(w, http.StatusOK, map[string]any{"status": "supervisor_proof_provisioned", "execution_enabled": false, "durably_redeemed": false, "independent_target_effect_verified": false})
}

func (s *Server) validSupervisorClaims(c nativeSupervisorProofClaims, now int64) bool {
	return c.Version == 1 && nativeGrantIDRE.MatchString(c.GrantID) && validIdent(c.RequestID, "req-") &&
		validIdent(c.EngagementID, "eng-") && validIdent(c.FlowID, "flow-") &&
		validIdent(c.TaskID, "task-") && validIdent(c.SubtaskID, "subtask-") &&
		validIdent(c.ActionID, "action-") && nativeIdentifierRE.MatchString(c.OwnerID) &&
		c.ServerID == s.ID && nativeIdentifierRE.MatchString(c.WorkerID) &&
		len(c.WorkerID) <= 96 && nativeIdentifierRE.MatchString(c.SupervisorID) && len(c.SupervisorID) <= 96 &&
		nativeHex64.MatchString(c.ContainerID) && c.Epoch > 0 && c.Revision == 1 &&
		validIdent(c.ApprovalID, "apr-") && validIdent(c.LeaseID, "lease-") &&
		nativeHex64.MatchString(c.AuthorizationSHA256) && nativeHex64.MatchString(c.ClaimsSHA256) &&
		nativeHex64.MatchString(c.ResourceSHA256) && nativeHex32.MatchString(c.Nonce) &&
		now-5 <= c.IssuedAt && c.IssuedAt <= now && now < c.ExpiresAt && c.ExpiresAt <= c.IssuedAt+10
}

func (s *Server) consumeSupervisorProof(grant NativeGrantClaims, claimSHA string) ([]byte, bool) {
	admission := s.supervisorAdmission()
	if admission == nil || grant.ResourceSHA256 == nil {
		return nil, false
	}
	admission.mu.Lock()
	defer admission.mu.Unlock()
	p, ok := admission.pending[grant.GrantID]
	if !ok {
		return nil, false
	}
	// Atomic consume occurs BEFORE independent central redemption. Lost ACK is
	// UNKNOWN and cannot automatically retry this particular worker grant.
	delete(admission.pending, grant.GrantID)
	admission.used[grant.GrantID] = p.claims.ExpiresAt
	c := p.claims
	now := time.Now().Unix()
	if !s.validSupervisorClaims(c, now) ||
		c.GrantID != grant.GrantID || c.RequestID != grant.RequestID ||
		c.EngagementID != grant.EngagementID || c.FlowID != grant.FlowID ||
		c.TaskID != grant.TaskID || c.SubtaskID != grant.SubtaskID ||
		c.ActionID != grant.ActionID || c.ServerID != grant.ServerID ||
		c.LeaseID != grant.LeaseID || c.AuthorizationSHA256 != grant.AuthorizationSHA256 ||
		c.ClaimsSHA256 != claimSHA || c.ResourceSHA256 != *grant.ResourceSHA256 ||
		c.ExpiresAt > grant.ExpiresAt {
		return nil, false
	}
	return append([]byte(nil), p.raw...), true
}
