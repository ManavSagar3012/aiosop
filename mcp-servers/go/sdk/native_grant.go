package sdk

// Signed native grants can authorize ONLY the built-in inert authority_status
// handler, never a cmd-registered Tool.Handler. Config and trust roots are
// provisioned by the server owner, not by HTTP callers or a gateway token.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	nativeGrantDomain         = "ai-osop/native-grant/v1\x00"
	NativeAuthorityStatusTool = "authority_status"
	nativeGrantHeader         = "X-OSOP-Native-Grant"
	maxGrantHeader            = 8192
	maxExecuteBody            = 2048
	maxRedeemBody             = 2048
)

var (
	nativeGrantIDRE    = regexp.MustCompile("^ngr-[0-9a-f]{32}$")
	nativeSHARE        = regexp.MustCompile("^[0-9a-f]{64}$")
	nativeIdentifierRE = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$")
	nativeKidRE        = regexp.MustCompile("^[A-Za-z0-9_-]{1,64}$")
)

// NativeGrantConfig must come from separately trusted *server-side* code.
// No environment key auto-enables legacy Go cmd binaries and neither an API
// bearer nor client-supplied URL can configure this authority.
type NativeGrantConfig struct {
	TrustedPublicKeys map[string]ed25519.PublicKey
	RedeemURL         string
	PinnedRootPEM     []byte
	// Independently provisioned per-server credential checked by the PG
	// redemption service in addition to the Ed25519 claim and signed Task.
	RedeemServiceSecret string
}

// configureNativeGrantFromEnvironment is invoked by Server.Run, not by any
// HTTP request. All trust materials must be provisioned together by the
// operator; a missing part never enables an unreviewed native tool.
func (s *Server) configureNativeGrantFromEnvironment() error {
	const publicEnv = "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON"
	const redeemEnv = "OSOP_NATIVE_MCP_REDEEM_URL"
	const rootEnv = "OSOP_NATIVE_MCP_REDEEM_ROOT_PEM"
	const secretsEnv = "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON"
	inputs := []string{os.Getenv(publicEnv), os.Getenv(redeemEnv), os.Getenv(rootEnv), os.Getenv(secretsEnv)}
	count := 0
	for _, input := range inputs {
		if input != "" {
			count++
		}
	}
	if count == 0 {
		return nil
	} // explicit metadata-only legacy mode
	if count != len(inputs) {
		return errors.New("complete independent native MCP trust configuration required")
	}
	if len(inputs[0]) > 8192 || len(inputs[1]) > 2048 || len(inputs[2]) > 65536 || len(inputs[3]) > 16384 {
		return errors.New("native MCP trust configuration exceeds bounds")
	}
	var encodedKeys map[string]string
	var secrets map[string]string
	if err := json.Unmarshal([]byte(inputs[0]), &encodedKeys); err != nil {
		return errors.New("native MCP public trust registry invalid")
	}
	if err := json.Unmarshal([]byte(inputs[3]), &secrets); err != nil {
		return errors.New("native MCP service trust registry invalid")
	}
	// A native worker must not be provisioned with OTHER servers' bearer
	// credentials. The central verifier may hold many, but an individual
	// Go server process receives exactly its own server-id key.
	if len(encodedKeys) == 0 || len(encodedKeys) > 16 || len(secrets) != 1 {
		return errors.New("native MCP trust registry unavailable")
	}
	keys := make(map[string]ed25519.PublicKey, len(encodedKeys))
	for kid, encoded := range encodedKeys {
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(decoded) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
			return errors.New("native MCP public issuer key invalid")
		}
		keys[kid] = ed25519.PublicKey(decoded)
	}
	secret, ok := secrets[s.ID]
	if !ok || secret == "" {
		return errors.New("native MCP service identity not explicitly configured")
	}
	return s.ConfigureNativeGrant(NativeGrantConfig{
		TrustedPublicKeys:   keys,
		RedeemURL:           inputs[1],
		PinnedRootPEM:       []byte(inputs[2]),
		RedeemServiceSecret: secret,
	})
}

type nativeAuthority struct {
	keys          map[string]ed25519.PublicKey
	redeemURL     string
	client        *http.Client
	serviceSecret string
}

// NativeGrantClaims are the EXACT signed fields (no arbitrary extensions).
// resource_sha256 is required on the wire, with null or lowercase SHA-256.
type NativeGrantClaims struct {
	Version              int64   `json:"version"`
	GrantID              string  `json:"grant_id"`
	RequestID            string  `json:"request_id"`
	EngagementID         string  `json:"engagement_id"`
	FlowID               string  `json:"flow_id"`
	TaskID               string  `json:"task_id"`
	SubtaskID            string  `json:"subtask_id"`
	ActionID             string  `json:"action_id"`
	ServerID             string  `json:"server_id"`
	ToolName             string  `json:"tool_name"`
	ParametersSHA256     string  `json:"parameters_sha256"`
	ManifestSHA256       string  `json:"manifest_sha256"`
	AuthorizationVersion int64   `json:"authorization_version"`
	AuthorizationSHA256  string  `json:"authorization_sha256"`
	LeaseID              string  `json:"lease_id"`
	ResourceSHA256       *string `json:"resource_sha256"`
	IssuedAt             int64   `json:"issued_at"`
	ExpiresAt            int64   `json:"expires_at"`
	SideEffectClass      string  `json:"side_effect_class"`
}

type nativeGrantToken struct {
	Claims    NativeGrantClaims `json:"claims"`
	Kid       string            `json:"kid"`
	Signature string            `json:"signature"`
}

var nativeClaimKeys = map[string]bool{
	"version": true, "grant_id": true, "request_id": true,
	"engagement_id": true, "flow_id": true, "task_id": true,
	"subtask_id": true, "action_id": true, "server_id": true,
	"tool_name": true, "parameters_sha256": true, "manifest_sha256": true,
	"authorization_version": true, "authorization_sha256": true,
	"lease_id": true, "resource_sha256": true, "issued_at": true,
	"expires_at": true, "side_effect_class": true,
}

// decodeExactObject rejects unknown, missing, and duplicate keys. It decodes
// one bounded object and rejects trailing data, including after a valid token.
func decodeExactObject(raw []byte, keys map[string]bool) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("invalid object")
	}
	result := make(map[string]json.RawMessage, len(keys))
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, errors.New("invalid field")
		}
		key, ok := keyToken.(string)
		if !ok || !keys[key] {
			return nil, errors.New("unknown field")
		}
		if _, seen := result[key]; seen {
			return nil, errors.New("duplicate field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("invalid value")
		}
		result[key] = value
	}
	ending, err := decoder.Token()
	if err != nil || ending != json.Delim('}') || len(result) != len(keys) {
		return nil, errors.New("missing or invalid fields")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing content")
	}
	return result, nil
}

func decodeNativeGrant(header string) (nativeGrantToken, error) {
	var token nativeGrantToken
	if len(header) == 0 || len(header) > maxGrantHeader || strings.ContainsAny(header, " \t\r\n=") {
		return token, errors.New("invalid native grant envelope")
	}
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil || len(raw) > maxGrantHeader {
		return token, errors.New("invalid native grant encoding")
	}
	envelope, err := decodeExactObject(raw, map[string]bool{"claims": true, "kid": true, "signature": true})
	if err != nil {
		return token, err
	}
	if _, err = decodeExactObject(envelope["claims"], nativeClaimKeys); err != nil {
		return token, err
	}
	if err = json.Unmarshal(raw, &token); err != nil {
		return token, errors.New("invalid native grant claims")
	}
	return token, nil
}

// CanonicalNativeClaims encodes this fixed, flat claims schema exactly as
// Python json.dumps(...,sort_keys=True,separators=(',',':'),ensure_ascii=True).
// All signed strings are strictly printable ASCII identifiers or lowercase
// hex digests (no non-ASCII/HTML/control escapes), and Go's encoding/json
// sorts map keys with the same compact JSON encoding for this bounded subset.
func CanonicalNativeClaims(claims NativeGrantClaims) ([]byte, error) {
	values := map[string]any{
		"version": claims.Version, "grant_id": claims.GrantID,
		"request_id": claims.RequestID, "engagement_id": claims.EngagementID,
		"flow_id": claims.FlowID, "task_id": claims.TaskID,
		"subtask_id": claims.SubtaskID, "action_id": claims.ActionID,
		"server_id": claims.ServerID, "tool_name": claims.ToolName,
		"parameters_sha256": claims.ParametersSHA256, "manifest_sha256": claims.ManifestSHA256,
		"authorization_version": claims.AuthorizationVersion,
		"authorization_sha256":  claims.AuthorizationSHA256,
		"lease_id":              claims.LeaseID, "resource_sha256": claims.ResourceSHA256,
		"issued_at": claims.IssuedAt, "expires_at": claims.ExpiresAt,
		"side_effect_class": claims.SideEffectClass,
	}
	return json.Marshal(values)
}

func canonicalSHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

// AuthorityStatusParametersSHA256 is the sole admissible native parameter
// digest: SHA256 of Python canonical empty dict "{}".
func AuthorityStatusParametersSHA256() string { return canonicalSHA256([]byte("{}")) }

func authorityStatusTool() Tool {
	return Tool{
		Name:             NativeAuthorityStatusTool,
		Description:      "Inert native authority redemption status; no target, scan or provider execution.",
		Parameters:       []map[string]any{},
		Returns:          map[string]any{"status": "string"},
		TimeoutSeconds:   5,
		RequiresApproval: true, ScopeCheck: true,
		SideEffectClass: SideEffectReadOnly,
	}
}

// AuthorityStatusManifestSHA256ForServer matches Python's original 0027
// FlowMCPActionStore.declaration_sha256 across server identity, including
// every Pydantic MCPToolDefinition default, not the native Go struct shape.
func AuthorityStatusManifestSHA256ForServer(serverID string) string {
	tool := authorityStatusTool()
	metadata, _ := json.Marshal(map[string]any{"server_id": serverID, "declaration": map[string]any{
		"name":                 tool.Name,
		"description":          tool.Description,
		"parameters":           tool.Parameters,
		"returns":              tool.Returns,
		"timeout_seconds":      tool.TimeoutSeconds,
		"requires_approval":    tool.RequiresApproval,
		"scope_check":          tool.ScopeCheck,
		"side_effect_class":    tool.SideEffectClass,
		"version":              "1.0.0",
		"required_permissions": []string{},
	}})
	return canonicalSHA256(metadata)
}

func AuthorityStatusManifestSHA256() string {
	return AuthorityStatusManifestSHA256ForServer("recon-mcp")
}

func validIdent(value, prefix string) bool {
	return nativeIdentifierRE.MatchString(value) && strings.HasPrefix(value, prefix) &&
		len(value) > len(prefix) && len(value) <= 128
}

func validateClaims(c NativeGrantClaims, serverID, requestID string, now time.Time) error {
	if c.Version != 1 || !nativeGrantIDRE.MatchString(c.GrantID) ||
		!validIdent(c.RequestID, "req-") || c.RequestID != requestID ||
		!validIdent(c.EngagementID, "eng-") || !validIdent(c.FlowID, "flow-") ||
		!validIdent(c.TaskID, "task-") || !validIdent(c.SubtaskID, "subtask-") ||
		!validIdent(c.ActionID, "action-") || !validIdent(c.LeaseID, "lease-") ||
		!nativeIdentifierRE.MatchString(c.ServerID) || c.ServerID != serverID ||
		c.ToolName != NativeAuthorityStatusTool || c.SideEffectClass != SideEffectReadOnly ||
		c.AuthorizationVersion < 1 || c.AuthorizationVersion > 2147483647 ||
		!nativeSHARE.MatchString(c.AuthorizationSHA256) ||
		!nativeSHARE.MatchString(c.ParametersSHA256) ||
		c.ParametersSHA256 != AuthorityStatusParametersSHA256() ||
		!nativeSHARE.MatchString(c.ManifestSHA256) ||
		c.ManifestSHA256 != AuthorityStatusManifestSHA256ForServer(serverID) ||
		(c.ResourceSHA256 != nil && !nativeSHARE.MatchString(*c.ResourceSHA256)) {
		return errors.New("native grant identity or SHA mismatch")
	}
	// Epoch-second windows; no future-issued privilege or clock-grace replay.
	epoch := now.Unix()
	if c.IssuedAt > epoch || c.IssuedAt < epoch-60 ||
		c.ExpiresAt <= epoch || c.ExpiresAt < c.IssuedAt ||
		c.ExpiresAt-c.IssuedAt > 60 {
		return errors.New("native grant expired or outside bounded issuance")
	}
	return nil
}

func (s *Server) ConfigureNativeGrant(config NativeGrantConfig) error {
	if len(config.TrustedPublicKeys) == 0 || len(config.TrustedPublicKeys) > 16 ||
		len(config.PinnedRootPEM) == 0 || len(config.PinnedRootPEM) > 65536 ||
		len(config.RedeemURL) == 0 || len(config.RedeemURL) > 2048 {
		return errors.New("native grant authority configuration incomplete")
	}
	uri, err := url.Parse(config.RedeemURL)
	if err != nil || uri.Scheme != "https" || uri.Hostname() == "" ||
		uri.User != nil || uri.RawQuery != "" || uri.ForceQuery || uri.Fragment != "" ||
		uri.Path != "/native-grants/redeem" || uri.RawPath != "" ||
		strings.HasSuffix(uri.Host, ":") || uri.Opaque != "" ||
		strings.ContainsAny(uri.Host, "\\ \t\r\n") {
		return errors.New("invalid pinned native grant redemption endpoint")
	}
	if _, err := strconv.Atoi(uri.Port()); uri.Port() != "" && err != nil {
		return errors.New("invalid native validator port")
	}
	if config.RedeemServiceSecret != "" && (len(config.RedeemServiceSecret) < 20 ||
		len(config.RedeemServiceSecret) > 512 || strings.ContainsAny(config.RedeemServiceSecret, " \t\r\n")) {
		return errors.New("invalid independently provisioned native server credential")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(config.PinnedRootPEM) {
		return errors.New("invalid pinned native validator root")
	}
	trusted := make(map[string]ed25519.PublicKey, len(config.TrustedPublicKeys))
	for kid, pub := range config.TrustedPublicKeys {
		if !nativeKidRE.MatchString(kid) || len(pub) != ed25519.PublicKeySize {
			return errors.New("invalid native grant signing key")
		}
		// The two key sets may be configured in either order by a service
		// embedding this SDK. Never allow a grant issuer to impersonate the
		// separately trusted supervisor by sharing its Ed25519 public key.
		if supervisor := s.supervisorAdmission(); supervisor != nil {
			for _, identity := range supervisor.trusted {
				if bytes.Equal(identity.PublicKey, pub) {
					return errors.New("independent supervisor and grant issuer keys must differ")
				}
			}
		}
		trusted[kid] = append(ed25519.PublicKey(nil), pub...)
	}
	client := &http.Client{
		Timeout:       3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("native validator redirect denied") },
		Transport: &http.Transport{
			Proxy: nil, DisableKeepAlives: true, MaxIdleConns: 0,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		},
	}
	s.mu.Lock()
	s.native = &nativeAuthority{keys: trusted, redeemURL: uri.String(), client: client, serviceSecret: config.RedeemServiceSecret}
	s.mu.Unlock()
	return nil
}

func (s *Server) nativeConfig() *nativeAuthority {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.native
}

func (s *Server) verifyAndRedeemAuthorityStatus(ctx context.Context, body io.Reader, header string) (string, error) {
	config := s.nativeConfig()
	if config == nil {
		return "", errors.New("native validator unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(body, maxExecuteBody+1))
	if err != nil || len(raw) == 0 || len(raw) > maxExecuteBody {
		return "", errors.New("bounded native request required")
	}
	values, err := decodeExactObject(raw, map[string]bool{"tool_name": true, "parameters": true, "request_id": true})
	if err != nil {
		// Production MCPExecuteRequest.model_dump() includes the optional
		// timeout_override:null field. Reject other transport extensions.
		values, err = decodeExactObject(raw, map[string]bool{
			"tool_name": true, "parameters": true, "request_id": true,
			"timeout_override": true,
		})
		if err == nil {
			var timeoutValue any
			if e := json.Unmarshal(values["timeout_override"], &timeoutValue); e != nil || timeoutValue != nil {
				return "", errors.New("native timeout override unavailable")
			}
		}
	}
	if err != nil {
		return "", err
	}
	var toolName, requestID string
	if err = json.Unmarshal(values["tool_name"], &toolName); err != nil || toolName != NativeAuthorityStatusTool {
		return "", errors.New("builtin-only tool required")
	}
	if err = json.Unmarshal(values["request_id"], &requestID); err != nil || !validIdent(requestID, "req-") {
		return "", errors.New("bounded native request id required")
	}
	params, err := decodeExactObject(values["parameters"], map[string]bool{})
	if err != nil || len(params) != 0 {
		return "", errors.New("inert native parameters must be empty")
	}
	token, err := decodeNativeGrant(header)
	if err != nil {
		return "", err
	}
	pub, ok := config.keys[token.Kid]
	if !ok {
		return "", errors.New("unknown native grant kid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(token.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return "", errors.New("invalid native signature")
	}
	claimsBytes, err := CanonicalNativeClaims(token.Claims)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(pub, append([]byte(nativeGrantDomain), claimsBytes...), signature) {
		return "", errors.New("invalid native grant signature")
	}
	if err := validateClaims(token.Claims, s.ID, requestID, time.Now()); err != nil {
		return "", err
	}
	// Send exactly the signed envelope as a JSON object, never raw caller
	// HTTP headers or a bearer. The pinned HTTPS validator is the only
	// trusted authority for CURRENT signed Flow/ROE/Task/lease and atomic
	// cross-instance grant_id replay/revocation. No local nonce cache suffices.
	var outbound []byte
	if token.Claims.ResourceSHA256 != nil {
		// A request-header proof is UNTRUSTED, even if the source signature is
		// genuine: anyone holding it could race the designated worker. Only a
		// one-shot supervisor-provisioned, independently signed in-process proof
		// for the exact signed grant is admissible. PostgreSQL still enforces
		// the global, durable one-use and current 0033 epoch/revision.
		proof, ok := s.consumeSupervisorProof(token.Claims, canonicalSHA256(claimsBytes))
		if !ok {
			return "", errors.New("independently provisioned supervisor proof unavailable")
		}
		outbound, err = json.Marshal(map[string]any{"grant": token, "worker_proof": json.RawMessage(proof)})
	} else {
		outbound, err = json.Marshal(token)
	}
	if err != nil {
		return "", errors.New("invalid native envelope")
	}
	redeemReq, err := http.NewRequestWithContext(ctx, http.MethodPost, config.redeemURL, bytes.NewReader(outbound))
	if err != nil {
		return "", errors.New("native redemption request unavailable")
	}
	redeemReq.Header.Set("Content-Type", "application/json")
	redeemReq.Header.Set("Cache-Control", "no-store")
	redeemReq.Header.Set("X-OSOP-Native-Server-ID", s.ID)
	if config.serviceSecret != "" {
		redeemReq.Header.Set("Authorization", "Bearer "+config.serviceSecret)
	}
	result, err := config.client.Do(redeemReq)
	if err != nil {
		return "", errors.New("native grant redemption UNKNOWN")
	}
	defer result.Body.Close()
	if result.StatusCode != http.StatusOK {
		return "", errors.New("native grant not durably redeemed")
	}
	if ct := strings.ToLower(strings.TrimSpace(strings.Split(result.Header.Get("Content-Type"), ";")[0])); ct != "application/json" {
		return "", errors.New("native redemption content type unavailable")
	}
	evidence, err := io.ReadAll(io.LimitReader(result.Body, maxRedeemBody+1))
	if err != nil || len(evidence) == 0 || len(evidence) > maxRedeemBody {
		return "", errors.New("native redemption result unavailable")
	}
	fields, err := decodeExactObject(evidence, map[string]bool{
		"grant_id": true, "request_id": true, "claim_sha256": true, "durably_redeemed": true,
	})
	if err != nil {
		return "", errors.New("invalid native redemption certificate")
	}
	var redeemed struct {
		GrantID         string `json:"grant_id"`
		RequestID       string `json:"request_id"`
		ClaimSHA256     string `json:"claim_sha256"`
		DurablyRedeemed bool   `json:"durably_redeemed"`
	}
	if err = json.Unmarshal(evidence, &redeemed); err != nil ||
		!redeemed.DurablyRedeemed ||
		redeemed.GrantID != token.Claims.GrantID ||
		redeemed.RequestID != token.Claims.RequestID ||
		redeemed.ClaimSHA256 != canonicalSHA256(claimsBytes) {
		return "", errors.New("native redemption identity mismatch")
	}
	_ = fields
	// A reviewed resource is offered only after a *durable* one-time grant
	// redemption. Its byte offer is itself a separate PostgreSQL one-shot
	// transaction. A lost ACK or failed independent byte verification returns
	// UNKNOWN without any replay or automatic re-fetch.
	if token.Claims.ResourceSHA256 != nil {
		// Redemption intentionally uses the separately provisioned supervisor
		// worker_proof envelope. The *next* resource-offer endpoint independently
		// validates the ORIGINAL signed grant object only, after checking its
		// globally redeemed PostgreSQL row. Never forward the consumed worker
		// supervisor proof to a second service endpoint or confuse its schema.
		resourceGrant, encodeErr := json.Marshal(token)
		if encodeErr != nil {
			return "", errors.New("native resource grant envelope unavailable")
		}
		if err := s.receiveNativeReviewedResource(ctx, config, token, resourceGrant); err != nil {
			// Explicit local-qualification diagnostics only. Never reflect
			// errors, token bytes or resource content to HTTP callers.
			if os.Getenv("OSOP_NATIVE_MCP_LOCAL_TEST_TRACE") == "1" {
				log.Printf("native inert reviewed-resource check failed closed: %v", err)
			}
			return "", errors.New("native reviewed resource receipt UNKNOWN")
		}
	}
	return token.Claims.RequestID, nil
}
