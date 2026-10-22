package sdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mockDurableValidator struct {
	mu        sync.Mutex
	committed map[string]bool
	calls     atomic.Int64
	revoked   atomic.Bool
	reply     func(*http.Request, nativeGrantToken) (int, any)
}

func TestRunNativeTrustRequiresCompleteOwnerManagedConfiguration(t *testing.T) {
	for _, name := range []string{
		"OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON",
		"OSOP_NATIVE_MCP_REDEEM_URL",
		"OSOP_NATIVE_MCP_REDEEM_ROOT_PEM",
		"OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON",
	} {
		t.Setenv(name, "")
	}
	unconfigured := NewServer("recon-mcp")
	if err := unconfigured.configureNativeGrantFromEnvironment(); err != nil || unconfigured.nativeConfig() != nil {
		t.Fatal("default native service must remain disabled")
	}
	t.Setenv("OSOP_NATIVE_MCP_REDEEM_URL", "https://127.0.0.1/native-grants/redeem")
	if err := unconfigured.configureNativeGrantFromEnvironment(); err == nil {
		t.Fatal("partial server trust would enable a native handler")
	}
	f := newGrantFixture(t)
	pub := f.signer.Public().(ed25519.PublicKey)
	keys, _ := json.Marshal(map[string]string{f.keyID: base64.RawURLEncoding.EncodeToString(pub)})
	secrets, _ := json.Marshal(map[string]string{"recon-mcp": strings.Repeat("z", 48)})
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.tlsServer.Certificate().Raw})
	t.Setenv("OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON", string(keys))
	t.Setenv("OSOP_NATIVE_MCP_REDEEM_URL", f.tlsServer.URL+"/native-grants/redeem")
	t.Setenv("OSOP_NATIVE_MCP_REDEEM_ROOT_PEM", string(ca))
	t.Setenv("OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON", string(secrets))
	configured := NewServer("recon-mcp")
	if err := configured.configureNativeGrantFromEnvironment(); err != nil || configured.nativeConfig() == nil {
		t.Fatalf("fully provisioned inert test authority unavailable: %v", err)
	}
	if configured.nativeConfig().serviceSecret != strings.Repeat("z", 48) {
		t.Fatal("native service auth was not bound to server identity")
	}
	foreign := NewServer("security-bridge")
	if err := foreign.configureNativeGrantFromEnvironment(); err == nil {
		t.Fatal("foreign native server inherited another service credential")
	}
}

func (v *mockDurableValidator) serve(w http.ResponseWriter, r *http.Request) {
	v.calls.Add(1)
	if r.Method != http.MethodPost || r.URL.Path != "/native-grants/redeem" ||
		r.Header.Get("Content-Type") != "application/json" ||
		r.Header.Get("Authorization") != "" ||
		r.Header.Get(nativeGrantHeader) != "" {
		http.Error(w, "bad transport", http.StatusBadRequest)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil || len(raw) > 4096 {
		http.Error(w, "invalid", 400)
		return
	}
	var token nativeGrantToken
	if err = json.Unmarshal(raw, &token); err != nil {
		http.Error(w, "invalid", 400)
		return
	}
	if v.reply != nil {
		status, payload := v.reply(r, token)
		w.Header().Set("Content-Type", "application/json")
		if status == http.StatusFound {
			// A relative local redirect proves the SDK rejects ANY redirect.
			// No test is permitted to send traffic to an external host.
			w.Header().Set("Location", "/native-grants/redeem")
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)
		return
	}
	claims, err := CanonicalNativeClaims(token.Claims)
	if err != nil {
		http.Error(w, "invalid", 400)
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	// An independent service, not the signer or native SDK, owns these
	// authoritative current Task/ROE/Flow/lease/tenant facts. The fake
	// validates the tuple before the single-use claim; the real deployment
	// must read an independently maintained durable authority source.
	if v.revoked.Load() || token.Claims.EngagementID != "eng-owner" ||
		token.Claims.FlowID != "flow-a" ||
		token.Claims.TaskID != "task-1" ||
		token.Claims.SubtaskID != "subtask-1" ||
		token.Claims.ActionID != "action-1" ||
		token.Claims.LeaseID != "lease-1" ||
		token.Claims.AuthorizationVersion != 2 ||
		token.Claims.AuthorizationSHA256 != strings.Repeat("a", 64) ||
		token.Claims.ResourceSHA256 != nil {
		http.Error(w, "independent authority denied", 403)
		return
	}
	if v.committed[token.Claims.GrantID] {
		http.Error(w, "already redeemed", 409)
		return
	}
	v.committed[token.Claims.GrantID] = true // atomic global ledger simulation
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"grant_id":         token.Claims.GrantID,
		"request_id":       token.Claims.RequestID,
		"claim_sha256":     canonicalSHA256(claims),
		"durably_redeemed": true,
	})
}

type grantFixture struct {
	server    *Server
	signer    ed25519.PrivateKey
	keyID     string
	validator *mockDurableValidator
	tlsServer *httptest.Server
	calls     atomic.Int64
}

func newGrantFixture(t *testing.T) *grantFixture {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	validator := &mockDurableValidator{committed: map[string]bool{}}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(validator.serve))
	t.Cleanup(tlsServer.Close)
	s := NewServer("recon-mcp")
	s.Register(Tool{
		Name: "scan", SideEffectClass: SideEffectReadOnly, ScopeCheck: true,
		Handler: func(map[string]any) any { return "NATIVE TOOL SHOULD NOT RUN" },
	})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})
	if err := s.ConfigureNativeGrant(NativeGrantConfig{
		TrustedPublicKeys: map[string]ed25519.PublicKey{"trusted-kid": pub},
		RedeemURL:         tlsServer.URL + "/native-grants/redeem", PinnedRootPEM: certPEM,
	}); err != nil {
		t.Fatalf("native trust config rejected: %v", err)
	}
	return &grantFixture{
		server: s, signer: private, keyID: "trusted-kid", validator: validator,
		tlsServer: tlsServer,
	}
}

func makeGrantClaims(now int64) NativeGrantClaims {
	return NativeGrantClaims{
		Version: 1, GrantID: "ngr-" + strings.Repeat("1", 32),
		RequestID: "req-1234", EngagementID: "eng-owner", FlowID: "flow-a",
		TaskID: "task-1", SubtaskID: "subtask-1", ActionID: "action-1",
		ServerID: "recon-mcp", ToolName: NativeAuthorityStatusTool,
		ParametersSHA256:     AuthorityStatusParametersSHA256(),
		ManifestSHA256:       AuthorityStatusManifestSHA256(),
		AuthorizationVersion: 2, AuthorizationSHA256: strings.Repeat("a", 64),
		LeaseID: "lease-1", ResourceSHA256: nil,
		IssuedAt: now - 1, ExpiresAt: now + 40, SideEffectClass: SideEffectReadOnly,
	}
}

func (f *grantFixture) sign(t *testing.T, c NativeGrantClaims) string {
	t.Helper()
	canon, err := CanonicalNativeClaims(c)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(f.signer, append([]byte(nativeGrantDomain), canon...))
	envelope, _ := json.Marshal(nativeGrantToken{
		Claims: c, Kid: f.keyID, Signature: base64.RawURLEncoding.EncodeToString(sig),
	})
	return base64.RawURLEncoding.EncodeToString(envelope)
}

func sendGrant(s *Server, header, requestID string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"tool_name":"authority_status","parameters":{},"request_id":%q}`, requestID)
	return request(s.Handler(), http.MethodPost, "/mcp/execute", body,
		map[string]string{nativeGrantHeader: header, "Content-Type": "application/json"})
}

func testDeny(t *testing.T, reply *httptest.ResponseRecorder) {
	t.Helper()
	if reply.Code != http.StatusServiceUnavailable {
		t.Fatalf("must fail closed HTTP503, got %d body %s", reply.Code, reply.Body.String())
	}
	output := decoded(t, reply)
	if output["error"] != "native_execution_not_authorized" || output["status"] != "error" {
		t.Fatalf("native action misreported as executed: %#v", output)
	}
	for _, private := range []string{"eng-owner", "action-1", "token", "invalid signature", "trusted-kid", "scope"} {
		if strings.Contains(reply.Body.String(), private) {
			t.Fatalf("untrusted evidence leaked: %s", private)
		}
	}
}

func TestBuiltinAuthorityStatusNeedsSignedAndDurablyRedeemedGrant(t *testing.T) {
	fixture := newGrantFixture(t)
	c := makeGrantClaims(time.Now().Unix())
	token := fixture.sign(t, c)
	good := sendGrant(fixture.server, token, c.RequestID)
	if good.Code != 200 {
		t.Fatalf("first atomic redemption denied %d: %s", good.Code, good.Body)
	}
	out := decoded(t, good)
	if out["request_id"] != c.RequestID || out["status"] != "success" {
		t.Fatalf("native result malformed: %#v", out)
	}
	result, ok := out["result"].(map[string]any)
	if !ok || result["status"] != "grant_durably_redeemed" ||
		result["tool_name"] != NativeAuthorityStatusTool ||
		result["native_target_execution_enabled"] != false ||
		result["target_contacted"] != false || result["provider_contacted"] != false {
		t.Fatalf("inert-only result not explicit: %#v", out)
	}
	if fixture.validator.calls.Load() != 1 {
		t.Fatalf("expected exactly one atomic durable attempt")
	}
	testDeny(t, sendGrant(fixture.server, token, c.RequestID))
	if fixture.validator.calls.Load() != 2 || len(fixture.validator.committed) != 1 {
		t.Fatalf("replay admitted or bypassed durable validator")
	}
}

func TestDefaultNoNativeConfigStillBlocksBuiltin(t *testing.T) {
	s := NewServer("recon-mcp")
	testDeny(t, sendGrant(s, "invalid", "req-1234"))
	health := request(s.Handler(), http.MethodGet, "/health", "", nil)
	if health.Code != 503 || decoded(t, health)["execution_enabled"] != false {
		t.Fatal("legacy provider claims ready")
	}
}

func TestManifestAndParameterShaUsePythonASCIICompactSortedRepresentation(t *testing.T) {
	// Independently computed by live Python 0027 FlowMCPActionStore using
	// MCPToolDefinition.model_dump(mode="json") for the pinned built-in.
	if AuthorityStatusManifestSHA256ForServer("recon-mcp") != "af5f099b32bbb520822f118dceddadb2e4359d5de125e26d9828bc3309672ad1" {
		t.Fatal("Go native manifest differs from original Python 0027 declaration")
	}
	if AuthorityStatusManifestSHA256ForServer("security-bridge") != "5de3e86d5a7e75f395c263d5d657d2feae50822815333dd903cd98fa572245fb" {
		t.Fatal("Go native manifest did not bind distinct MCP server identity")
	}
	c := makeGrantClaims(1761000000)
	// Independent, manually sorted canonical Python object key order.
	expected := `{"action_id":"action-1","authorization_sha256":"` + strings.Repeat("a", 64) + `","authorization_version":2,"engagement_id":"eng-owner","expires_at":1761000040,"flow_id":"flow-a","grant_id":"ngr-` + strings.Repeat("1", 32) + `","issued_at":1760999999,"lease_id":"lease-1","manifest_sha256":"` + AuthorityStatusManifestSHA256() + `","parameters_sha256":"` + AuthorityStatusParametersSHA256() + `","request_id":"req-1234","resource_sha256":null,"server_id":"recon-mcp","side_effect_class":"READ_ONLY","subtask_id":"subtask-1","task_id":"task-1","tool_name":"authority_status","version":1}`
	canonical, _ := CanonicalNativeClaims(c)
	if string(canonical) != expected {
		t.Fatalf("Python canonicalization mismatch: %s != %s", canonical, expected)
	}
	if AuthorityStatusParametersSHA256() != "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" {
		t.Fatal("expected SHA256 canonical {}")
	}
	// Independent fixture in Python sorted-key order, not Go Tool struct order.
	pythonManifest := fmt.Sprintf(
		`{"declaration":{"description":%q,"name":"authority_status","parameters":[],"required_permissions":[],"requires_approval":true,"returns":{"status":"string"},"scope_check":true,"side_effect_class":"READ_ONLY","timeout_seconds":5,"version":"1.0.0"},"server_id":"recon-mcp"}`,
		authorityStatusTool().Description,
	)
	digest := sha256.Sum256([]byte(pythonManifest))
	if AuthorityStatusManifestSHA256() != hex.EncodeToString(digest[:]) {
		t.Fatal("manifest digest not bound to builtin")
	}
}

func TestValidSignatureButStaleCrossIdentityAndMissingScopeIsRejectedBeforeRedeem(t *testing.T) {
	base := makeGrantClaims(time.Now().Unix())
	cases := map[string]func(*NativeGrantClaims){
		"wrong tenant":          func(c *NativeGrantClaims) { c.EngagementID = "outside" },
		"empty Flow":            func(c *NativeGrantClaims) { c.FlowID = "" },
		"wrong action":          func(c *NativeGrantClaims) { c.ActionID = "x-action" },
		"wrong task":            func(c *NativeGrantClaims) { c.TaskID = "task-" },
		"wrong subtask":         func(c *NativeGrantClaims) { c.SubtaskID = "subtask-" },
		"wrong server":          func(c *NativeGrantClaims) { c.ServerID = "another-mcp" },
		"wrong request":         func(c *NativeGrantClaims) { c.RequestID = "req-another" },
		"wrong tool":            func(c *NativeGrantClaims) { c.ToolName = "scan" },
		"wrong effect":          func(c *NativeGrantClaims) { c.SideEffectClass = SideEffectReconActive },
		"wrong params hash":     func(c *NativeGrantClaims) { c.ParametersSHA256 = strings.Repeat("b", 64) },
		"wrong manifest":        func(c *NativeGrantClaims) { c.ManifestSHA256 = strings.Repeat("b", 64) },
		"zero auth version":     func(c *NativeGrantClaims) { c.AuthorizationVersion = 0 },
		"wrong ROE hash":        func(c *NativeGrantClaims) { c.AuthorizationSHA256 = "wrong" },
		"missing lease":         func(c *NativeGrantClaims) { c.LeaseID = "" },
		"bad resource SHA":      func(c *NativeGrantClaims) { s := "short"; c.ResourceSHA256 = &s },
		"expired":               func(c *NativeGrantClaims) { c.IssuedAt -= 65; c.ExpiresAt = c.IssuedAt + 55 },
		"not yet issued":        func(c *NativeGrantClaims) { c.IssuedAt += 20; c.ExpiresAt += 20 },
		"too long validity":     func(c *NativeGrantClaims) { c.ExpiresAt = c.IssuedAt + 61 },
		"already at expiration": func(c *NativeGrantClaims) { c.ExpiresAt = time.Now().Unix() },
		"invalid nonce":         func(c *NativeGrantClaims) { c.GrantID = "ngr-nothex" },
		"wrong version":         func(c *NativeGrantClaims) { c.Version = 2 },
	}
	for name, mutation := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newGrantFixture(t)
			c := base
			mutation(&c)
			testDeny(t, sendGrant(fixture.server, fixture.sign(t, c), base.RequestID))
			if fixture.validator.calls.Load() != 0 {
				t.Fatal("invalid grant crossed network redemption boundary")
			}
		})
	}
}

func TestForgedSignatureUnknownKidWrongDomainAndMutatedClaimsNeverRedeem(t *testing.T) {
	fixture := newGrantFixture(t)
	c := makeGrantClaims(time.Now().Unix())
	genuine := fixture.sign(t, c)
	raw, _ := base64.RawURLEncoding.DecodeString(genuine)
	var token nativeGrantToken
	_ = json.Unmarshal(raw, &token)
	cases := map[string]func(*nativeGrantToken){
		"unknown kid":            func(t *nativeGrantToken) { t.Kid = "unknown-kid" },
		"signature forged":       func(t *nativeGrantToken) { t.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64)) },
		"mutation after signing": func(t *nativeGrantToken) { t.Claims.EngagementID = "eng-foreign" },
		"wrong base64":           func(t *nativeGrantToken) { t.Signature = "abc===" },
	}
	for name, mutation := range cases {
		t.Run(name, func(t *testing.T) {
			cloned := token
			mutation(&cloned)
			body, _ := json.Marshal(cloned)
			testDeny(t, sendGrant(fixture.server, base64.RawURLEncoding.EncodeToString(body), c.RequestID))
		})
	}
	signedClaims, _ := CanonicalNativeClaims(c)
	token.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(fixture.signer, append([]byte("WRONG-DOMAIN\x00"), signedClaims...)))
	body, _ := json.Marshal(token)
	testDeny(t, sendGrant(fixture.server, base64.RawURLEncoding.EncodeToString(body), c.RequestID))
	if fixture.validator.calls.Load() != 0 {
		t.Fatal("forged signatures contacted central validator")
	}
}

func TestDuplicateAndUnknownJSONFieldsAndMalformedAuthorityRequestsDenied(t *testing.T) {
	f := newGrantFixture(t)
	c := makeGrantClaims(time.Now().Unix())
	good := f.sign(t, c)
	raw, _ := base64.RawURLEncoding.DecodeString(good)
	tokenVariants := [][]byte{
		bytes.Replace(raw, []byte(`"kid":`), []byte(`"kid":"duplicate","kid":`), 1),
		bytes.Replace(raw, []byte(`"grant_id":`), []byte(`"grant_id":"ngr-`+strings.Repeat("0", 32)+`","grant_id":`), 1),
		bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"hidden":"secret"`), 1),
		[]byte("not JSON"), []byte("{}"),
	}
	for _, bad := range tokenVariants {
		testDeny(t, sendGrant(f.server, base64.RawURLEncoding.EncodeToString(bad), c.RequestID))
	}
	bodys := []string{
		`{"tool_name":"scan","parameters":{},"request_id":"req-1234"}`,
		`{"tool_name":"authority_status","parameters":{"target":"example.test"},"request_id":"req-1234"}`,
		`{"tool_name":"authority_status","parameters":null,"request_id":"req-1234"}`,
		`{"tool_name":"authority_status","parameters":{},"request_id":"req-1234","extra":true}`,
		`{"tool_name":"authority_status","tool_name":"authority_status","parameters":{},"request_id":"req-1234"}`,
		strings.Repeat("a", maxExecuteBody+1),
	}
	for _, body := range bodys {
		testDeny(t, request(f.server.Handler(), http.MethodPost, "/mcp/execute", body,
			map[string]string{nativeGrantHeader: good}))
	}
	if f.validator.calls.Load() != 0 {
		t.Fatalf("invalid token/body attempted durable redemption")
	}
}

func TestAllRegisteredToolsBlockedEvenWithValidAuthorityStatusGrant(t *testing.T) {
	f := newGrantFixture(t)
	c := makeGrantClaims(time.Now().Unix())
	valid := f.sign(t, c)
	blocked := []string{"scan", "sqlmap", "nmap", "generate_payload", "cve_lookup", "shodan_lookup",
		"web_search", "read_only", "mutate_payload", "execute"}
	for _, tool := range blocked {
		body := fmt.Sprintf(`{"tool_name":%q,"parameters":{},"request_id":%q}`, tool, c.RequestID)
		testDeny(t, request(f.server.Handler(), http.MethodPost, "/mcp/execute", body,
			map[string]string{nativeGrantHeader: valid, "Content-Type": "application/json"}))
	}
	if f.validator.calls.Load() != 0 {
		t.Fatal("registered handler ever able to redeem signed builtin grant")
	}
}

func TestSingleUseGrantParallelAttemptAtMostOneSuccess(t *testing.T) {
	f := newGrantFixture(t)
	c := makeGrantClaims(time.Now().Unix())
	token := f.sign(t, c)
	const parallel = 64
	var successes atomic.Int64
	var failures atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := sendGrant(f.server, token, c.RequestID)
			if res.Code == 200 {
				successes.Add(1)
			} else if res.Code == 503 {
				failures.Add(1)
			} else {
				failures.Add(1000)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || failures.Load() != parallel-1 {
		t.Fatalf("atomic redemption violated: success=%d denied=%d", successes.Load(), failures.Load())
	}
	f.validator.mu.Lock()
	recorded := len(f.validator.committed)
	f.validator.mu.Unlock()
	if recorded != 1 {
		t.Fatal("redemption was not atomic")
	}
}

func TestIndependentValidatorMustBindAllReceiptIdentityFields(t *testing.T) {
	tests := map[string]func(nativeGrantToken) (int, any){
		"wrong grant_id": func(token nativeGrantToken) (int, any) {
			return 200, map[string]any{
				"grant_id": "ngr-" + strings.Repeat("b", 32), "request_id": token.Claims.RequestID,
				"claim_sha256": strings.Repeat("b", 64), "durably_redeemed": true}
		},
		"wrong request_id": func(token nativeGrantToken) (int, any) {
			return 200, map[string]any{
				"grant_id": token.Claims.GrantID, "request_id": "req-other",
				"claim_sha256": strings.Repeat("b", 64), "durably_redeemed": true}
		},
		"wrong claim digest": func(token nativeGrantToken) (int, any) {
			return 200, map[string]any{
				"grant_id": token.Claims.GrantID, "request_id": token.Claims.RequestID,
				"claim_sha256": strings.Repeat("b", 64), "durably_redeemed": true}
		},
		"not durable": func(token nativeGrantToken) (int, any) {
			canon, _ := CanonicalNativeClaims(token.Claims)
			return 200, map[string]any{
				"grant_id": token.Claims.GrantID, "request_id": token.Claims.RequestID,
				"claim_sha256": canonicalSHA256(canon), "durably_redeemed": false}
		},
		"injected extra": func(token nativeGrantToken) (int, any) {
			canon, _ := CanonicalNativeClaims(token.Claims)
			return 200, map[string]any{
				"grant_id": token.Claims.GrantID, "request_id": token.Claims.RequestID,
				"claim_sha256": canonicalSHA256(canon), "durably_redeemed": true, "fake": "true"}
		},
		"validator denied":      func(token nativeGrantToken) (int, any) { return 409, map[string]any{"status": "revoked"} },
		"validator unavailable": func(token nativeGrantToken) (int, any) { return 503, map[string]any{"status": "unknown"} },
	}
	for name, answer := range tests {
		t.Run(name, func(t *testing.T) {
			f := newGrantFixture(t)
			f.validator.reply = func(_ *http.Request, token nativeGrantToken) (int, any) { return answer(token) }
			c := makeGrantClaims(time.Now().Unix())
			testDeny(t, sendGrant(f.server, f.sign(t, c), c.RequestID))
			if f.validator.calls.Load() != 1 {
				t.Fatal("unexpected redemption count")
			}
		})
	}
}

func TestValidatorTLSRequiresExplicitPinnedRootAndNeverFollowsRedirect(t *testing.T) {
	f := newGrantFixture(t)
	c := makeGrantClaims(time.Now().Unix())
	realToken := f.sign(t, c)
	f.server.mu.Lock()
	original := f.server.native
	f.server.mu.Unlock()
	insecure := NewServer("recon-mcp")
	// A different self-signed TLS server cannot impersonate the pinned root.
	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(20261020),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, priv2.Public(), priv2)
	if err != nil {
		t.Fatal(err)
	}
	other := httptest.NewUnstartedServer(http.HandlerFunc(f.validator.serve))
	other.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv2}}}
	other.StartTLS()
	defer other.Close()
	incorrect := *original
	incorrect.redeemURL = other.URL + "/native-grants/redeem"
	insecure.native = &incorrect
	testDeny(t, sendGrant(insecure, realToken, c.RequestID))
	if f.validator.calls.Load() != 0 {
		t.Fatal("unpinned validator was reached")
	}
	// Real pinned server issues a cross-origin redirect; do not follow.
	f.validator.reply = func(w *http.Request, token nativeGrantToken) (int, any) {
		return 302, map[string]any{"status": "redirected"}
	}
	testDeny(t, sendGrant(f.server, realToken, c.RequestID))
	if f.validator.calls.Load() != 1 {
		t.Fatal("unexpected redirect attempts")
	}
}

func TestCancelledRequestNeverReturnsSuccessOrRetries(t *testing.T) {
	f := newGrantFixture(t)
	c := makeGrantClaims(time.Now().Unix())
	token := f.sign(t, c)
	body := fmt.Sprintf(`{"tool_name":"authority_status","parameters":{},"request_id":%q}`, c.RequestID)
	req := httptest.NewRequest(http.MethodPost, "/mcp/execute", strings.NewReader(body))
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)
	req.Header.Set(nativeGrantHeader, token)
	req.Header.Set("Content-Type", "application/json")
	result := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(result, req)
	testDeny(t, result)
}

func TestConfigCannotUseUntrustedRootOrHTTPOrCrossHostURL(t *testing.T) {
	f := newGrantFixture(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.tlsServer.Certificate().Raw})
	config := NativeGrantConfig{
		TrustedPublicKeys: map[string]ed25519.PublicKey{"root-key": pub},
		RedeemURL:         f.tlsServer.URL + "/native-grants/redeem",
		PinnedRootPEM:     root,
	}
	for _, mutate := range []func(*NativeGrantConfig){
		func(c *NativeGrantConfig) { c.RedeemURL = "http://localhost/native-grants/redeem" },
		func(c *NativeGrantConfig) { c.RedeemURL = f.tlsServer.URL + "/not-the-authority" },
		func(c *NativeGrantConfig) { c.RedeemURL = f.tlsServer.URL + "/native-grants/redeem?token=x" },
		func(c *NativeGrantConfig) { c.RedeemURL = "https://user:pass@example.test/native-grants/redeem" },
		func(c *NativeGrantConfig) { c.PinnedRootPEM = []byte("insecure") },
		func(c *NativeGrantConfig) { c.TrustedPublicKeys = map[string]ed25519.PublicKey{"bad": {}} },
	} {
		c := config
		mutate(&c)
		s := NewServer("recon-mcp")
		if err := s.ConfigureNativeGrant(c); err == nil {
			t.Fatal("unsafe native grant root or redemption location was accepted")
		}
		testDeny(t, sendGrant(s, "invalid", "req-1234"))
	}
}

func TestConfiguredCatalogNegotiatesInertBuiltinWithoutAuthorizingScanners(t *testing.T) {
	f := newGrantFixture(t)
	health := request(f.server.Handler(), http.MethodGet, "/health", "", nil)
	if health.Code != 200 || decoded(t, health)["status"] != "configured_unverified" ||
		decoded(t, health)["execution_enabled"] != false {
		t.Fatal("configured trust did not disclose inert-only unverified handshake")
	}
	init := request(f.server.Handler(), http.MethodPost, "/mcp/initialize", `{"scope":{},"auth_credentials":{},"session_id":"signed-native-catalog","metadata":{}}`,
		map[string]string{"Content-Type": "application/json"})
	if init.Code != 200 {
		t.Fatalf("unready metadata initialization failed: %d", init.Code)
	}
	data := decoded(t, init)
	if data["status"] != "ready" || data["execution_enabled"] != false ||
		data["native_scanners_enabled"] != false || data["authority_verified"] != false {
		t.Fatal("configuration claimed target execution readiness")
	}
	tools := data["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("only independently fenced inert builtin may be negotiated: %#v", tools)
	}
	for _, raw := range tools {
		tool := raw.(map[string]any)
		if tool["name"] == NativeAuthorityStatusTool {
			if tool["side_effect_class"] != SideEffectReadOnly || tool["requires_approval"] != true ||
				tool["scope_check"] != true || len(tool["parameters"].([]any)) != 0 {
				t.Fatal("native builtin schema cannot be trusted")
			}
		} else {
			t.Fatal("legacy tool leaked into native grant negotiation")
		}
	}
}

func TestNativeGrantSignatureCannotBeRedeemedWithAnotherServerKey(t *testing.T) {
	fixture := newGrantFixture(t)
	c := makeGrantClaims(time.Now().Unix())
	token := fixture.sign(t, c)
	// Another SDK service lacks the configured trust; cannot co-opt grant.
	other := NewServer("security-bridge")
	testDeny(t, sendGrant(other, token, c.RequestID))
	other.native = fixture.server.native // even an accidentally shared key is insufficient
	testDeny(t, sendGrant(other, token, c.RequestID))
	if fixture.validator.calls.Load() != 0 {
		t.Fatal("cross-server grant reached durable verifier")
	}
}

func TestNativeGrantRejectsMalformedAndDuplicatedHeaderInstances(t *testing.T) {
	f := newGrantFixture(t)
	c := makeGrantClaims(time.Now().Unix())
	token := f.sign(t, c)
	badHeaders := []string{
		token + "=", token + " ", strings.Repeat("X", maxGrantHeader+1), "not_base64!",
	}
	for _, header := range badHeaders {
		testDeny(t, sendGrant(f.server, header, c.RequestID))
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp/execute", strings.NewReader(
		`{"tool_name":"authority_status","parameters":{},"request_id":"req-1234"}`))
	req.Header.Add(nativeGrantHeader, token)
	req.Header.Add(nativeGrantHeader, token)
	req.Header.Set("Content-Type", "application/json")
	result := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(result, req)
	testDeny(t, result)
	if f.validator.calls.Load() != 0 {
		t.Fatal("duplicate header was accepted")
	}
}

func TestIndependentlyOperatedValidatorDeniesSignedButWrongTenantAndStaleLease(t *testing.T) {
	for name, mutate := range map[string]func(*NativeGrantClaims){
		"cross-tenant signed":  func(c *NativeGrantClaims) { c.EngagementID = "eng-foreign" },
		"cross-Flow signed":    func(c *NativeGrantClaims) { c.FlowID = "flow-foreign" },
		"cross-Task signed":    func(c *NativeGrantClaims) { c.TaskID = "task-other" },
		"cross-subtask signed": func(c *NativeGrantClaims) { c.SubtaskID = "subtask-other" },
		"cross-action signed":  func(c *NativeGrantClaims) { c.ActionID = "action-other" },
		"stale lease":          func(c *NativeGrantClaims) { c.LeaseID = "lease-stale" },
		"stale signed ROE":     func(c *NativeGrantClaims) { c.AuthorizationVersion = 1 },
		"changed signed ROE":   func(c *NativeGrantClaims) { c.AuthorizationSHA256 = strings.Repeat("b", 64) },
		"unbound resource":     func(c *NativeGrantClaims) { value := strings.Repeat("c", 64); c.ResourceSHA256 = &value },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newGrantFixture(t)
			claims := makeGrantClaims(time.Now().Unix())
			mutate(&claims)
			testDeny(t, sendGrant(fixture.server, fixture.sign(t, claims), claims.RequestID))
			expectedCalls := int64(1)
			if name == "unbound resource" {
				// Resource-bound grants now need independent 0033 supervisor
				// provisioning before they may contact central redemption.
				expectedCalls = 0
			}
			if fixture.validator.calls.Load() != expectedCalls {
				t.Fatal("native stale grant or unbound supervisor bypassed authority")
			}
			if len(fixture.validator.committed) != 0 {
				t.Fatal("validator consumed grant with stale or cross-identity authorization")
			}
		})
	}
}

func TestDurableValidatorRejectsRevokedOrCancelledActionGrant(t *testing.T) {
	f := newGrantFixture(t)
	f.validator.revoked.Store(true)
	claims := makeGrantClaims(time.Now().Unix())
	testDeny(t, sendGrant(f.server, f.sign(t, claims), claims.RequestID))
	if f.validator.calls.Load() != 1 || len(f.validator.committed) != 0 {
		t.Fatal("revoked task consumed remote grant")
	}
}

func TestNativeBuiltinCannotBeShadowedByRegisteredArbitraryHandler(t *testing.T) {
	f := newGrantFixture(t)
	var ran atomic.Int64
	f.server.Register(Tool{
		Name:            NativeAuthorityStatusTool,
		SideEffectClass: SideEffectReadOnly,
		Handler: func(map[string]any) any {
			ran.Add(1)
			return map[string]any{"target_scanned": true}
		},
	})
	if _, exists := f.server.Tools[NativeAuthorityStatusTool]; exists {
		t.Fatal("cmd native handler shadowed protected SDK builtin")
	}
	claims := makeGrantClaims(time.Now().Unix())
	response := sendGrant(f.server, f.sign(t, claims), claims.RequestID)
	if response.Code != http.StatusOK || ran.Load() != 0 {
		t.Fatalf("builtin shadowing executed handler: %d/%d", response.Code, ran.Load())
	}
}

func TestAuthorityStatusNeedsJSONContentTypeEvenWithCorrectSignedGrant(t *testing.T) {
	f := newGrantFixture(t)
	claims := makeGrantClaims(time.Now().Unix())
	token := f.sign(t, claims)
	body := `{"tool_name":"authority_status","parameters":{},"request_id":"req-1234"}`
	for _, contentType := range []string{"", "text/plain", "application/x-www-form-urlencoded"} {
		testDeny(t, request(f.server.Handler(), http.MethodPost,
			"/mcp/execute", body, map[string]string{
				nativeGrantHeader: token, "Content-Type": contentType,
			}))
	}
	if f.validator.calls.Load() != 0 {
		t.Fatal("invalid content type reached trusted validator")
	}
}
