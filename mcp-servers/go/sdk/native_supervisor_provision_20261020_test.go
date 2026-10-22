package sdk

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func makeSignedNativeSupervisorProof(t *testing.T, private ed25519.PrivateKey, c NativeGrantClaims) ([]byte, nativeSupervisorProofClaims) {
	t.Helper()
	now := time.Now().Unix()
	claims := nativeSupervisorProofClaims{
		Version: 1, GrantID: c.GrantID, RequestID: c.RequestID,
		EngagementID: c.EngagementID, FlowID: c.FlowID, TaskID: c.TaskID,
		SubtaskID: c.SubtaskID, ActionID: c.ActionID,
		OwnerID: "owner-qualified", ServerID: c.ServerID,
		WorkerID: "worker-isolated", ContainerID: strings.Repeat("c", 64),
		SupervisorID: "independent-supervisor", Epoch: 4, Revision: 1,
		ApprovalID: "apr-qualified", LeaseID: c.LeaseID,
		AuthorizationSHA256: c.AuthorizationSHA256,
		ClaimsSHA256:        canonicalSHA256(mustCanonicalClaims(t, c)),
		ResourceSHA256:      *c.ResourceSHA256, Nonce: strings.Repeat("a", 32),
		IssuedAt: now, ExpiresAt: now + 8,
	}
	canonical, err := canonicalSupervisorProof(claims)
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(map[string]any{
		"claims": claims, "kid": "supervisor-test-key",
		"signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, append([]byte(nativeSupervisorDomain), canonical...))),
	})
	if err != nil {
		t.Fatal(err)
	}
	return content, claims
}

func provisionNativeTestSupervisor(s *Server, content []byte, addr string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/native-supervisor/provision", bytes.NewReader(content))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = addr
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestNativeSupervisorProvisionDenyForgedCallerReplayAndUnsafeIngress(t *testing.T) {
	f := newGrantFixture(t)
	claims := makeGrantClaims(time.Now().Unix())
	resource := strings.Repeat("d", 64)
	claims.ResourceSHA256 = &resource
	_, supervisor, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.server.ConfigureNativeSupervisorTrust(map[string]NativeSupervisorPublicIdentity{
		"independent-supervisor": {KeyID: "supervisor-test-key", PublicKey: supervisor.Public().(ed25519.PublicKey)},
	}); err != nil {
		t.Fatal(err)
	}
	proof, _ := makeSignedNativeSupervisorProof(t, supervisor, claims)
	for _, test := range []struct {
		name     string
		content  []byte
		addr     string
		expected int
	}{
		{"remote-host", proof, "10.0.0.12:12345", http.StatusForbidden},
		{"malformed", []byte(`{"claims":{},"kid":"x","signature":"y"}`), "127.0.0.1:54321", http.StatusForbidden},
		{"duplicate-top-level", append(append([]byte(`{"kid":"a",`), proof[1:]...), []byte{}...), "127.0.0.1:54321", http.StatusForbidden},
		{"oversized", bytes.Repeat([]byte("A"), 5000), "127.0.0.1:54321", http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := provisionNativeTestSupervisor(f.server, test.content, test.addr)
			if got.Code != test.expected {
				t.Fatalf("unsafe ingress permitted: %d %s", got.Code, got.Body.String())
			}
		})
	}
	forged := append([]byte(nil), proof...)
	for i := range forged {
		if forged[i] == 'a' {
			forged[i] = 'b'
			break
		}
	}
	if p := provisionNativeTestSupervisor(f.server, forged, "127.0.0.1:54321"); p.Code == http.StatusOK {
		t.Fatal("forged signed supervisor proof accepted")
	}
	// The operator cannot inject even a valid proof through the normal MCP
	// request. It must be supplied by a separately signed supervisor channel.
	header := f.sign(t, claims)
	without := request(f.server.Handler(), http.MethodPost, "/mcp/execute",
		`{"tool_name":"authority_status","parameters":{},"request_id":"`+claims.RequestID+`"}`,
		map[string]string{nativeGrantHeader: header, "Content-Type": "application/json"})
	if without.Code != http.StatusServiceUnavailable || f.validator.calls.Load() != 0 {
		t.Fatal("resource grant redeemed without supervisor")
	}
	withCallerHeader := request(f.server.Handler(), http.MethodPost, "/mcp/execute",
		`{"tool_name":"authority_status","parameters":{},"request_id":"`+claims.RequestID+`"}`,
		map[string]string{nativeGrantHeader: header, "Content-Type": "application/json", "X-OSOP-Native-Supervisor-Proof": base64.RawURLEncoding.EncodeToString(proof)})
	if withCallerHeader.Code != http.StatusServiceUnavailable || f.validator.calls.Load() != 0 {
		t.Fatal("caller-injected independent proof reached source")
	}
	if p := provisionNativeTestSupervisor(f.server, proof, "127.0.0.1:54321"); p.Code != http.StatusOK {
		t.Fatalf("trusted independent signer denied: %d %s", p.Code, p.Body.String())
	}
	if p := provisionNativeTestSupervisor(f.server, proof, "127.0.0.1:54321"); p.Code != http.StatusConflict {
		t.Fatal("duplicate provisioning not prevented")
	}
	wrongClaims := claims
	wrongClaims.LeaseID = "lease-other"
	wrongHeader := f.sign(t, wrongClaims)
	wrong := request(f.server.Handler(), http.MethodPost, "/mcp/execute",
		`{"tool_name":"authority_status","parameters":{},"request_id":"`+claims.RequestID+`"}`,
		map[string]string{nativeGrantHeader: wrongHeader, "Content-Type": "application/json"})
	if wrong.Code != http.StatusServiceUnavailable || f.validator.calls.Load() != 0 {
		t.Fatal("wrong signed grant used independent supervisor proof")
	}
	// Consumption is fail-closed and may not be reused even by original grant.
	original := request(f.server.Handler(), http.MethodPost, "/mcp/execute",
		`{"tool_name":"authority_status","parameters":{},"request_id":"`+claims.RequestID+`"}`,
		map[string]string{nativeGrantHeader: header, "Content-Type": "application/json"})
	if original.Code != http.StatusServiceUnavailable || f.validator.calls.Load() != 0 {
		t.Fatal("mismatched claim was mistakenly redeemed")
	}
	if p := provisionNativeTestSupervisor(f.server, proof, "127.0.0.1:54321"); p.Code != http.StatusConflict {
		t.Fatal("used grant proof could be replayed")
	}
}

func TestNativeSupervisorConcurrentProvisionOneWinner(t *testing.T) {
	f := newGrantFixture(t)
	c := makeGrantClaims(time.Now().Unix())
	resource := strings.Repeat("d", 64)
	c.ResourceSHA256 = &resource
	_, supervisor, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.server.ConfigureNativeSupervisorTrust(map[string]NativeSupervisorPublicIdentity{
		"independent-supervisor": {KeyID: "supervisor-test-key", PublicKey: supervisor.Public().(ed25519.PublicKey)},
	}); err != nil {
		t.Fatal(err)
	}
	proof, _ := makeSignedNativeSupervisorProof(t, supervisor, c)
	var wg sync.WaitGroup
	var winners atomic.Int64
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if provisionNativeTestSupervisor(f.server, proof, "127.0.0.1:5555").Code == http.StatusOK {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("one supervisor proof should have one local winner: %d", winners.Load())
	}
}

func TestNativeSupervisorRotationInvalidatesPendingProofAndIssuerKeyCollision(t *testing.T) {
	f := newGrantFixture(t)
	issuer := f.signer.Public().(ed25519.PublicKey)
	if err := f.server.ConfigureNativeSupervisorTrust(map[string]NativeSupervisorPublicIdentity{
		"independent-supervisor": {KeyID: "same-grant-key", PublicKey: issuer},
	}); err == nil {
		t.Fatal("0029 grant issuer was accepted as independent supervisor")
	}
	pub1, key1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.server.ConfigureNativeSupervisorTrust(map[string]NativeSupervisorPublicIdentity{
		"independent-supervisor": {KeyID: "supervisor-test-key", PublicKey: pub1},
	}); err != nil {
		t.Fatal(err)
	}
	c := makeGrantClaims(time.Now().Unix())
	resource := strings.Repeat("d", 64)
	c.ResourceSHA256 = &resource
	proof, _ := makeSignedNativeSupervisorProof(t, key1, c)
	if p := provisionNativeTestSupervisor(f.server, proof, "127.0.0.1:12345"); p.Code != http.StatusOK {
		t.Fatal("trusted supervisor not provisioned")
	}
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.server.ConfigureNativeSupervisorTrust(map[string]NativeSupervisorPublicIdentity{
		"independent-supervisor": {KeyID: "rotated-supervisor-key", PublicKey: pub2},
	}); err != nil {
		t.Fatal(err)
	}
	if p := provisionNativeTestSupervisor(f.server, proof, "127.0.0.1:12345"); p.Code == http.StatusOK {
		t.Fatal("rotated supervisor signature trusted")
	}
	header := f.sign(t, c)
	w := request(f.server.Handler(), http.MethodPost, "/mcp/execute",
		`{"tool_name":"authority_status","parameters":{},"request_id":"`+c.RequestID+`"}`,
		map[string]string{nativeGrantHeader: header, "Content-Type": "application/json"})
	if w.Code != http.StatusServiceUnavailable || f.validator.calls.Load() != 0 {
		t.Fatal("old supervisor provision survived rotation")
	}
	// Validate reverse configuration order too: no different API can first
	// register a supervisor then configure that very key as grant issuer.
	other := NewServer("recon-mcp")
	if err := other.ConfigureNativeSupervisorTrust(map[string]NativeSupervisorPublicIdentity{
		"independent-supervisor": {KeyID: "supervisor-test-key", PublicKey: issuer},
	}); err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.tlsServer.Certificate().Raw})
	if err := other.ConfigureNativeGrant(NativeGrantConfig{
		TrustedPublicKeys: map[string]ed25519.PublicKey{f.keyID: issuer},
		RedeemURL:         f.tlsServer.URL + "/native-grants/redeem", PinnedRootPEM: certPEM,
	}); err == nil {
		t.Fatal("reverse configuration accepted identical supervisor/issuer key")
	}
}

func TestNativeSupervisorProductionEnvironmentTrustRejectsAmbiguity(t *testing.T) {
	f := newGrantFixture(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	configured := map[string]any{
		"independent-supervisor": map[string]any{
			"kid":           "supervisor-test-key",
			"public_key":    base64.RawURLEncoding.EncodeToString(pub),
			"secret_sha256": strings.Repeat("a", 64),
		},
	}
	raw, err := json.Marshal(configured)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(nativeSupervisorTrustEnv, string(raw))
	if err := f.server.configureNativeSupervisorFromEnvironment(); err != nil {
		t.Fatalf("real per-server production verifier config rejected: %v", err)
	}
	c := makeGrantClaims(time.Now().Unix())
	resource := strings.Repeat("e", 64)
	c.ResourceSHA256 = &resource
	proof, _ := makeSignedNativeSupervisorProof(t, key, c)
	if response := provisionNativeTestSupervisor(f.server, proof, "127.0.0.1:12345"); response.Code != http.StatusOK {
		t.Fatalf("configured verifier rejected signed independent proof: %d", response.Code)
	}
	for _, invalid := range []string{
		`{"independent-supervisor":{"kid":"x","kid":"y","public_key":"x","secret_sha256":"x"}}`,
		`{"independent-supervisor":{"kid":"supervisor-test-key","public_key":"x","secret_sha256":"` + strings.Repeat("a", 64) + `"}}`,
		`{"independent-supervisor":{"kid":"supervisor-test-key","public_key":"` + base64.RawURLEncoding.EncodeToString(pub) + `","secret_sha256":"` + strings.Repeat("a", 64) + `","private_key":"forbidden"}}`,
	} {
		t.Setenv(nativeSupervisorTrustEnv, invalid)
		other := newGrantFixture(t)
		if err := other.server.configureNativeSupervisorFromEnvironment(); err == nil {
			t.Fatal("malformed, duplicate or private supervisor configuration became trusted")
		}
	}
}
