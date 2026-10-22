package sdk

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The worker is an opaque forwarder, NOT a supervisor proof issuer. The
// independently pinned central verifier remains the only authority to
// validate the 0033 signature, epoch and live PostgreSQL source.
func TestSeparateSupervisorProofForwardedOverPinnedHTTPS(t *testing.T) {
	f := newGrantFixture(t)
	claims := makeGrantClaims(time.Now().Unix())
	sha := strings.Repeat("d", 64)
	claims.ResourceSHA256 = &sha
	header := f.sign(t, claims)
	supervisorPub, supervisorKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.server.ConfigureNativeSupervisorTrust(map[string]NativeSupervisorPublicIdentity{
		"independent-supervisor": {KeyID: "supervisor-test-key", PublicKey: supervisorPub},
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	proofClaims := nativeSupervisorProofClaims{
		Version: 1, GrantID: claims.GrantID, RequestID: claims.RequestID,
		EngagementID: claims.EngagementID, FlowID: claims.FlowID, TaskID: claims.TaskID,
		SubtaskID: claims.SubtaskID, ActionID: claims.ActionID,
		OwnerID: "owner-qualified", ServerID: claims.ServerID,
		WorkerID: "worker-isolated", ContainerID: strings.Repeat("c", 64),
		SupervisorID: "independent-supervisor", Epoch: 1, Revision: 1,
		ApprovalID: "apr-qualified", LeaseID: claims.LeaseID,
		AuthorizationSHA256: claims.AuthorizationSHA256,
		ClaimsSHA256:        canonicalSHA256(mustCanonicalClaims(t, claims)),
		ResourceSHA256:      sha, Nonce: strings.Repeat("a", 32), IssuedAt: now, ExpiresAt: now + 8,
	}
	canonical, err := canonicalSupervisorProof(proofClaims)
	if err != nil {
		t.Fatal(err)
	}
	proof := map[string]any{
		"claims": proofClaims,
		"kid":    "supervisor-test-key", "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(supervisorKey, append([]byte(nativeSupervisorDomain), canonical...))),
	}
	proofJSON, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(proofJSON)
	provisionRequest := httptest.NewRequest(http.MethodPost, "/native-supervisor/provision", bytes.NewReader(proofJSON))
	provisionRequest.RemoteAddr = "127.0.0.1:45672"
	provisionRequest.Header.Set("Content-Type", "application/json")
	provisionResponse := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(provisionResponse, provisionRequest)
	if provisionResponse.Code != http.StatusOK {
		t.Fatalf("independent signed supervisor not provisioned: %d %s", provisionResponse.Code, provisionResponse.Body.String())
	}
	requests := 0
	resourceRequests := 0
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/native-grants/resources" {
			resourceRequests++
			// Independent original-source offer accepts the signed issuer grant,
			// NOT the separately consumed supervisor redemption proof wrapper.
			// Distinguish the two envelopes at a real TLS HTTP boundary.
			originalBytes, readErr := io.ReadAll(io.LimitReader(r.Body, 8193))
			if readErr != nil {
				t.Errorf("resource original grant unavailable: %v", readErr)
			}
			original, shapeErr := decodeExactObject(originalBytes, map[string]bool{
				"claims": true, "kid": true, "signature": true,
			})
			if shapeErr != nil {
				t.Errorf("resource endpoint received supervisor wrapper instead of signed original: %v", shapeErr)
			} else if _, hasGrant := original["claims"]; !hasGrant {
				t.Error("resource must carry signed original issuer claims")
			}
			// No original bytes were provisioned in this transport-only test.
			// Source MUST fail closed rather than simulate a 0030 offer.
			http.Error(w, "original source unavailable", http.StatusServiceUnavailable)
			return
		}
		requests++
		if r.URL.Path != "/native-grants/redeem" || r.Method != http.MethodPost {
			t.Error("unexpected supervisor redemption endpoint")
			http.Error(w, "unavailable", http.StatusForbidden)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil {
			t.Error(err)
			return
		}
		obj, err := decodeExactObject(raw, map[string]bool{"grant": true, "worker_proof": true})
		if err != nil {
			t.Errorf("expected independently forwarded two-field envelope: %v", err)
			return
		}
		var actualProof map[string]any
		if err := json.Unmarshal(obj["worker_proof"], &actualProof); err != nil || actualProof["kid"] != "supervisor-test-key" {
			t.Error("original supervisor testimony not forwarded")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"grant_id": claims.GrantID, "request_id": claims.RequestID,
			"claim_sha256":     canonicalSHA256(mustCanonicalClaims(t, claims)),
			"durably_redeemed": true,
		})
	}))
	defer remote.Close()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: remote.Certificate().Raw})
	if err := f.server.ConfigureNativeGrant(NativeGrantConfig{
		TrustedPublicKeys: map[string]ed25519.PublicKey{f.keyID: f.signer.Public().(ed25519.PublicKey)},
		RedeemURL:         remote.URL + "/native-grants/redeem", PinnedRootPEM: certPEM,
	}); err != nil {
		t.Fatal(err)
	}
	body := `{"tool_name":"authority_status","parameters":{},"request_id":"` + claims.RequestID + `"}`
	r := request(f.server.Handler(), http.MethodPost, "/mcp/execute", body, map[string]string{
		nativeGrantHeader: header, "Content-Type": "application/json",
	})
	if r.Code != http.StatusServiceUnavailable {
		t.Fatalf("transport-only fixture must NOT claim original byte delivery: %d", r.Code)
	}
	if requests != 1 {
		t.Fatal("expected one pinned central verifier request")
	}
	if resourceRequests != 1 {
		t.Fatal("expected one separately verified original grant resource request")
	}
	for _, bad := range []string{"==", "bad proof", strings.Repeat("A", 6100), encoded} {
		before := requests
		denied := request(f.server.Handler(), http.MethodPost, "/mcp/execute", body, map[string]string{
			nativeGrantHeader: header, "X-OSOP-Native-Supervisor-Proof": bad, "Content-Type": "application/json",
		})
		if denied.Code != http.StatusServiceUnavailable || requests != before {
			t.Fatal("malformed supervisor credential reached independent verifier")
		}
	}
}

func mustCanonicalClaims(t *testing.T, claims NativeGrantClaims) []byte {
	t.Helper()
	value, err := CanonicalNativeClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
