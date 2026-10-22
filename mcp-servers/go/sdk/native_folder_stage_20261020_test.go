package sdk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestPinnedWorkerStageReceiptUsesSeparateEd25519Key(t *testing.T) {
	raw, err := os.ReadFile("testdata/native_python_folder_offer.json")
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(41 + i)
	}
	worker := ed25519.NewKeyFromSeed(seed)
	t.Setenv("OSOP_NATIVE_STAGE_RECEIPT_ED25519_SEED_B64",
		base64.RawURLEncoding.EncodeToString(seed))
	t.Setenv("OSOP_NATIVE_STAGE_RECEIPT_KID", "native-worker-qa")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/native-grants/stage-receipt" ||
			r.Header.Get("Authorization") != "Bearer "+strings.Repeat("s", 40) ||
			r.Header.Get("X-OSOP-Native-Server-ID") != "recon-mcp" {
			http.Error(w, "invalid independently pinned native server identity", 403)
			return
		}
		var incoming struct {
			Grant   nativeGrantToken `json:"grant"`
			Receipt struct {
				Claims    map[string]any `json:"claims"`
				Kid       string         `json:"kid"`
				Signature string         `json:"signature"`
			} `json:"receipt"`
		}
		if json.NewDecoder(r.Body).Decode(&incoming) != nil {
			http.Error(w, "malformed stage receipt", 403)
			return
		}
		canonical, err := json.Marshal(incoming.Receipt.Claims)
		sig, e := base64.RawURLEncoding.DecodeString(incoming.Receipt.Signature)
		if err != nil || e != nil || incoming.Receipt.Kid != "native-worker-qa" ||
			!ed25519.Verify(worker.Public().(ed25519.PublicKey),
				append([]byte(stageReceiptDomain), canonical...), sig) {
			http.Error(w, "invalid independent worker proof", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"grant_id":                           incoming.Grant.Claims.GrantID,
			"request_id":                         incoming.Grant.Claims.RequestID,
			"receipt_sha256":                     canonicalSHA256(canonical),
			"worker_stage_report_durable":        true,
			"independent_target_effect_verified": false,
		})
	}))
	defer server.Close()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer("recon-mcp")
	if err := s.ConfigureNativeGrant(NativeGrantConfig{
		TrustedPublicKeys:   map[string]ed25519.PublicKey{"issuer-qa": pub},
		RedeemURL:           server.URL + "/native-grants/redeem",
		PinnedRootPEM:       cert,
		RedeemServiceSecret: strings.Repeat("s", 40),
	}); err != nil {
		t.Fatal(err)
	}
	var offer struct {
		GrantID        string `json:"grant_id"`
		RequestID      string `json:"request_id"`
		ManifestSHA256 string `json:"manifest_sha256"`
	}
	if json.Unmarshal(raw, &offer) != nil {
		t.Fatal("original fixture invalid")
	}
	token := nativeGrantToken{Claims: NativeGrantClaims{
		GrantID: offer.GrantID, RequestID: offer.RequestID, ServerID: "recon-mcp",
		ResourceSHA256: &offer.ManifestSHA256,
	}}
	if err := s.sendNativeStageReceipt(
		context.Background(), s.nativeConfig(), token, []byte("{}"), raw,
	); err != nil {
		t.Fatalf("real Go separate Ed25519 stage receipt rejected: %v", err)
	}
	_ = sha256.Size
	_ = hex.EncodedLen
	_ = x509.NewCertPool
}

func TestPythonTaskPinnedFolderOriginalBytes(t *testing.T) {
	raw, err := os.ReadFile("testdata/native_python_folder_offer.json")
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		GrantID        string `json:"grant_id"`
		RequestID      string `json:"request_id"`
		ManifestSHA256 string `json:"manifest_sha256"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	claims := NativeGrantClaims{
		GrantID: envelope.GrantID, RequestID: envelope.RequestID,
		FlowID: "flow-qualified", AuthorizationVersion: 2,
		ResourceSHA256: &envelope.ManifestSHA256,
	}
	if err := verifyNativeOffer(raw, claims); err != nil {
		t.Fatalf("verified approved Python 0026 folder snapshot refused: %v", err)
	}
	// A stock host path is not an isolated tmpfs sandbox. Fail closed instead
	// of describing a temporary host directory as safely container-staged.
	if os.Getenv("OSOP_NATIVE_MCP_STAGE_ROOT") == "" {
		if err := stageNativeReviewedOriginal(raw); err == nil {
			t.Fatal("native host filesystem staging was enabled without sandbox")
		}
		return
	}
	// Positive file creation/readback/atomic manifest/cleanup ONLY when an
	// independently provisioned Linux tmpfs sandbox has already been checked.
	if err := stageNativeReviewedOriginal(raw); err != nil {
		t.Fatalf("isolated tmpfs atomic original byte staging failed: %v", err)
	}
	if items, err := os.ReadDir("/run/osop-native-stage"); err != nil || len(items) != 0 {
		t.Fatal("ephemeral native files survived completed stage cleanup")
	}
}

func TestUnsafeFolderedResourcePlanDenied(t *testing.T) {
	raw, err := os.ReadFile("testdata/native_python_folder_offer.json")
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if json.Unmarshal(raw, &envelope) != nil {
		t.Fatal("source fixture invalid")
	}
	plan := envelope["folder_staging"].(map[string]any)
	items := plan["items"].([]any)
	entry := items[0].(map[string]any)
	for _, path := range []string{
		"resources/operator_reviewed/../../private.txt",
		"resources/other/independently_reviewed_notes.txt",
		"/etc/shadow",
		"resources/operator_reviewed/evil-link",
	} {
		entry["relative_path"] = path
		copyPlan := map[string]any{}
		for k, v := range plan {
			if k != "staging_sha256" {
				copyPlan[k] = v
			}
		}
		sorted, _ := json.Marshal(copyPlan)
		plan["staging_sha256"] = canonicalSHA256(sorted)
		encoded, _ := json.Marshal(envelope)
		var offer nativeResourceOffer
		if json.Unmarshal(encoded, &offer) != nil {
			t.Fatal("source fixture invalid")
		}
		planJSON, _ := json.Marshal(plan)
		if err := verifyNativeFolderPlan(planJSON, offer); err == nil {
			t.Fatalf("fully SHA-signed but unsafe folder path admitted: %q", path)
		}
	}
}
