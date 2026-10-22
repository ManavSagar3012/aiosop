package sdk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNativeReviewedResourceFollowsNoTLSRedirect(t *testing.T) {
	var leaked atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/leak" {
			leaked.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path != "/native-grants/resources" {
			t.Error("unexpected native resource route")
		}
		w.Header().Set("Location", "/leak")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer("recon-mcp")
	if err := s.ConfigureNativeGrant(NativeGrantConfig{
		TrustedPublicKeys:   map[string]ed25519.PublicKey{"issuer-qa": pub},
		RedeemURL:           server.URL + "/native-grants/redeem",
		PinnedRootPEM:       root,
		RedeemServiceSecret: strings.Repeat("s", 40),
	}); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	token := nativeGrantToken{Claims: NativeGrantClaims{ResourceSHA256: &digest}}
	if err := s.receiveNativeReviewedResource(
		context.Background(), s.nativeConfig(), token, []byte("{}"),
	); err == nil {
		t.Fatal("resource redirect followed or forged success")
	}
	if leaked.Load() != 0 {
		t.Fatal("native resource redirect leaked capability to alternate path")
	}
}

func TestPythonProducedCanonicalReviewedResourceOffer(t *testing.T) {
	data, err := os.ReadFile("testdata/native_python_original_offer.json")
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		GrantID        string `json:"grant_id"`
		RequestID      string `json:"request_id"`
		ManifestSHA256 string `json:"manifest_sha256"`
	}
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatal(err)
	}
	claims := NativeGrantClaims{
		GrantID:              source.GrantID,
		RequestID:            source.RequestID,
		FlowID:               "flow-qualified",
		AuthorizationVersion: 2,
		ResourceSHA256:       &source.ManifestSHA256,
	}
	if err := verifyNativeOffer(data, claims); err != nil {
		t.Fatalf("true Python original byte envelope rejected: %v", err)
	}
}

func TestFastAPIPythonUnsortedNestedManifestCanonicalization(t *testing.T) {
	data, err := os.ReadFile("testdata/native_fastapi_unsorted_offer.json")
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		GrantID        string `json:"grant_id"`
		RequestID      string `json:"request_id"`
		ManifestSHA256 string `json:"manifest_sha256"`
	}
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatal(err)
	}
	claims := NativeGrantClaims{
		GrantID: source.GrantID, RequestID: source.RequestID,
		FlowID: "flow-qualified", AuthorizationVersion: 2,
		ResourceSHA256: &source.ManifestSHA256,
	}
	if err := verifyNativeOffer(data, claims); err != nil {
		t.Fatalf("real Python/FastAPI unsorted nested keys must canonicalize: %v", err)
	}
}

func resourceOfferFixture(t *testing.T, name, blob string) ([]byte, NativeGrantClaims) {
	t.Helper()
	id := "artifact-" + strings.Repeat("a", 32)
	sha := canonicalSHA256([]byte(blob))
	item := map[string]any{"artifact_id": id, "name": name, "resource_path": "resources/" + name,
		"size_bytes": len(blob), "sha256": sha, "classification": "utf8_inert_text"}
	manifest := map[string]any{
		"format":  "ai-osop-inert-flow-resources-v1",
		"flow_id": "flow-qualified", "flow_revision": 1,
		"authorization_version": 2, "count": 1, "total_size_bytes": len(blob),
		"items": []map[string]any{item}, "read_only": true, "content_executed": false,
		"host_files_created": false, "archive_compression": "stored", "artifact_bytes_untrusted": true,
	}
	base, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := canonicalSHA256(base)
	manifest["manifest_sha256"] = digest
	claims := NativeGrantClaims{
		GrantID:   "ngr-" + strings.Repeat("b", 32),
		RequestID: "req-" + strings.Repeat("c", 48),
		FlowID:    "flow-qualified", AuthorizationVersion: 2, ResourceSHA256: &digest,
	}
	data, err := json.Marshal(map[string]any{
		"grant_id": claims.GrantID, "request_id": claims.RequestID,
		"manifest_sha256": digest, "manifest": manifest,
		"files": []map[string]any{{"artifact_id": id, "sha256": sha,
			"content_b64": base64.StdEncoding.EncodeToString([]byte(blob))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data, claims
}

func TestNativeReviewedOriginalBytesStrictMemoryOnly(t *testing.T) {
	data, claims := resourceOfferFixture(t, "reviewed_notes.txt", "inert original data\n")
	if err := verifyNativeOffer(data, claims); err != nil {
		t.Fatalf("valid original source bytes rejected: %v", err)
	}
	for _, tc := range []struct{ name, path, body string }{
		{"traversal", "../private.txt", "untrusted\n"},
		{"windows-path", "C:\\private.txt", "untrusted\n"},
		{"executable", "payload.exe", "untrusted\n"},
		{"shell-shebang", "resource.txt", "#!/bin/sh\nrun this\n"},
		{"active-html", "resource.txt", "<script>alert(1)</script>\n"},
		{"html-anchor-no-space", "resource.txt", "<a>forged link</a>\n"},
		{"html-paragraph-no-space", "resource.txt", "<p>injected</p>\n"},
		{"html-whitespace", "resource.txt", "<  SCRIPT>active</SCRIPT>\n"},
		{"bidi", "resource.txt", "hidden\u202edisplay\n"},
		{"binary", "resource.txt", "x\x00y"},
		{"hidden", "..hidden.txt", "safe\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			malicious, signed := resourceOfferFixture(t, tc.path, tc.body)
			if err := verifyNativeOffer(malicious, signed); err == nil {
				t.Fatal("independently hashed malicious resource accepted")
			}
		})
	}
	changed := strings.Replace(string(data),
		base64.StdEncoding.EncodeToString([]byte("inert original data\n")),
		base64.StdEncoding.EncodeToString([]byte("altered data\n")), 1)
	if err := verifyNativeOffer([]byte(changed), claims); err == nil {
		t.Fatal("tampered source bytes accepted")
	}
	if err := verifyNativeOffer(append(data, make([]byte, maxNativeResourceWire)...), claims); err == nil {
		t.Fatal("oversized response accepted")
	}
	duplicate := strings.Replace(string(data), "\"request_id\":", "\"request_id\":\"req-forged\",\"request_id\":", 1)
	if err := verifyNativeOffer([]byte(duplicate), claims); err == nil {
		t.Fatal("ambiguous duplicate signed request identity accepted")
	}
}
