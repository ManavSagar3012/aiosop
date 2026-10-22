package sdk

// Source-verifiable distinct Ed25519 WORKER testimony, emitted only after
// successful 0026 folder staging, independent original-byte SHA readback,
// atomic manifest publication AND confirmed cleanup. It cannot establish
// independent target-owner effects or independently attest OS sandbox policy.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const stageReceiptDomain = "ai-osop/native-stage-receipt/v1\x00"
const stageReadbackDomain = "ai-osop/native-stage-readback/v1\x00"

func (s *Server) sendNativeStageReceipt(
	ctx context.Context, cfg *nativeAuthority,
	token nativeGrantToken, envelope []byte, source []byte,
) error {
	seedString := os.Getenv("OSOP_NATIVE_STAGE_RECEIPT_ED25519_SEED_B64")
	kid := os.Getenv("OSOP_NATIVE_STAGE_RECEIPT_KID")
	if !nativeKidRE.MatchString(kid) || len(seedString) != 43 {
		return errors.New("independent native worker stage signing identity unavailable")
	}
	seed, err := base64.RawURLEncoding.DecodeString(seedString)
	if err != nil || len(seed) != ed25519.SeedSize ||
		base64.RawURLEncoding.EncodeToString(seed) != seedString {
		return errors.New("native worker signing seed not canonical")
	}
	var offered struct {
		FolderStage nativeFolderStagePlan `json:"folder_staging"`
	}
	if json.Unmarshal(source, &offered) != nil ||
		!nativeSHARE.MatchString(offered.FolderStage.StagingSHA256) {
		return errors.New("native worker stage source is not signed")
	}
	files := make([]map[string]any, 0, len(offered.FolderStage.Items))
	for _, item := range offered.FolderStage.Items {
		files = append(files, map[string]any{
			"artifact_id":   item.ArtifactID,
			"relative_path": item.RelativePath,
			"sha256":        item.SHA256,
		})
	}
	basis := map[string]any{
		"grant_id":              token.Claims.GrantID,
		"request_id":            token.Claims.RequestID,
		"folder_staging_sha256": offered.FolderStage.StagingSHA256,
		"files":                 files,
	}
	canonical, err := json.Marshal(basis)
	if err != nil {
		return errors.New("stage reread provenance cannot be canonicalized")
	}
	digest := sha256.Sum256(append([]byte(stageReadbackDomain), canonical...))
	claims := map[string]any{
		"version":               1,
		"grant_id":              token.Claims.GrantID,
		"request_id":            token.Claims.RequestID,
		"server_id":             token.Claims.ServerID,
		"resource_sha256":       *token.Claims.ResourceSHA256,
		"folder_staging_sha256": offered.FolderStage.StagingSHA256,
		"readback_sha256":       hex.EncodeToString(digest[:]),
		"verified_at":           time.Now().Unix(),
	}
	// The provenance SHA is a single SHA256(domain || canonical plan) as
	// Python's independent source checker also requires.
	claimJSON, err := json.Marshal(claims)
	if err != nil {
		return errors.New("independent stage receipt claims invalid")
	}
	signer := ed25519.NewKeyFromSeed(seed)
	signature := ed25519.Sign(signer, append([]byte(stageReceiptDomain), claimJSON...))
	requestBody, err := json.Marshal(map[string]any{
		"grant": token,
		"receipt": map[string]any{
			"claims": claims, "kid": kid,
			"signature": base64.RawURLEncoding.EncodeToString(signature),
		},
	})
	if err != nil || len(requestBody) > 8192 {
		return errors.New("bounded worker receipt unavailable")
	}
	if !strings.HasSuffix(cfg.redeemURL, "/native-grants/redeem") {
		return errors.New("pinned native stage receipt path unavailable")
	}
	u := strings.TrimSuffix(cfg.redeemURL, "/redeem") + "/stage-receipt"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(requestBody))
	if err != nil {
		return errors.New("native stage receipt transport unavailable")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("X-OSOP-Native-Server-ID", s.ID)
	req.Header.Set("Authorization", "Bearer "+cfg.serviceSecret)
	client := *cfg.client
	client.Timeout = 3 * time.Second
	response, err := client.Do(req)
	if err != nil {
		return errors.New("native worker stage receipt acknowledgment UNKNOWN")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])) != "application/json" {
		return errors.New("native stage receipt not durably accepted")
	}
	proof, err := io.ReadAll(io.LimitReader(response.Body, 2049))
	if err != nil || len(proof) > 2048 {
		return errors.New("worker receipt acknowledgment invalid")
	}
	fields, err := decodeExactObject(proof, map[string]bool{
		"grant_id": true, "request_id": true, "receipt_sha256": true,
		"worker_stage_report_durable": true, "independent_target_effect_verified": true,
	})
	if err != nil {
		return errors.New("worker stage acknowledgment ambiguous")
	}
	var accepted struct {
		GrantID                         string `json:"grant_id"`
		RequestID                       string `json:"request_id"`
		ReceiptSHA256                   string `json:"receipt_sha256"`
		WorkerStageReportDurable        bool   `json:"worker_stage_report_durable"`
		IndependentTargetEffectVerified bool   `json:"independent_target_effect_verified"`
	}
	if json.Unmarshal(proof, &accepted) != nil ||
		accepted.GrantID != token.Claims.GrantID ||
		accepted.RequestID != token.Claims.RequestID ||
		accepted.ReceiptSHA256 != canonicalSHA256(claimJSON) ||
		!accepted.WorkerStageReportDurable ||
		accepted.IndependentTargetEffectVerified {
		return errors.New("independent source worker-stage receipt mismatch")
	}
	_ = fields
	return nil
}
