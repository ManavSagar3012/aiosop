package sdk

// Read-only native worker original-byte inspection, in-memory only. A durable
// central PostgreSQL OFFER is not proof of receipt or a target effect.
import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const maxNativeResourceWire = 6*1024*1024 + 128*1024

var nativeArtifactIDRE = regexp.MustCompile(`^artifact-[a-f0-9]{32}$`)
var nativeResourceFilenameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// Match the Python source export's active-markup rejection independently;
// simple substring checks would miss <a>, <p> and whitespace after '<'.
var nativeActiveMarkupRE = regexp.MustCompile(`(?i)<\s*(?:!doctype\s+html|html\b|head\b|body\b|script\b|iframe\b|object\b|embed\b|svg\b|meta\b|link\b|form\b|style\b|img\b|a\b|div\b|p\b|input\b|button\b|textarea\b|video\b|audio\b|template\b|math\b|base\b|picture\b|\?xml\b)`)
var inertResourceSuffixes = map[string]bool{
	".txt": true, ".md": true, ".csv": true, ".tsv": true, ".json": true,
	".jsonl": true, ".yaml": true, ".yml": true, ".toml": true,
	".ini": true, ".cfg": true, ".log": true, ".diff": true, ".patch": true,
	".py": true, ".go": true, ".rs": true, ".java": true, ".c": true,
	".h": true, ".cpp": true, ".hpp": true, ".ts": true, ".tsx": true,
	".js": true, ".jsx": true, ".css": true, ".sql": true,
}

type nativeResourceItem struct {
	ArtifactID     string `json:"artifact_id"`
	Name           string `json:"name"`
	ResourcePath   string `json:"resource_path"`
	SizeBytes      int    `json:"size_bytes"`
	SHA256         string `json:"sha256"`
	Classification string `json:"classification"`
}
type nativeResourceManifest struct {
	Format                 string               `json:"format"`
	FlowID                 string               `json:"flow_id"`
	FlowRevision           int                  `json:"flow_revision"`
	AuthorizationVersion   int                  `json:"authorization_version"`
	Count                  int                  `json:"count"`
	TotalSizeBytes         int                  `json:"total_size_bytes"`
	Items                  []nativeResourceItem `json:"items"`
	ReadOnly               bool                 `json:"read_only"`
	ContentExecuted        bool                 `json:"content_executed"`
	HostFilesCreated       bool                 `json:"host_files_created"`
	ArchiveCompression     string               `json:"archive_compression"`
	ArtifactBytesUntrusted bool                 `json:"artifact_bytes_untrusted"`
	ManifestSHA256         string               `json:"manifest_sha256"`
}
type nativeOfferedFile struct {
	ArtifactID string `json:"artifact_id"`
	SHA256     string `json:"sha256"`
	ContentB64 string `json:"content_b64"`
}
type nativeResourceOffer struct {
	GrantID        string                 `json:"grant_id"`
	RequestID      string                 `json:"request_id"`
	ManifestSHA256 string                 `json:"manifest_sha256"`
	Manifest       nativeResourceManifest `json:"manifest"`
	Files          []nativeOfferedFile    `json:"files"`
}

var nativeManifestKeys = map[string]bool{
	"format": true, "flow_id": true, "flow_revision": true, "authorization_version": true,
	"count": true, "total_size_bytes": true, "items": true, "read_only": true,
	"content_executed": true, "host_files_created": true, "archive_compression": true,
	"artifact_bytes_untrusted": true, "manifest_sha256": true,
}
var nativeItemKeys = map[string]bool{
	"artifact_id": true, "name": true, "resource_path": true,
	"size_bytes": true, "sha256": true, "classification": true,
}

func validNativeUntrustedText(data []byte) bool {
	if len(data) == 0 || !utf8.Valid(data) || bytes.Contains(data, []byte("<!--")) ||
		bytes.Contains(data, []byte("<![CDATA[")) || nativeActiveMarkupRE.Match(data) {
		return false
	}
	s := string(data)
	if strings.HasPrefix(strings.TrimLeft(s, "\ufeff \t\r\n"), "#!") {
		return false
	}
	for _, r := range s {
		if (r < 32 && r != '\n' && r != '\r' && r != '\t') || r == 127 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return false
		}
	}
	lower := strings.ToLower(s)
	for _, p := range []string{"<!doctype html", "<html", "<head", "<body", "<script", "<iframe", "<object", "<embed", "<svg", "<meta", "<link", "<form", "<style", "<img", "<a ", "<div", "<p ", "<input", "<button", "<textarea", "<video", "<audio", "<template", "<math", "<base", "<picture", "<?xml"} {
		if strings.Contains(lower, p) {
			return false
		}
	}
	return true
}

func verifyNativeOffer(raw []byte, claims NativeGrantClaims) error {
	if claims.ResourceSHA256 == nil || len(raw) == 0 || len(raw) > maxNativeResourceWire {
		return errors.New("resource envelope unavailable")
	}
	fields, err := decodeExactObject(raw, map[string]bool{"grant_id": true, "request_id": true, "manifest_sha256": true, "manifest": true, "files": true})
	if err != nil {
		// Only an independently pinned 0026 folder-catalog plan may add a
		// source-side envelope field. The native caller cannot invent it.
		fields, err = decodeExactObject(raw, map[string]bool{
			"grant_id": true, "request_id": true, "manifest_sha256": true,
			"manifest": true, "files": true, "folder_staging": true,
		})
		if err != nil {
			return errors.New("resource envelope ambiguous")
		}
	}
	manifestFields, err := decodeExactObject(fields["manifest"], nativeManifestKeys)
	if err != nil {
		return errors.New("manifest schema unavailable")
	}
	var rawItems []json.RawMessage
	if json.Unmarshal(manifestFields["items"], &rawItems) != nil {
		return errors.New("items unavailable")
	}
	for _, item := range rawItems {
		if _, err := decodeExactObject(item, nativeItemKeys); err != nil {
			return errors.New("resource item ambiguous")
		}
	}
	var rawFiles []json.RawMessage
	if json.Unmarshal(fields["files"], &rawFiles) != nil {
		return errors.New("files unavailable")
	}
	for _, file := range rawFiles {
		if _, err := decodeExactObject(file, map[string]bool{"artifact_id": true, "sha256": true, "content_b64": true}); err != nil {
			return errors.New("file ambiguous")
		}
	}
	var offer nativeResourceOffer
	if json.Unmarshal(raw, &offer) != nil || offer.GrantID != claims.GrantID || offer.RequestID != claims.RequestID || offer.ManifestSHA256 != *claims.ResourceSHA256 || offer.Manifest.ManifestSHA256 != *claims.ResourceSHA256 || offer.Manifest.FlowID != claims.FlowID || offer.Manifest.AuthorizationVersion != int(claims.AuthorizationVersion) || offer.Manifest.Format != "ai-osop-inert-flow-resources-v1" || !offer.Manifest.ReadOnly || offer.Manifest.ContentExecuted || offer.Manifest.HostFilesCreated || !offer.Manifest.ArtifactBytesUntrusted || offer.Manifest.ArchiveCompression != "stored" || offer.Manifest.FlowRevision < 0 || offer.Manifest.Count < 1 || offer.Manifest.Count > 16 || offer.Manifest.Count != len(offer.Files) || offer.Manifest.Count != len(offer.Manifest.Items) || offer.Manifest.TotalSizeBytes < 1 || offer.Manifest.TotalSizeBytes > 4*1024*1024 {
		return errors.New("resource claims mismatch")
	}
	// FastAPI emits Python dict insertion order, whereas make_manifest signs
	// Python json.dumps(sort_keys=True) RECURSIVELY. Re-encode fully parsed
	// nested maps, not json.RawMessage: RawMessage preserves arbitrary nested
	// item key order and would falsely reject the actual mounted API's bytes.
	var m map[string]any
	if json.Unmarshal(fields["manifest"], &m) != nil {
		return errors.New("manifest unavailable")
	}
	delete(m, "manifest_sha256")
	canonical, err := json.Marshal(m)
	if err != nil || canonicalSHA256(canonical) != *claims.ResourceSHA256 {
		return errors.New("manifest checksum rejected")
	}
	byID := map[string]nativeOfferedFile{}
	for _, f := range offer.Files {
		if !nativeArtifactIDRE.MatchString(f.ArtifactID) || !nativeSHARE.MatchString(f.SHA256) || len(f.ContentB64) > 3*1024*1024 {
			return errors.New("file identity rejected")
		}
		if _, ok := byID[f.ArtifactID]; ok {
			return errors.New("duplicate file")
		}
		byID[f.ArtifactID] = f
	}
	total := 0
	seen := map[string]bool{}
	for _, item := range offer.Manifest.Items {
		f, ok := byID[item.ArtifactID]
		if !ok || item.SHA256 != f.SHA256 || !nativeResourceFilenameRE.MatchString(item.Name) || strings.HasPrefix(item.Name, ".") || strings.Contains(item.Name, "..") || path.Base(item.Name) != item.Name || seen[item.Name] || !inertResourceSuffixes[strings.ToLower(path.Ext(item.Name))] || item.ResourcePath != "resources/"+item.Name || !nativeArtifactIDRE.MatchString(item.ArtifactID) || (item.Classification != "utf8_inert_text" && item.Classification != "utf8_inert_source") {
			return errors.New("path or file type unsafe")
		}
		seen[item.Name] = true
		blob, err := base64.StdEncoding.Strict().DecodeString(f.ContentB64)
		if err != nil || base64.StdEncoding.EncodeToString(blob) != f.ContentB64 || len(blob) != item.SizeBytes || len(blob) > 2*1024*1024 || canonicalSHA256(blob) != item.SHA256 || !validNativeUntrustedText(blob) {
			return errors.New("untrusted bytes tampered or active")
		}
		total += len(blob)
		if total > 4*1024*1024 {
			return errors.New("original byte quota exceeded")
		}
		// The ephemeral bytes go nowhere beyond validation. No files or mounts.
	}
	if total != offer.Manifest.TotalSizeBytes {
		return errors.New("original byte count changed")
	}
	if plan, hasPlan := fields["folder_staging"]; hasPlan {
		if err := verifyNativeFolderPlan(plan, offer); err != nil {
			return errors.New("approved folder staging plan rejected")
		}
	}
	return nil
}

func (s *Server) receiveNativeReviewedResource(ctx context.Context, config *nativeAuthority, token nativeGrantToken, envelope []byte) error {
	if token.Claims.ResourceSHA256 == nil {
		return nil
	}
	if !strings.HasSuffix(config.redeemURL, "/native-grants/redeem") {
		return errors.New("source route unavailable")
	}
	u := strings.TrimSuffix(config.redeemURL, "/redeem") + "/resources"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(envelope))
	if err != nil {
		return errors.New("source request invalid")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("X-OSOP-Native-Server-ID", s.ID)
	req.Header.Set("Authorization", "Bearer "+config.serviceSecret)
	// Resource BYTEA offers may wait behind a concurrently failing redeemer's
	// PostgreSQL original-Action lock. Keep the ordinary short redemption
	// timeout unchanged, but permit a separately bounded 6s byte readback.
	// Copying the client preserves its pinned TLS root, no proxy and strict
	// redirect denial; this does not retry a committed resource offer.
	resourceClient := *config.client
	resourceClient.Timeout = 6 * time.Second
	response, err := resourceClient.Do(req)
	if err != nil {
		return errors.New("resource acknowledgment UNKNOWN")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])) != "application/json" {
		return fmt.Errorf("resource offer response unavailable (HTTP %d)", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxNativeResourceWire+1))
	if err != nil || len(raw) > maxNativeResourceWire {
		return errors.New("resource response too large")
	}
	if err := verifyNativeOffer(raw, token.Claims); err != nil {
		return fmt.Errorf("independent original-byte check rejected: %w", err)
	}
	// RAM-only existing behavior is unchanged. A distinctly approved source
	// folder plan must NOT silently fall back to RAM verification: staging in
	// a pre-isolated, no-host-mount worker is mandatory or this fails closed.
	var verified map[string]json.RawMessage
	if err := json.Unmarshal(raw, &verified); err != nil {
		return errors.New("native resource envelope unavailable")
	}
	if _, stageRequested := verified["folder_staging"]; stageRequested {
		if err := stageNativeReviewedOriginal(raw); err != nil {
			return errors.New("native isolated original-byte staging unavailable")
		}
		if err := s.sendNativeStageReceipt(ctx, config, token, envelope, raw); err != nil {
			// The independently signed native worker receipt MAY have been
			// committed before HTTP ACK loss. Do not retry; original Action
			// stays UNKNOWN even after safe staging completed and was erased.
			return errors.New("native worker stage receipt outcome UNKNOWN")
		}
	}
	return nil
}
