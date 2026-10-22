package sdk

// A separately Task-approved, source-reconstructed 0026 virtual-folder
// assignment, never a client-supplied arbitrary destination. The source's
// response is bound by the same signed grant and independently pinned TLS
// validator and one-time PostgreSQL offering transaction.
import (
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"strings"
)

var nativeFolderIDRE = regexp.MustCompile(`^folder-[a-f0-9]{32}$`)
var nativeFolderNameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,47}$`)

type nativeFolderAssignment struct {
	ArtifactID   string `json:"artifact_id"`
	FolderID     string `json:"folder_id"`
	FolderName   string `json:"folder_name"`
	RelativePath string `json:"relative_path"`
	SHA256       string `json:"sha256"`
}
type nativeFolderStagePlan struct {
	Format          string                   `json:"format"`
	CatalogRevision int                      `json:"catalog_revision"`
	ManifestSHA256  string                   `json:"manifest_sha256"`
	Items           []nativeFolderAssignment `json:"items"`
	StagingSHA256   string                   `json:"staging_sha256"`
}

func verifyNativeFolderPlan(raw json.RawMessage, offered nativeResourceOffer) error {
	fields, err := decodeExactObject(raw, map[string]bool{
		"format": true, "catalog_revision": true, "manifest_sha256": true,
		"items": true, "staging_sha256": true,
	})
	if err != nil {
		return errors.New("folder plan schema changed")
	}
	var nested []json.RawMessage
	if json.Unmarshal(fields["items"], &nested) != nil || len(nested) != len(offered.Manifest.Items) || len(nested) == 0 {
		return errors.New("folder plan item count changed")
	}
	for _, entry := range nested {
		if _, err := decodeExactObject(entry, map[string]bool{
			"artifact_id": true, "folder_id": true, "folder_name": true,
			"relative_path": true, "sha256": true,
		}); err != nil {
			return errors.New("ambiguous folder assignment")
		}
	}
	var plan nativeFolderStagePlan
	if json.Unmarshal(raw, &plan) != nil || plan.Format != "ai-osop-readonly-folder-stage-v1" ||
		plan.CatalogRevision < 1 || plan.CatalogRevision > 1000000 ||
		plan.ManifestSHA256 != offered.ManifestSHA256 ||
		!nativeSHARE.MatchString(plan.StagingSHA256) {
		return errors.New("folder authority or format mismatch")
	}
	var canonical map[string]any
	if json.Unmarshal(raw, &canonical) != nil {
		return errors.New("folder digest source invalid")
	}
	delete(canonical, "staging_sha256")
	serialized, err := json.Marshal(canonical)
	if err != nil || canonicalSHA256(serialized) != plan.StagingSHA256 {
		return errors.New("approved folder assignment digest mismatch")
	}
	resources := map[string]nativeResourceItem{}
	for _, item := range offered.Manifest.Items {
		resources[item.ArtifactID] = item
	}
	seen := map[string]bool{}
	for index, item := range plan.Items {
		original, ok := resources[item.ArtifactID]
		if !ok || !nativeFolderIDRE.MatchString(item.FolderID) ||
			!nativeFolderNameRE.MatchString(item.FolderName) ||
			!nativeArtifactIDRE.MatchString(item.ArtifactID) ||
			item.SHA256 != original.SHA256 ||
			index > 0 && plan.Items[index-1].ArtifactID >= item.ArtifactID ||
			item.RelativePath != "resources/"+item.FolderName+"/"+original.Name ||
			path.Clean(item.RelativePath) != item.RelativePath ||
			strings.HasPrefix(item.RelativePath, "/") || seen[item.RelativePath] {
			return errors.New("untrusted folder-relative path or assignment")
		}
		seen[item.RelativePath] = true
	}
	return nil
}
