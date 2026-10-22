//go:build linux

package sdk

// POSIX filesystem staging is available ONLY within an independently
// provisioned dedicated Linux sandbox with an exact private noexec/nosuid/
// nodev tmpfs mount. This code does not mount filesystems or run subprocesses.
// It refuses ordinary host temp directories and every caller-provided path.
// A disposable per-grant container lifetime is still a deployment obligation.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const stageRoot = "/run/osop-native-stage"

func protectedStageRoot() error {
	if os.Getenv("OSOP_NATIVE_MCP_STAGE_ROOT") != stageRoot {
		return errors.New("operator-provisioned isolated stage root unavailable")
	}
	info, err := os.Lstat(stageRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("isolated stage root unavailable")
	}
	// Merely being on tmpfs or named /run is insufficient: the EXACT root
	// must be a mountpoint with noexec,nodev,nosuid policy. No host bind mount.
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil || len(mounts) > 1024*1024 {
		return errors.New("sandbox mount evidence unavailable")
	}
	found := false
	for _, line := range strings.Split(string(mounts), "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left := strings.Fields(parts[0])
		right := strings.Fields(parts[1])
		if len(left) < 6 || left[4] != stageRoot {
			continue
		}
		if len(right) < 3 || right[0] != "tmpfs" {
			return errors.New("sandbox root is not dedicated tmpfs")
		}
		opts := "," + left[5] + "," + right[2] + ","
		for _, flag := range []string{"noexec", "nodev", "nosuid"} {
			if !strings.Contains(opts, ","+flag+",") {
				return errors.New("sandbox tmpfs missing confinement")
			}
		}
		found = true
		break
	}
	if !found {
		return errors.New("private stage mountpoint not independently observed")
	}
	var stat syscall.Statfs_t
	if syscall.Statfs(stageRoot, &stat) != nil || uint64(stat.Type) != 0x01021994 {
		return errors.New("native stage root filesystem unavailable")
	}
	return nil
}

func stageNativeReviewedOriginal(raw []byte) (resultErr error) {
	if err := protectedStageRoot(); err != nil {
		return err
	}
	var offer nativeResourceOffer
	if err := json.Unmarshal(raw, &offer); err != nil {
		return errors.New("bounded signed source snapshot invalid")
	}
	var parsed struct {
		FolderStage nativeFolderStagePlan `json:"folder_staging"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return errors.New("approved folder stage source invalid")
	}
	// Verifier completed before staging and source plan digest is validated
	// again, independently of any client-provided absolute destination.
	planBytes, err := json.Marshal(parsed.FolderStage)
	if err != nil || verifyNativeFolderPlan(planBytes, offer) != nil {
		return errors.New("approved folder assignment not verified")
	}
	rootFD, err := syscall.Open(stageRoot, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("protected native stage root inaccessible")
	}
	defer syscall.Close(rootFD)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return errors.New("ephemeral stage identity unavailable")
	}
	stagingName := "stage-" + hex.EncodeToString(nonce)
	if err := syscall.Mkdirat(rootFD, stagingName, 0700); err != nil {
		return errors.New("ephemeral stage creation denied")
	}
	stagingPath := filepath.Join(stageRoot, stagingName)
	defer func() {
		// Path was created with a fresh random basename beneath a verified
		// private tmpfs mount. RemoveAll never traverses symlinks. On errors,
		// deny success and keep the original Action UNKNOWN/no replay.
		if err := os.RemoveAll(stagingPath); err != nil {
			resultErr = errors.New("sandbox cleanup not confirmed")
		}
	}()
	stageFD, err := syscall.Openat(rootFD, stagingName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("ephemeral stage root changed")
	}
	defer syscall.Close(stageFD)
	if err := syscall.Mkdirat(stageFD, "resources", 0700); err != nil {
		return errors.New("resource staging directory unavailable")
	}
	resourceFD, err := syscall.Openat(stageFD, "resources", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("resource staging directory changed")
	}
	defer syscall.Close(resourceFD)
	byID := map[string]nativeOfferedFile{}
	for _, f := range offer.Files {
		byID[f.ArtifactID] = f
	}
	createdFolders := map[string]bool{}
	for _, item := range parsed.FolderStage.Items {
		if !nativeFolderNameRE.MatchString(item.FolderName) {
			return errors.New("unsafe stage folder")
		}
		if !createdFolders[item.FolderName] {
			if err := syscall.Mkdirat(resourceFD, item.FolderName, 0700); err != nil {
				return errors.New("stage folder creation denied")
			}
			createdFolders[item.FolderName] = true
		}
		folderFD, err := syscall.Openat(resourceFD, item.FolderName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return errors.New("stage folder symlink denied")
		}
		original, ok := byID[item.ArtifactID]
		if !ok || !nativeSHARE.MatchString(original.SHA256) {
			syscall.Close(folderFD)
			return errors.New("source byte identity changed")
		}
		blob, err := base64.StdEncoding.Strict().DecodeString(original.ContentB64)
		if err != nil || !validNativeUntrustedText(blob) || canonicalSHA256(blob) != item.SHA256 {
			syscall.Close(folderFD)
			return errors.New("original source bytes changed before stage")
		}
		name := strings.TrimPrefix(item.RelativePath, "resources/"+item.FolderName+"/")
		if !nativeResourceFilenameRE.MatchString(name) || strings.Contains(name, "..") {
			syscall.Close(folderFD)
			return errors.New("staged leaf filename unsafe")
		}
		fd, err := syscall.Openat(folderFD, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if err != nil {
			syscall.Close(folderFD)
			return errors.New("atomic stage creation unavailable")
		}
		file := os.NewFile(uintptr(fd), name)
		written, writeErr := file.Write(blob)
		if writeErr == nil && written != len(blob) {
			writeErr = io.ErrShortWrite
		}
		if writeErr == nil {
			writeErr = file.Sync()
		}
		if writeErr == nil {
			writeErr = file.Chmod(0400)
		}
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			syscall.Close(folderFD)
			return errors.New("original resource stage incomplete")
		}
		readFD, err := syscall.Openat(folderFD, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			syscall.Close(folderFD)
			return errors.New("readonly staged resource inaccessible")
		}
		var st syscall.Stat_t
		if err := syscall.Fstat(readFD, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 {
			syscall.Close(readFD)
			syscall.Close(folderFD)
			return errors.New("stage is not unique regular read-only data")
		}
		readFile := os.NewFile(uintptr(readFD), "verified-original")
		readback, readErr := io.ReadAll(io.LimitReader(readFile, int64(len(blob)+1)))
		readFile.Close()
		syscall.Close(folderFD)
		if readErr != nil || len(readback) != len(blob) || canonicalSHA256(readback) != item.SHA256 {
			return errors.New("original stage file SHA readback mismatch")
		}
	}
	// Final manifest is created at a random temporary name and atomically
	// renamed only AFTER all leaf readbacks have succeeded.
	manifest, err := json.Marshal(parsed.FolderStage)
	if err != nil {
		return errors.New("staging manifest serialization failed")
	}
	fd, err := syscall.Openat(stageFD, ".manifest.pending", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("atomic staging manifest creation denied")
	}
	mf := os.NewFile(uintptr(fd), "manifest-pending")
	n, writeErr := mf.Write(manifest)
	if writeErr == nil && n != len(manifest) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = mf.Sync()
	}
	if writeErr == nil {
		writeErr = mf.Chmod(0400)
	}
	closeErr := mf.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("atomic manifest failed")
	}
	if err := syscall.Renameat(stageFD, ".manifest.pending", stageFD, "resource-manifest.json"); err != nil {
		return errors.New("atomic manifest publication failed")
	}
	readFD, err := syscall.Openat(stageFD, "resource-manifest.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("atomic read-only manifest unavailable")
	}
	readFile := os.NewFile(uintptr(readFD), "resource-manifest")
	readback, err := io.ReadAll(io.LimitReader(readFile, int64(len(manifest)+1)))
	readFile.Close()
	if err != nil || string(readback) != string(manifest) {
		return fmt.Errorf("atomic staging manifest readback unavailable")
	}
	return nil
}
