//go:build !linux

package sdk

import "errors"

// Windows temp directories and platform-agnostic host paths are NOT an OS
// sandbox. Keep the old RAM-only diagnostic when no 0026 folder stage was
// independently approved; refuse filesystem staging on unsupported hosts.
func stageNativeReviewedOriginal(_ []byte) error {
	return errors.New("independently isolated tmpfs sandbox unavailable on host")
}
