//go:build windows

package windows

import (
	"os/exec"
	"strings"
)

// GetDiskEncryptionStatus checks BitLocker protection status on the C: drive.
// Returns (true, "bitlocker-enabled") when protection is on.
func GetDiskEncryptionStatus() (enabled bool, status string) {
	out, err := exec.Command("manage-bde", "-status", "C:").Output()
	if err != nil {
		return false, "unknown"
	}
	s := string(out)
	if strings.Contains(s, "Protection On") {
		return true, "bitlocker-enabled"
	}
	return false, "bitlocker-disabled"
}
