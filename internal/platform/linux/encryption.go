//go:build linux

package linux

import (
	"os/exec"
	"strings"
)

// GetDiskEncryptionStatus checks for LUKS-encrypted block devices via lsblk.
// Returns (true, "luks-enabled") if any crypt-type device is found.
func GetDiskEncryptionStatus() (enabled bool, status string) {
	out, err := exec.Command("lsblk", "-o", "NAME,TYPE").Output()
	if err != nil {
		return false, "unknown"
	}
	if strings.Contains(string(out), "crypt") {
		return true, "luks-enabled"
	}
	return false, "no-encryption-detected"
}
