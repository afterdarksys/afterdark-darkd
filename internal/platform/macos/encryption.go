//go:build darwin

package macos

import (
	"os/exec"
	"strings"
)

// GetDiskEncryptionStatus returns FileVault encryption status.
// Returns (true, "enabled") when FileVault is on, (false, <status>) otherwise.
func GetDiskEncryptionStatus() (enabled bool, status string) {
	out, err := exec.Command("fdesetup", "status").Output()
	if err != nil {
		return false, "unknown"
	}
	s := strings.TrimSpace(string(out))
	if strings.Contains(s, "FileVault is On") {
		return true, "enabled"
	}
	return false, s
}
