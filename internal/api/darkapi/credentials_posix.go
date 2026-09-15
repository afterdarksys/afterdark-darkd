//go:build !windows

package darkapi

import (
	"fmt"
	"os"
)

func secureCredentialFile(path string) error { return os.Chmod(path, 0600) }
func checkCredentialPermissions(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("credential file must have mode 0600")
	}
	return nil
}
