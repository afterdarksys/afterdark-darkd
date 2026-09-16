//go:build !windows

package darkapi

import (
	"fmt"
	"os"
	"path/filepath"
)

func secureCredentialFile(path string) error { return os.Chmod(path, 0600) }
func checkCredentialPermissions(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("credential file must have mode 0600")
	}
	return nil
}

func syncCredentialDirectory(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func replaceCredential(source, target string) error {
	if err := os.Rename(source, target); err != nil {
		return err
	}
	return syncCredentialDirectory(target)
}
