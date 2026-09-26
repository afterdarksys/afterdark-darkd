//go:build windows

package control

import "os"

// Windows ACLs are not modelled here, so the daemon-side key check fails
// closed. Signing (LoadPrivateKey) still works for offline use.
const privateKeyModeCheck = false

func fileOwner(os.FileInfo) (uint32, bool) { return 0, false }

func openNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrPermission}
	}
	return os.Open(path)
}
