//go:build !windows

package ipc

import (
	"fmt"
	"net"
)

// createWindowsListener is a compile-time stub on non-Windows platforms.
// It is never called at runtime (createListener only dispatches here when
// runtime.GOOS == "windows"), but must exist so the package compiles on all
// platforms.
func (s *Server) createWindowsListener() (net.Listener, error) {
	return nil, fmt.Errorf("Windows named pipes are unavailable on this platform")
}
