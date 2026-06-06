//go:build !windows

package ipc

import "net"

// createWindowsListener is a compile-time stub on non-Windows platforms.
// It is never called at runtime (createListener only dispatches here when
// runtime.GOOS == "windows"), but must exist so the package compiles on all
// platforms.
func (s *Server) createWindowsListener() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}
