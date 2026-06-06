//go:build windows

package ipc

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"go.uber.org/zap"
)

// createWindowsListener creates a Windows named pipe listener using go-winio.
// The pipe DACL restricts access to Local System and Administrators only.
func (s *Server) createWindowsListener() (net.Listener, error) {
	pipeName := s.config.PipeName
	if pipeName == "" {
		pipeName = DefaultWindowsPipeName
	}

	cfg := &winio.PipeConfig{
		// D:P — DACL, protected. GA = GENERIC_ALL.
		// SY = Local System, BA = Built-in Administrators.
		SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)",
	}

	ln, err := winio.ListenPipe(pipeName, cfg)
	if err != nil {
		return nil, fmt.Errorf("named pipe %s: %w", pipeName, err)
	}

	s.logger.Info("listening on Windows named pipe", zap.String("pipe", pipeName))
	return ln, nil
}
