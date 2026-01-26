//go:build !windows

package memscan

import (
	"go.uber.org/zap"
)

// NewWindowsReader creates a dummy Windows reader for non-Windows platforms
func NewWindowsReader(logger *zap.Logger) (MemoryReader, error) {
	return nil, nil // Placeholder
}
