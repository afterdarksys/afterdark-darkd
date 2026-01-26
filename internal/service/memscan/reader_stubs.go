//go:build !linux

package memscan

import (
	"go.uber.org/zap"
)

// NewLinuxReader creates a dummy Linux reader
func NewLinuxReader(logger *zap.Logger) (MemoryReader, error) {
	return nil, nil // Placeholder
}
