//go:build !darwin

package memscan

import (
	"go.uber.org/zap"
)

// NewDarwinReader creates a dummy Darwin reader for non-Darwin platforms
func NewDarwinReader(logger *zap.Logger) (MemoryReader, error) {
	return nil, nil // Placeholder
}
