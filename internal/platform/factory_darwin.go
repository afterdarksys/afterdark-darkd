//go:build darwin

package platform

import (
	"github.com/afterdarksys/afterdark-darkd/internal/platform/macos"
)

// NewMacOS creates a new macOS platform
func NewMacOS() (Platform, error) {
	return macos.New()
}
