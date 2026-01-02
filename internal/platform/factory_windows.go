//go:build windows

package platform

import (
	"github.com/afterdarksys/afterdark-darkd/internal/platform/windows"
)

// NewWindows creates a new Windows platform
func NewWindows() (Platform, error) {
	return windows.New()
}
