//go:build linux

package platform

import (
	"github.com/afterdarksys/afterdark-darkd/internal/platform/linux"
)

// NewLinux creates a new Linux platform
func NewLinux() (Platform, error) {
	return linux.New()
}
