package factory

import (
	"github.com/afterdarksys/afterdark-darkd/internal/platform"
)

// New creates a new platform instance
func New() (platform.Platform, error) {
	return newPlatform()
}
