//go:build darwin

package factory

import (
	"github.com/afterdarksys/afterdark-darkd/internal/platform"
	"github.com/afterdarksys/afterdark-darkd/internal/platform/macos"
)

func newPlatform() (platform.Platform, error) {
	return macos.New()
}
