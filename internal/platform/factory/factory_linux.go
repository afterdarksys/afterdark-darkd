//go:build linux

package factory

import (
	"github.com/afterdarksys/afterdark-darkd/internal/platform"
	"github.com/afterdarksys/afterdark-darkd/internal/platform/linux"
)

func newPlatform() (platform.Platform, error) {
	return linux.New()
}
