//go:build windows

package factory

import (
	"github.com/afterdarksys/afterdark-darkd/internal/platform"
	"github.com/afterdarksys/afterdark-darkd/internal/platform/windows"
)

func newPlatform() (platform.Platform, error) {
	return windows.New()
}
