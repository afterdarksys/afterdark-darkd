//go:build !darwin && !linux && !windows

package factory

import (
	"runtime"

	"github.com/afterdarksys/afterdark-darkd/internal/platform"
)

func newPlatform() (platform.Platform, error) {
	return nil, &platform.ErrUnsupportedPlatform{OS: runtime.GOOS}
}
