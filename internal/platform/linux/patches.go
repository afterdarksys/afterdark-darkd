//go:build linux

package linux

import (
	"context"
	"fmt"

	"github.com/afterdarksys/afterdark-darkd/internal/platform"
)

// ListInstalledPatches returns a list of installed patches/updates
func (p *Platform) ListInstalledPatches(ctx context.Context) ([]platform.Patch, error) {
	// TODO: Implement using apt/yum/dnf logs or queries
	// Debian/Ubuntu: grep " install " /var/log/dpkg.log
	// RHEL: rpm -qa --last
	return []platform.Patch{}, nil
}

// ListAvailablePatches returns a list of available updates
func (p *Platform) ListAvailablePatches(ctx context.Context) ([]platform.Patch, error) {
	// TODO: Implement using apt-get -s upgrade or yum check-update
	return []platform.Patch{}, nil
}

// InstallPatch installs a specific patch by ID
func (p *Platform) InstallPatch(ctx context.Context, patchID string) error {
	// TODO: Implement using package manager
	return fmt.Errorf("not implemented on linux yet")
}

// ListInstalledApplications returns installed applications
func (p *Platform) ListInstalledApplications(ctx context.Context) ([]platform.Application, error) {
	// TODO: Implement using dpkg/rpm
	return []platform.Application{}, nil
}
