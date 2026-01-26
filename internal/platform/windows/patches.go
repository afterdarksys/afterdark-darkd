//go:build windows

package windows

import (
	"context"
	"fmt"

	"github.com/afterdarksys/afterdark-darkd/internal/platform"
)

// ListInstalledPatches returns a list of installed patches/updates
func (p *Platform) ListInstalledPatches(ctx context.Context) ([]platform.Patch, error) {
	// TODO: Implement using WMI or PSWindowsUpdate
	// Get-WmiObject -Class Win32_QuickFixEngineering
	return []platform.Patch{}, nil
}

// ListAvailablePatches returns a list of available updates
func (p *Platform) ListAvailablePatches(ctx context.Context) ([]platform.Patch, error) {
	// TODO: Implement using Windows Update Agent API or PSWindowsUpdate
	return []platform.Patch{}, nil
}

// InstallPatch installs a specific patch by ID
func (p *Platform) InstallPatch(ctx context.Context, patchID string) error {
	// TODO: Implement using Windows Update Agent API
	return fmt.Errorf("not implemented on windows yet")
}

// ListInstalledApplications returns installed applications
func (p *Platform) ListInstalledApplications(ctx context.Context) ([]platform.Application, error) {
	// TODO: Implement using Registry keys
	// HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall
	return []platform.Application{}, nil
}
