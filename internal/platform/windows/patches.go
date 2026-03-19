//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

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
	var apps []platform.Application

	// Run PowerShell command to extract list from registry
	psCmd := `Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object { $_.DisplayName -ne $null } | ConvertTo-Json -Compress`
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list windows applications: %w", err)
	}

	type psApp struct {
		DisplayName    string `json:"DisplayName"`
		DisplayVersion string `json:"DisplayVersion"`
		Publisher      string `json:"Publisher"`
		InstallDate    string `json:"InstallDate"` // Format is often YYYYMMDD
	}

	var parsedApps []psApp
	if err := json.Unmarshal(output, &parsedApps); err != nil {
		// Might be a single object instead of array if there's only one app
		var singleApp psApp
		if jsonErr := json.Unmarshal(output, &singleApp); jsonErr != nil {
			return apps, nil // Cannot parse
		}
		parsedApps = append(parsedApps, singleApp)
	}

	for _, pa := range parsedApps {
		if pa.DisplayName == "" {
			continue
		}
		
		var installed time.Time
		if len(pa.InstallDate) == 8 {
			installed, _ = time.Parse("20060102", pa.InstallDate)
		}
		
		apps = append(apps, platform.Application{
			Name:        pa.DisplayName,
			Version:     pa.DisplayVersion,
			Vendor:      pa.Publisher,
			InstallDate: installed,
		})
	}

	return apps, nil
}
