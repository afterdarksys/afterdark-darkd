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
// WUA queries are read-only and require the Windows Update service.
func (p *Platform) ListInstalledPatches(ctx context.Context) ([]platform.Patch, error) {
	return listUpdates(ctx, true)
}
func (p *Platform) ListAvailablePatches(ctx context.Context) ([]platform.Patch, error) {
	return listUpdates(ctx, false)
}
func listUpdates(ctx context.Context, installed bool) ([]platform.Patch, error) {
	flag := "0"
	if installed {
		flag = "1"
	}
	script := `$ErrorActionPreference='Stop'; $s=New-Object -ComObject Microsoft.Update.Session; $r=$s.CreateUpdateSearcher().Search('IsInstalled=` + flag + ` and IsHidden=0'); if($r.ResultCode -ne 2){throw 'Windows Update search incomplete'}; $items=@(foreach($u in $r.Updates){[pscustomobject]@{id=$u.Identity.UpdateID;name=$u.Title;severity=$u.MsrcSeverity;released=$u.LastDeploymentChangeTime.ToUniversalTime().ToString('o')}}); ConvertTo-Json -InputObject $items -Compress`
	out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return nil, fmt.Errorf("Windows Update assessment: %w", err)
	}
	var rows []struct {
		ID, Name, Severity string
		Released           time.Time
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("Windows Update response: %w", err)
	}
	patches := make([]platform.Patch, 0, len(rows))
	for _, r := range rows {
		sev := platform.SeverityUnknown
		switch r.Severity {
		case "Critical":
			sev = platform.SeverityCritical
		case "Important":
			sev = platform.SeverityImportant
		case "Moderate":
			sev = platform.SeverityModerate
		case "Low":
			sev = platform.SeverityLow
		}
		patches = append(patches, platform.Patch{ID: r.ID, Name: r.Name, Severity: sev, ReleasedAt: r.Released})
	}
	return patches, nil
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
