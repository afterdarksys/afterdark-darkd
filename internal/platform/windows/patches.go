//go:build windows

package windows

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/platform"
)

// powershellCSV runs a PowerShell command that outputs CSV and returns the rows
// (header row excluded).
func powershellCSV(ctx context.Context, script string) ([][]string, error) {
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive",
		"-Command", script).Output()
	if err != nil {
		return nil, fmt.Errorf("powershell: %w", err)
	}
	r := csv.NewReader(bytes.NewReader(out))
	// Skip header
	if _, err := r.Read(); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	return r.ReadAll()
}

// ListInstalledPatches returns installed Windows hotfixes via PowerShell Get-HotFix.
func (p *Platform) ListInstalledPatches(ctx context.Context) ([]platform.Patch, error) {
	return listUpdates(ctx, true)
}

// classifyKB assigns severity based on KB article prefix patterns (best-effort).
func classifyKB(id string) platform.PatchSeverity {
	// No reliable severity data from Get-HotFix alone.
	return platform.SeverityUnknown
}

// ListAvailablePatches queries the Windows Update Agent COM object for pending updates.
func (p *Platform) ListAvailablePatches(ctx context.Context) ([]platform.Patch, error) {
	return listUpdates(ctx, false)
}

// InstallPatch installs a Windows update by KB article ID using wusa.exe.
// Requires the update .msu to be on disk, or falls back to DISM for in-box components.
func (p *Platform) InstallPatch(ctx context.Context, patchID string) error {
	// TODO: Implement using Windows Update Agent API
	return fmt.Errorf("not implemented on windows yet")
}

// ListInstalledApplications returns installed applications from the Uninstall registry hive.
func (p *Platform) ListInstalledApplications(ctx context.Context) ([]platform.Application, error) {
	script := `
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
  Where-Object { $_.DisplayName } |
  Select-Object DisplayName,DisplayVersion,Publisher,InstallDate |
  ConvertTo-Csv -NoTypeInformation
`
	rows, err := powershellCSV(ctx, strings.TrimSpace(script))
	if err != nil {
		return nil, err
	}

	apps := make([]platform.Application, 0, len(rows))
	for _, row := range rows {
		if len(row) < 4 {
			continue
		}
		name := strings.TrimSpace(row[0])
		if name == "" {
			continue
		}
		app := platform.Application{
			Name:    name,
			Version: strings.TrimSpace(row[1]),
			Vendor:  strings.TrimSpace(row[2]),
		}
		// InstallDate format: "20240115" (YYYYMMDD)
		if d := strings.TrimSpace(row[3]); len(d) == 8 {
			if t, err := time.Parse("20060102", d); err == nil {
				app.InstallDate = t
			}
		}
		apps = append(apps, app)
	}
	return apps, nil
}

// readCSV is a helper used in the scanner loop.
func readCSV(r io.Reader) ([][]string, error) {
	return csv.NewReader(r).ReadAll()
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
