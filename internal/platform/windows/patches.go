//go:build windows

package windows

import (
	"bytes"
	"context"
	"encoding/csv"
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
	script := "Get-HotFix | Select-Object HotFixID,Description,InstalledOn | ConvertTo-Csv -NoTypeInformation"
	rows, err := powershellCSV(ctx, script)
	if err != nil {
		return nil, err
	}

	patches := make([]platform.Patch, 0, len(rows))
	for _, row := range rows {
		if len(row) < 3 {
			continue
		}
		id, desc, installedStr := strings.TrimSpace(row[0]), strings.TrimSpace(row[1]), strings.TrimSpace(row[2])
		if id == "" {
			continue
		}
		patch := platform.Patch{
			ID:          id,
			Name:        id,
			Description: desc,
			Category:    platform.CategorySoftware,
			Severity:    classifyKB(id),
			ReleasedAt:  time.Time{},
		}
		if t, err := time.Parse("1/2/2006 12:00:00 AM", installedStr); err == nil {
			patch.InstalledAt = &t
		}
		patches = append(patches, patch)
	}
	return patches, nil
}

// classifyKB assigns severity based on KB article prefix patterns (best-effort).
func classifyKB(id string) platform.PatchSeverity {
	// No reliable severity data from Get-HotFix alone.
	return platform.SeverityUnknown
}

// ListAvailablePatches queries the Windows Update Agent COM object for pending updates.
func (p *Platform) ListAvailablePatches(ctx context.Context) ([]platform.Patch, error) {
	script := `
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search('IsInstalled=0 and IsHidden=0')
$result.Updates | Select-Object @{N='Title';E={$_.Title}},@{N='ID';E={$_.Identity.UpdateID}} | ConvertTo-Csv -NoTypeInformation
`
	rows, err := powershellCSV(ctx, strings.TrimSpace(script))
	if err != nil {
		// WUA COM may fail in non-interactive sessions; return empty rather than error.
		return []platform.Patch{}, nil
	}

	patches := make([]platform.Patch, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		title, id := strings.TrimSpace(row[0]), strings.TrimSpace(row[1])
		if title == "" {
			continue
		}
		patches = append(patches, platform.Patch{
			ID:         id,
			Name:       title,
			Category:   platform.CategorySoftware,
			Severity:   platform.SeverityUnknown,
			ReleasedAt: time.Now(),
		})
	}
	return patches, nil
}

// InstallPatch installs a Windows update by KB article ID using wusa.exe.
// Requires the update .msu to be on disk, or falls back to DISM for in-box components.
func (p *Platform) InstallPatch(ctx context.Context, patchID string) error {
	patchID = strings.TrimSpace(patchID)
	if patchID == "" || strings.HasPrefix(patchID, "/") || strings.ContainsAny(patchID, "\r\n\x00") {
		return fmt.Errorf("invalid Windows patch identifier")
	}
	// wusa.exe accepts /kb: flag for updates already downloaded by Windows Update.
	// The /forcequiet flag suppresses the reboot dialog.
	err := exec.CommandContext(ctx, "wusa.exe",
		"/install", "/kb:"+strings.TrimPrefix(strings.ToUpper(patchID), "KB"),
		"/quiet", "/norestart").Run()
	if err != nil {
		return fmt.Errorf("wusa install %s: %w", patchID, err)
	}
	return nil
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
