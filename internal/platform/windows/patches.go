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
	"regexp"
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

// InstallPatch downloads and installs the exact WUA UpdateID returned by enumeration.
// It never reboots the machine. Updates requiring EULA acceptance must first be
// approved through the organization's update management policy.
func (p *Platform) InstallPatch(ctx context.Context, patchID string) error {
	if !regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`).MatchString(patchID) {
		return fmt.Errorf("invalid Windows Update ID")
	}
	script := `$ErrorActionPreference='Stop'
$s=New-Object -ComObject Microsoft.Update.Session
$r=$s.CreateUpdateSearcher().Search("IsInstalled=0 and UpdateID='` + patchID + `'")
if($r.ResultCode -ne 2 -or $r.Updates.Count -ne 1){throw 'Exact update unavailable or search incomplete'}
$u=$r.Updates.Item(0)
if(-not $u.EulaAccepted){throw 'Update EULA must be accepted by administrator first'}
if($u.InstallationBehavior.CanRequestUserInput){throw 'Update requires interactive installation'}
$c=New-Object -ComObject Microsoft.Update.UpdateColl
[void]$c.Add($u)
$d=$s.CreateUpdateDownloader(); $d.Updates=$c
$download=$d.Download()
if($download.ResultCode -ne 2 -or -not $u.IsDownloaded){throw 'Update download failed'}
$i=$s.CreateUpdateInstaller(); $i.Updates=$c
if($i.RebootRequiredBeforeInstallation){throw 'Restart required before installation'}
$result=$i.Install()
if($result.ResultCode -ne 2 -or $result.GetUpdateResult(0).ResultCode -ne 2){throw 'Update installation failed or incomplete'}
[pscustomobject]@{success=$true;reboot_required=$result.RebootRequired}|ConvertTo-Json -Compress`
	out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return fmt.Errorf("Windows Update installation: %w", err)
	}
	var result struct {
		Success        bool `json:"success"`
		RebootRequired bool `json:"reboot_required"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("Windows Update did not confirm installation")
	}
	if result.RebootRequired {
		return fmt.Errorf("update installed; administrator restart required to complete installation")
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
