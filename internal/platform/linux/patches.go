//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/platform"
)

// isDebian returns true when apt-get is present (Debian/Ubuntu family).
func isDebian() bool {
	_, err := exec.LookPath("apt-get")
	return err == nil
}

// ListInstalledPatches returns installed packages.
// Debian/Ubuntu: parses dpkg.log for install events.
// RHEL/Fedora: queries rpm with install timestamps.
func (p *Platform) ListInstalledPatches(ctx context.Context) ([]platform.Patch, error) {
	if isDebian() {
		return listInstalledDpkg(ctx)
	}
	return listInstalledRPM(ctx)
}

// listInstalledDpkg reads /var/log/dpkg.log and returns one Patch per install line.
func listInstalledDpkg(ctx context.Context) ([]platform.Patch, error) {
	out, err := exec.CommandContext(ctx, "grep", " install ", "/var/log/dpkg.log").Output()
	if err != nil {
		// grep exits 1 when no matches — treat as empty, not error
		return []platform.Patch{}, nil
	}

	var patches []platform.Patch
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		// Format: "2024-01-15 12:34:56 install libssl1.1:amd64 <none> 1.1.1n-0+deb11u4"
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		ts, err := time.Parse("2006-01-02 15:04:05", fields[0]+" "+fields[1])
		if err != nil {
			continue
		}
		name := strings.SplitN(fields[3], ":", 2)[0] // strip :amd64 suffix
		version := fields[5]
		patches = append(patches, platform.Patch{
			ID:          name + "-" + version,
			Name:        name,
			Description: name + " " + version,
			Category:    platform.CategorySoftware,
			Severity:    platform.SeverityUnknown,
			InstalledAt: &ts,
			ReleasedAt:  ts,
		})
	}
	return patches, nil
}

// listInstalledRPM queries rpm for all installed packages with timestamps.
func listInstalledRPM(ctx context.Context) ([]platform.Patch, error) {
	out, err := exec.CommandContext(ctx, "rpm", "-qa",
		"--qf", "%{NAME}|%{VERSION}-%{RELEASE}|%{SUMMARY}|%{INSTALLTIME}\n").Output()
	if err != nil {
		return nil, fmt.Errorf("rpm query failed: %w", err)
	}

	var patches []platform.Patch
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), "|", 4)
		if len(fields) < 4 {
			continue
		}
		name, version, summary, tsStr := fields[0], fields[1], fields[2], fields[3]
		var ts time.Time
		if epoch, err := parseEpoch(tsStr); err == nil {
			ts = epoch
		}
		patches = append(patches, platform.Patch{
			ID:          name + "-" + version,
			Name:        name,
			Description: summary,
			Category:    platform.CategorySoftware,
			Severity:    platform.SeverityUnknown,
			InstalledAt: &ts,
			ReleasedAt:  ts,
		})
	}
	return patches, nil
}

// ListAvailablePatches lists packages with pending updates.
// Debian: apt-get -s upgrade; RHEL: yum check-update.
func (p *Platform) ListAvailablePatches(ctx context.Context) ([]platform.Patch, error) {
	if isDebian() {
		return listAvailableApt(ctx)
	}
	return listAvailableYum(ctx)
}

func listAvailableApt(ctx context.Context) ([]platform.Patch, error) {
	// -s = simulate (no root required); lists "Inst <pkg> ..." lines
	out, err := exec.CommandContext(ctx, "apt-get", "-s", "upgrade").Output()
	if err != nil {
		return nil, fmt.Errorf("apt-get simulate failed: %w", err)
	}

	var patches []platform.Patch
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		// "Inst libssl1.1 [1.1.1n-0+deb11u3] (1.1.1n-0+deb11u4 Debian:11 [amd64])"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[1]
		patches = append(patches, platform.Patch{
			ID:         name,
			Name:       name,
			Category:   platform.CategorySoftware,
			Severity:   platform.SeverityUnknown,
			ReleasedAt: time.Now(),
		})
	}
	return patches, nil
}

func listAvailableYum(ctx context.Context) ([]platform.Patch, error) {
	// exit 100 = updates available, 0 = none, other = error
	out, err := exec.CommandContext(ctx, "yum", "check-update", "-q").Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 100 {
			// 100 means updates exist — parse the output
			err = nil
		} else {
			return nil, fmt.Errorf("yum check-update failed: %w", err)
		}
	}

	var patches []platform.Patch
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Last metadata") {
			continue
		}
		// "openssl.x86_64   1:3.0.7-18.el9_2    baseos"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.SplitN(fields[0], ".", 2)[0]
		patches = append(patches, platform.Patch{
			ID:         name,
			Name:       name,
			Category:   platform.CategorySoftware,
			Severity:   platform.SeverityUnknown,
			ReleasedAt: time.Now(),
		})
	}
	return patches, nil
}

// InstallPatch installs a package by name using the native package manager.
func (p *Platform) InstallPatch(ctx context.Context, patchID string) error {
	patchID = strings.TrimSpace(patchID)
	if patchID == "" || strings.HasPrefix(patchID, "-") || strings.ContainsAny(patchID, "\r\n\x00") {
		return fmt.Errorf("invalid Linux patch identifier")
	}
	if isDebian() {
		return exec.CommandContext(ctx, "apt-get", "install", "-y", patchID).Run()
	}
	return exec.CommandContext(ctx, "yum", "install", "-y", patchID).Run()
}

// ListInstalledApplications returns installed packages as applications.
func (p *Platform) ListInstalledApplications(ctx context.Context) ([]platform.Application, error) {
	if isDebian() {
		return listAppsDpkg(ctx)
	}
	return listAppsRPM(ctx)
}

func listAppsDpkg(ctx context.Context) ([]platform.Application, error) {
	out, err := exec.CommandContext(ctx, "dpkg-query", "-W",
		"-f=${Package}|${Version}|${Maintainer}\n").Output()
	if err != nil {
		return nil, fmt.Errorf("dpkg-query failed: %w", err)
	}
	return parsePipeDelimitedApps(out), nil
}

func listAppsRPM(ctx context.Context) ([]platform.Application, error) {
	out, err := exec.CommandContext(ctx, "rpm", "-qa",
		"--qf", "%{NAME}|%{VERSION}-%{RELEASE}|%{VENDOR}\n").Output()
	if err != nil {
		return nil, fmt.Errorf("rpm query failed: %w", err)
	}
	return parsePipeDelimitedApps(out), nil
}

// parsePipeDelimitedApps parses "name|version|vendor" lines.
func parsePipeDelimitedApps(out []byte) []platform.Application {
	var apps []platform.Application
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), "|", 3)
		if len(fields) < 3 || fields[0] == "" {
			continue
		}
		apps = append(apps, platform.Application{
			Name:    fields[0],
			Version: fields[1],
			Vendor:  fields[2],
		})
	}
	return apps
}

// parseEpoch converts a Unix timestamp string to time.Time.
func parseEpoch(s string) (time.Time, error) {
	var epoch int64
	if _, err := fmt.Sscanf(s, "%d", &epoch); err != nil {
		return time.Time{}, err
	}
	return time.Unix(epoch, 0), nil
}
