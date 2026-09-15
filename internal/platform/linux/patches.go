//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/afterdarksys/afterdark-darkd/internal/platform/packages"
	"os/exec"
	"strings"

	"github.com/afterdarksys/afterdark-darkd/internal/platform"
)

// ListInstalledPatches returns a list of installed patches/updates
func (p *Platform) ListInstalledPatches(ctx context.Context) ([]platform.Patch, error) {
	var cmd *exec.Cmd
	switch p.distro {
	case "ubuntu", "debian":
		cmd = exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package}|||${Version}\n")
	case "rhel", "centos", "rocky", "almalinux", "fedora":
		cmd = exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{NAME}.%{ARCH}|||%{VERSION}-%{RELEASE}\n")
	default:
		return nil, fmt.Errorf("unsupported package manager for %s", p.distro)
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("installed packages: %w", err)
	}
	return packages.Installed(string(out))
}
func (p *Platform) ListAvailablePatches(ctx context.Context) ([]platform.Patch, error) {
	switch p.distro {
	case "ubuntu", "debian":
		out, err := exec.CommandContext(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade").Output()
		if err != nil {
			return nil, fmt.Errorf("apt assessment: %w", err)
		}
		return packages.APT(string(out))
	case "rhel", "centos", "rocky", "almalinux", "fedora":
		out, err := exec.CommandContext(ctx, "dnf", "-q", "--cacheonly", "check-update").Output()
		var exit *exec.ExitError
		if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 100) {
			return nil, fmt.Errorf("dnf assessment: %w", err)
		}
		updates, err := packages.DNF(string(out))
		if exit != nil && exit.ExitCode() == 100 && len(updates) == 0 {
			return nil, fmt.Errorf("dnf reported updates but no candidates could be parsed")
		}
		return updates, err
	default:
		return nil, fmt.Errorf("unsupported package manager for %s", p.distro)
	}
}

// InstallPatch installs a specific patch by ID
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

// ListInstalledApplications returns installed applications
func (p *Platform) ListInstalledApplications(ctx context.Context) ([]platform.Application, error) {
	if isDebian() {
		return listAppsDpkg(ctx)
	}
	return listAppsRPM(ctx)
}

func isDebian() bool {
	_, err := exec.LookPath("apt-get")
	return err == nil
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
