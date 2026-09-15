//go:build linux

package linux

import (
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
	// TODO: Implement using package manager
	return fmt.Errorf("not implemented on linux yet")
}

// ListInstalledApplications returns installed applications
func (p *Platform) ListInstalledApplications(ctx context.Context) ([]platform.Application, error) {
	var apps []platform.Application

	if p.distro == "ubuntu" || p.distro == "debian" {
		cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package}|||${Version}\n")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				parts := strings.Split(line, "|||")
				if len(parts) == 2 {
					apps = append(apps, platform.Application{
						Name:    strings.TrimSpace(parts[0]),
						Version: strings.TrimSpace(parts[1]),
						Vendor:  "Debian/Ubuntu",
					})
				}
			}
		}
	} else {
		// RPM-based (RHEL, Rocky, Fedora)
		cmd := exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{NAME}|||%{VERSION}-%{RELEASE}\n")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				parts := strings.Split(line, "|||")
				if len(parts) == 2 {
					apps = append(apps, platform.Application{
						Name:    strings.TrimSpace(parts[0]),
						Version: strings.TrimSpace(parts[1]),
						Vendor:  "RedHat/Rocky",
					})
				}
			}
		}
	}
	return apps, nil
}
