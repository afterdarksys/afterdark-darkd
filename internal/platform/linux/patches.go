//go:build linux

package linux

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

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
