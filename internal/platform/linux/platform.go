//go:build linux

package linux

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/afterdarksys/afterdark-darkd/internal/platform"
)

// Platform implements the platform.Platform interface for Linux
type Platform struct {
	distro string
}

// New creates a new Linux platform implementation
func New() (*Platform, error) {
	distro := detectDistro()
	return &Platform{distro: distro}, nil
}

func detectDistro() string {
	// Check for /etc/os-release
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ID=") {
			return strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		}
	}
	return "unknown"
}

// GetOSInfo returns Linux system information
func (p *Platform) GetOSInfo() (*platform.OSInfo, error) {
	// Get kernel version
	kernelOut, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return nil, err
	}

	// Get OS name and version from /etc/os-release
	name := "Linux"
	version := "unknown"
	build := ""

	data, err := os.ReadFile("/etc/os-release")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "NAME=") {
				name = strings.Trim(strings.TrimPrefix(line, "NAME="), "\"")
			}
			if strings.HasPrefix(line, "VERSION_ID=") {
				version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
			}
			if strings.HasPrefix(line, "BUILD_ID=") {
				build = strings.Trim(strings.TrimPrefix(line, "BUILD_ID="), "\"")
			}
		}
	}

	return &platform.OSInfo{
		Name:         name,
		Version:      version,
		Build:        build,
		Architecture: runtime.GOARCH,
		Kernel:       strings.TrimSpace(string(kernelOut)),
	}, nil
}

// GetHostname returns the system hostname
func (p *Platform) GetHostname() (string, error) {
	return os.Hostname()
}

// ListInstalledPatches returns installed Linux packages/updates
func (p *Platform) ListInstalledPatches(ctx context.Context) ([]platform.Patch, error) {
	switch p.distro {
	case "debian", "ubuntu":
		return p.listDebianPatches(ctx)
	case "rhel", "rocky", "centos", "fedora":
		return p.listRHELPatches(ctx)
	default:
		return []platform.Patch{}, nil
	}
}

func (p *Platform) listDebianPatches(ctx context.Context) ([]platform.Patch, error) {
	// Use dpkg or apt to list packages
	return []platform.Patch{}, nil
}

func (p *Platform) listRHELPatches(ctx context.Context) ([]platform.Patch, error) {
	// Use rpm or yum/dnf to list packages
	return []platform.Patch{}, nil
}

// ListAvailablePatches returns available Linux updates
func (p *Platform) ListAvailablePatches(ctx context.Context) ([]platform.Patch, error) {
	switch p.distro {
	case "debian", "ubuntu":
		return p.listDebianAvailable(ctx)
	case "rhel", "rocky", "centos", "fedora":
		return p.listRHELAvailable(ctx)
	default:
		return []platform.Patch{}, nil
	}
}

func (p *Platform) listDebianAvailable(ctx context.Context) ([]platform.Patch, error) {
	// Use apt-get upgrade --dry-run or apt list --upgradable
	return []platform.Patch{}, nil
}

func (p *Platform) listRHELAvailable(ctx context.Context) ([]platform.Patch, error) {
	// Use yum check-update or dnf check-update
	return []platform.Patch{}, nil
}

// InstallPatch installs a specific package/update
func (p *Platform) InstallPatch(ctx context.Context, patchID string) error {
	// Use apt-get or yum/dnf
	return nil
}

// ListInstalledApplications returns installed applications
func (p *Platform) ListInstalledApplications(ctx context.Context) ([]platform.Application, error) {
	// Use package manager to list installed packages
	return []platform.Application{}, nil
}

// GetNetworkInterfaces returns network interfaces
func (p *Platform) GetNetworkInterfaces() ([]platform.NetworkInterface, error) {
	// Use ip addr or /sys/class/net
	return []platform.NetworkInterface{}, nil
}

// GetPublicIP returns the public IP address
func (p *Platform) GetPublicIP(ctx context.Context) (string, error) {
	return "", nil
}

// SetDNSServers configures DNS servers
func (p *Platform) SetDNSServers(servers []string) error {
	// Modify /etc/resolv.conf or use systemd-resolved
	return nil
}

// EnableFirewall enables the Linux firewall
func (p *Platform) EnableFirewall() error {
	// Use iptables or firewalld
	return nil
}

// DisableICMP enables/disables ICMP responses
func (p *Platform) DisableICMP(enabled bool) error {
	// Use sysctl or iptables
	return nil
}

// BlockIPFragmentation enables/disables IP fragmentation
func (p *Platform) BlockIPFragmentation(enabled bool) error {
	// Use iptables
	return nil
}
