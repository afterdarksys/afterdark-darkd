//go:build linux

package linux

import (
	"context"
	"os"
	"runtime"
	"strings"
	"syscall"

	"github.com/afterdarksys/afterdark-darkd/internal/platform"
)

// Platform implements the platform.Platform interface for Linux
type Platform struct {
	distro string
	osInfo *platform.OSInfo
}

// New creates a new Linux platform implementation
func New() (*Platform, error) {
	distro := detectDistro()
	p := &Platform{distro: distro}
	// Pre-cache OS info
	info, err := p.GetOSInfo()
	if err == nil {
		p.osInfo = info
	}
	return p, nil
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

// GetOSInfo returns Linux system information using native APIs
// instead of exec.Command("uname")
func (p *Platform) GetOSInfo() (*platform.OSInfo, error) {
	// Get kernel version using syscall.Uname instead of exec.Command("uname")
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return nil, err
	}

	// Convert [65]int8 to string (Linux uses 65-byte arrays)
	kernelVersion := int8ArrayToString(uname.Release[:])

	// Get OS name and version from /etc/os-release (already native)
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
		Kernel:       kernelVersion,
	}, nil
}

// int8ArrayToString converts a null-terminated int8 array to string
func int8ArrayToString(arr []int8) string {
	b := make([]byte, 0, len(arr))
	for _, v := range arr {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

// GetHostname returns the system hostname
func (p *Platform) GetHostname() (string, error) {
	return os.Hostname()
}

// Methods moved to patches.go

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
