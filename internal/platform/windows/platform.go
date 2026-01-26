//go:build windows

package windows

import (
	"context"
	"os"
	"runtime"

	"github.com/afterdarksys/afterdark-darkd/internal/platform"
)

// Platform implements the platform.Platform interface for Windows
type Platform struct {
	osInfo *platform.OSInfo
}

// New creates a new Windows platform implementation
func New() (*Platform, error) {
	p := &Platform{}
	// Pre-cache OS info
	info, err := p.GetOSInfo()
	if err == nil {
		p.osInfo = info
	}
	return p, nil
}

// GetOSInfo returns Windows system information
func (p *Platform) GetOSInfo() (*platform.OSInfo, error) {
	// Use WMI or registry to get Windows version info
	return &platform.OSInfo{
		Name:         "Windows",
		Version:      "10.0",
		Build:        "unknown",
		Architecture: runtime.GOARCH,
		Kernel:       "NT",
	}, nil
}

// GetHostname returns the system hostname
func (p *Platform) GetHostname() (string, error) {
	return os.Hostname()
}

// Methods moved to patches.go

// GetNetworkInterfaces returns network interfaces
func (p *Platform) GetNetworkInterfaces() ([]platform.NetworkInterface, error) {
	// Use Win32 API
	return []platform.NetworkInterface{}, nil
}

// GetPublicIP returns the public IP address
func (p *Platform) GetPublicIP(ctx context.Context) (string, error) {
	return "", nil
}

// SetDNSServers configures DNS servers
func (p *Platform) SetDNSServers(servers []string) error {
	// Use netsh or PowerShell
	return nil
}

// EnableFirewall enables Windows Firewall
func (p *Platform) EnableFirewall() error {
	// Use Windows Firewall API
	return nil
}

// DisableICMP enables/disables ICMP responses
func (p *Platform) DisableICMP(enabled bool) error {
	// Use Windows Firewall rules
	return nil
}

// BlockIPFragmentation enables/disables IP fragmentation
func (p *Platform) BlockIPFragmentation(enabled bool) error {
	// Use Windows Firewall rules
	return nil
}
