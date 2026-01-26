//go:build darwin

package macos

import (
	"context"
	"os"
	"runtime"

	"github.com/afterdarksys/afterdark-darkd/internal/platform"
	"golang.org/x/sys/unix"
	"howett.net/plist"
)

// Platform implements the platform.Platform interface for macOS
type Platform struct {
	osInfo *platform.OSInfo
}

// New creates a new macOS platform implementation
func New() (*Platform, error) {
	p := &Platform{}
	// Pre-cache OS info
	info, err := p.GetOSInfo()
	if err == nil {
		p.osInfo = info
	}
	return p, nil
}

// SystemVersionPlist represents /System/Library/CoreServices/SystemVersion.plist
type SystemVersionPlist struct {
	ProductBuildVersion string `plist:"ProductBuildVersion"`
	ProductName         string `plist:"ProductName"`
	ProductVersion      string `plist:"ProductVersion"`
}

// GetOSInfo returns macOS system information using native APIs
// instead of exec.Command("sw_vers") and exec.Command("uname")
func (p *Platform) GetOSInfo() (*platform.OSInfo, error) {
	// Read SystemVersion.plist instead of calling sw_vers
	plistPath := "/System/Library/CoreServices/SystemVersion.plist"
	file, err := os.Open(plistPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var sysVer SystemVersionPlist
	decoder := plist.NewDecoder(file)
	if err := decoder.Decode(&sysVer); err != nil {
		return nil, err
	}

	// Get kernel version using unix.Uname instead of exec.Command("uname")
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return nil, err
	}

	// Convert [256]byte to string (darwin uses byte arrays)
	kernelVersion := byteArrayToString(uname.Release[:])

	return &platform.OSInfo{
		Name:         sysVer.ProductName,
		Version:      sysVer.ProductVersion,
		Build:        sysVer.ProductBuildVersion,
		Architecture: runtime.GOARCH,
		Kernel:       kernelVersion,
	}, nil
}

// byteArrayToString converts a null-terminated byte array to string
func byteArrayToString(arr []byte) string {
	for i, b := range arr {
		if b == 0 {
			return string(arr[:i])
		}
	}
	return string(arr)
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

// GetNetworkInterfaces returns network interfaces
func (p *Platform) GetNetworkInterfaces() ([]platform.NetworkInterface, error) {
	// Use ifconfig or networksetup
	// This is a stub implementation
	return []platform.NetworkInterface{}, nil
}

// GetPublicIP returns the public IP address
func (p *Platform) GetPublicIP(ctx context.Context) (string, error) {
	// Query external service for public IP
	// This is a stub implementation
	return "", nil
}

// SetDNSServers configures DNS servers
func (p *Platform) SetDNSServers(servers []string) error {
	// Use networksetup -setdnsservers
	// This is a stub implementation
	return nil
}

// EnableFirewall enables the macOS firewall
func (p *Platform) EnableFirewall() error {
	// Use socketfilterfw
	// This is a stub implementation
	return nil
}

// DisableICMP enables/disables ICMP responses
func (p *Platform) DisableICMP(enabled bool) error {
	// Use sysctl or pfctl
	// This is a stub implementation
	return nil
}

// BlockIPFragmentation enables/disables IP fragmentation
func (p *Platform) BlockIPFragmentation(enabled bool) error {
	// Use pfctl
	// This is a stub implementation
	return nil
}
