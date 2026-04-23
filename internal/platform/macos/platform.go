//go:build darwin

package macos

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

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

// GetNetworkInterfaces returns network interfaces using net.Interfaces()
func (p *Platform) GetNetworkInterfaces() ([]platform.NetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var result []platform.NetworkInterface
	for _, iface := range ifaces {
		ni := platform.NetworkInterface{
			Name:       iface.Name,
			MACAddress: iface.HardwareAddr.String(),
			Status:     iface.Flags.String(),
		}
		addrs, _ := iface.Addrs()
		if len(addrs) > 0 {
			ni.IPAddress = addrs[0].String()
		}
		result = append(result, ni)
	}
	return result, nil
}

// GetPublicIP returns the public IP address by querying an external service
func (p *Platform) GetPublicIP(ctx context.Context) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// SetDNSServers configures DNS servers using networksetup
func (p *Platform) SetDNSServers(servers []string) error {
	// Discover active network service names via networksetup -listallnetworkservices
	out, err := exec.CommandContext(context.Background(), "networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return fmt.Errorf("networksetup -listallnetworkservices: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var lastErr error
	applied := 0
	for _, svc := range lines {
		svc = strings.TrimSpace(svc)
		if svc == "" || strings.HasPrefix(svc, "*") || strings.Contains(svc, "network services") {
			continue
		}
		args := append([]string{"-setdnsservers", svc}, servers...)
		if err := exec.CommandContext(context.Background(), "networksetup", args...).Run(); err == nil {
			applied++
		} else {
			lastErr = err
		}
	}
	if applied == 0 && lastErr != nil {
		return fmt.Errorf("failed to set DNS on any interface: %w", lastErr)
	}
	return nil
}

// EnableFirewall enables the macOS application firewall
func (p *Platform) EnableFirewall() error {
	return exec.CommandContext(context.Background(),
		"/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on").Run()
}

// DisableICMP controls ICMP redirect responses via sysctl.
// When enabled is true, ICMP redirects are dropped (hardening on).
// When enabled is false, the sysctl is restored to the default permissive value.
func (p *Platform) DisableICMP(enabled bool) error {
	value := "1"
	if !enabled {
		value = "0"
	}
	return exec.CommandContext(context.Background(),
		"sysctl", "-w", fmt.Sprintf("net.inet.icmp.drop_redirect=%s", value)).Run()
}

// BlockIPFragmentation controls IP fragmentation via pfctl.
// When enabled is true, a pf rule is loaded to block non-SYN TCP/UDP fragments.
// When enabled is false, the anchor rule is flushed.
func (p *Platform) BlockIPFragmentation(enabled bool) error {
	if !enabled {
		return exec.CommandContext(context.Background(),
			"pfctl", "-a", "afterdark/frag", "-F", "rules").Run()
	}
	rule := "block in quick on any proto { tcp udp } from any to any flags !SF/SFRA\n"
	cmd := exec.CommandContext(context.Background(), "pfctl", "-a", "afterdark/frag", "-f", "-")
	cmd.Stdin = strings.NewReader(rule)
	return cmd.Run()
}
