//go:build darwin

package macos

import (
	"context"
	"errors"
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

// GetNetworkInterfaces enumerates network interfaces using the stdlib net package.
func (p *Platform) GetNetworkInterfaces() ([]platform.NetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	result := make([]platform.NetworkInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		ni := platform.NetworkInterface{
			Name:       iface.Name,
			MACAddress: iface.HardwareAddr.String(),
		}
		if iface.Flags&net.FlagUp != 0 {
			ni.Status = "up"
		} else {
			ni.Status = "down"
		}
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip != nil && ip.To4() != nil {
					ni.IPAddress = ip.String()
					break
				}
			}
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

// SetDNSServers configures DNS on all active network services via networksetup.
// Requires root on macOS 10.15+.
func (p *Platform) SetDNSServers(servers []string) error {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return fmt.Errorf("listing network services: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	// Skip the header line that explains the asterisk notation.
	if len(lines) > 0 && strings.HasPrefix(lines[0], "An asterisk") {
		lines = lines[1:]
	}
	var errs []error
	for _, svc := range lines {
		svc = strings.TrimPrefix(svc, "*")
		svc = strings.TrimSpace(svc)
		if svc == "" {
			continue
		}
		args := append([]string{"-setdnsservers", svc}, servers...)
		if err := exec.Command("networksetup", args...).Run(); err != nil {
			errs = append(errs, fmt.Errorf("service %q: %w", svc, err))
		}
	}
	return errors.Join(errs...)
}

// EnableFirewall enables the macOS Application Firewall via socketfilterfw.
// Requires root.
func (p *Platform) EnableFirewall() error {
	return exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on").Run()
}

// DisableICMP blocks or unblocks ICMP via a pf anchor in the com.apple/* namespace.
// macOS's default /etc/pf.conf traverses com.apple/* anchors so rules take
// effect without modifying the main ruleset. Requires root.
func (p *Platform) DisableICMP(enabled bool) error {
	const anchor = "com.apple/darkd-icmp"
	if enabled {
		rules := "block drop proto icmp from any to any\nblock drop proto icmp6 from any to any\n"
		cmd := exec.Command("pfctl", "-a", anchor, "-f", "-")
		cmd.Stdin = strings.NewReader(rules)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("loading icmp block rules: %w", err)
		}
		return exec.Command("pfctl", "-e").Run()
	}
	if err := exec.Command("pfctl", "-a", anchor, "-F", "all").Run(); err != nil {
		return fmt.Errorf("flushing icmp block rules: %w", err)
	}
	return nil
}

// BlockIPFragmentation enables or disables IP fragment reassembly via sysctl.
// net.inet.ip.maxfragpackets=0 drops all incoming fragments; macOS default is 800.
// Requires root.
func (p *Platform) BlockIPFragmentation(enabled bool) error {
	val := "0"
	if !enabled {
		val = "800"
	}
	if err := exec.Command("sysctl", "-w", "net.inet.ip.maxfragpackets="+val).Run(); err != nil {
		return fmt.Errorf("setting maxfragpackets: %w", err)
	}
	return nil
}
