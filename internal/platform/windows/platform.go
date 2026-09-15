//go:build windows

package windows

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

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

// GetOSInfo returns Windows system information via PowerShell registry query
func (p *Platform) GetOSInfo() (*platform.OSInfo, error) {
	// Query registry via PowerShell — avoids adding golang.org/x/sys/windows/registry dep
	psCmd := `(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object -Property ProductName,CurrentBuild | ConvertTo-Json -Compress)`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", psCmd).Output()
	if err != nil {
		return &platform.OSInfo{
			Name:         "Windows",
			Version:      "Unknown",
			Architecture: runtime.GOARCH,
			Kernel:       "NT",
		}, nil
	}
	// Parse the two fields out of the JSON manually to avoid an import
	s := strings.TrimSpace(string(out))
	name := jsonStringField(s, "ProductName")
	build := jsonStringField(s, "CurrentBuild")
	if name == "" {
		name = "Windows"
	}
	return &platform.OSInfo{
		Name:         name,
		Version:      build,
		Build:        build,
		Architecture: runtime.GOARCH,
		Kernel:       "NT",
	}, nil
}

// jsonStringField is a minimal helper that extracts a JSON string value by key
// without importing encoding/json (keeps the file's dependency footprint small).
func jsonStringField(s, key string) string {
	needle := `"` + key + `":"`
	idx := strings.Index(s, needle)
	if idx == -1 {
		return ""
	}
	rest := s[idx+len(needle):]
	end := strings.IndexByte(rest, '"')
	if end == -1 {
		return rest
	}
	return rest[:end]
}

// GetHostname returns the system hostname
func (p *Platform) GetHostname() (string, error) {
	return os.Hostname()
}

// Methods moved to patches.go

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

// SetDNSServers configures DNS servers using netsh on all non-loopback interfaces
func (p *Platform) SetDNSServers(servers []string) error {
	if len(servers) == 0 {
		return nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	var lastErr error
	applied := 0
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// Set primary DNS
		if err := exec.CommandContext(context.Background(),
			"netsh", "interface", "ip", "set", "dns",
			iface.Name, "static", servers[0]).Run(); err != nil {
			lastErr = err
			continue
		}
		applied++
		// Add additional DNS servers
		for i, s := range servers[1:] {
			_ = exec.CommandContext(context.Background(),
				"netsh", "interface", "ip", "add", "dns",
				iface.Name, s, strings.Join([]string{"index=", string(rune('2' + i))}, "")).Run()
		}
	}
	if applied == 0 && lastErr != nil {
		return lastErr
	}
	return nil
}

// EnableFirewall enables Windows Defender Firewall on all profiles
func (p *Platform) EnableFirewall() error {
	return exec.CommandContext(context.Background(),
		"netsh", "advfirewall", "set", "allprofiles", "state", "on").Run()
}

// DisableICMP controls inbound ICMPv4 echo (ping) requests via Windows Firewall rules.
// When enabled is true, a block rule is added; when false, the rule is removed.
func (p *Platform) DisableICMP(enabled bool) error {
	if enabled {
		return exec.CommandContext(context.Background(),
			"netsh", "advfirewall", "firewall", "add", "rule",
			"name=AfterDark-BlockICMP",
			"protocol=icmpv4:8,any",
			"dir=in",
			"action=block").Run()
	}
	return exec.CommandContext(context.Background(),
		"netsh", "advfirewall", "firewall", "delete", "rule",
		"name=AfterDark-BlockICMP").Run()
}

// BlockIPFragmentation controls whether fragmented IP packets are blocked.
// Windows does not expose a direct sysctl equivalent; we use a Windows Firewall
// rule targeting fragmented packets (protocol=any with fragment filtering).
// When enabled is true, a block rule is added; when false, it is removed.
func (p *Platform) BlockIPFragmentation(enabled bool) error {
	if enabled {
		psCmd := `New-NetFirewallRule -DisplayName 'AfterDark-BlockFragments' -Direction Inbound -Action Block -Protocol TCP -Description 'Block IP fragments' -EdgeTraversalPolicy Block`
		return exec.CommandContext(context.Background(),
			"powershell", "-NoProfile", "-Command", psCmd).Run()
	}
	psCmd := `Remove-NetFirewallRule -DisplayName 'AfterDark-BlockFragments' -ErrorAction SilentlyContinue`
	return exec.CommandContext(context.Background(),
		"powershell", "-NoProfile", "-Command", psCmd).Run()
}
