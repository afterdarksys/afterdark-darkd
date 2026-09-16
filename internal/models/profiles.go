package models

import (
	"fmt"
	"path/filepath"
	"time"
)

// Empty mode preserves the historical configuration until operators opt in.
func ValidMode(mode string) bool {
	return mode == "" || mode == "legacy" || mode == "server" || mode == "desktop"
}

// DefaultConfigForMode chooses defaults before decoding explicit operator values.
// Neither profile enables credentials, remote administration or active remediation.
func DefaultConfigForMode(mode, platform string) (*Config, error) {
	if !ValidMode(mode) {
		return nil, fmt.Errorf("daemon.mode must be server, desktop or legacy")
	}
	if mode == "" || mode == "legacy" {
		c := DefaultConfig()
		c.Daemon.Mode = "legacy"
		return c, nil
	}
	if platform != "linux" && platform != "darwin" && platform != "windows" {
		return nil, fmt.Errorf("unsupported profile platform %q", platform)
	}
	c := DefaultConfig()
	c.Daemon.Mode = mode
	base := "/var/lib/afterdark"
	join := filepath.Join
	if platform == "darwin" {
		base = "/Library/Application Support/AfterDark"
	}
	if platform == "windows" {
		base = `C:\ProgramData\AfterDark`
		join = func(parts ...string) string {
			out := parts[0]
			for _, p := range parts[1:] {
				out += `\` + p
			}
			return out
		}
	}
	c.Daemon.DataDir = base
	c.Daemon.PluginDir = join(base, "plugins")
	c.Storage.Path = join(base, "data")
	c.IPC.AuthTokenFile = join(base, ".auth_token")
	if platform == "windows" {
		c.Daemon.PIDFile = ""
		c.IPC.SocketPath = `\\.\pipe\afterdark-darkd`
	} else {
		c.Daemon.PIDFile = "/var/run/afterdark/darkd.pid"
		c.IPC.SocketPath = "/var/run/afterdark/darkd.sock"
	}
	s := &c.Services
	s.Investigation = InvestigationConfig{Enabled: true, Retention: 7 * 24 * time.Hour, MaxEvents: 100000}
	s.ProcessMonitor.Enabled = true
	s.NetworkMonitor.Tracking.Enabled = true
	s.ProcessMonitor.ProcessInterval = 10 * time.Second
	s.NetworkMonitor.Tracking.NetworkInterval = 10 * time.Second
	s.SysMonitor.Interval = 15 * time.Second
	s.PatchMonitor.AutoInstallWindows = false
	s.EBPF.Enabled = platform == "linux"
	s.ESF.Enabled = platform == "darwin"
	s.ETW.Enabled = platform == "windows"
	s.Registry.Enabled = platform == "windows"
	s.PersistenceMonitor.Enabled = platform != "windows"
	s.IntegrityMonitor.WatchedFiles = []string{"/etc/hosts", "/etc/passwd", "/etc/ssh/sshd_config"}
	if platform == "windows" {
		s.IntegrityMonitor.WatchedFiles = []string{`C:\Windows\System32\drivers\etc\hosts`}
	}
	// These legacy services contain placeholders, heuristics, or require explicit enforcement policy.
	s.MLEngine.Enabled = false
	s.Honeypot.Enabled = false
	s.DeviceControl.Enabled = false
	s.DLP.Enabled = false
	s.NetworkDrift.Enabled = mode == "server"
	s.CloudMetadata.Enabled = false
	s.AppLockdown.Enabled = false
	s.Scripting.Enabled = false
	s.ActivityMonitor.Enabled = false
	s.MemoryScanner.Enabled = false
	s.DetonationChamber.Enabled = false
	s.Canary.Enabled = mode == "desktop"
	s.Canary.DecoyPaths = []string{base}
	s.Canary.DecoyFilenames = []string{".darkd-canary.docx"}
	if mode == "desktop" {
		s.ProcessMonitor.ProcessInterval = 30 * time.Second
		s.NetworkMonitor.Tracking.NetworkInterval = 30 * time.Second
		s.SysMonitor.Interval = time.Minute
		s.PatchMonitor.ScanInterval = 4 * time.Hour
	}
	return c, nil
}
