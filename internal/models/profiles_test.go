package models

import (
	"testing"
	"time"
)

func TestProfilesSelectPlatformAndDisablePlaceholders(t *testing.T) {
	for _, platform := range []string{"linux", "darwin", "windows"} {
		for _, mode := range []string{"server", "desktop"} {
			t.Run(platform+"/"+mode, func(t *testing.T) {
				c, err := DefaultConfigForMode(mode, platform)
				if err != nil {
					t.Fatal(err)
				}
				s := c.Services
				if s.EBPF.Enabled != (platform == "linux") || s.ESF.Enabled != (platform == "darwin") || s.ETW.Enabled != (platform == "windows") || s.Registry.Enabled != (platform == "windows") {
					t.Fatal("incorrect native sensor selection")
				}
				if s.CloudMetadata.Enabled || s.DeviceControl.Enabled || s.MLEngine.Enabled || s.DLP.Enabled || s.Honeypot.Enabled || s.PatchMonitor.AutoInstallWindows {
					t.Fatal("profile enables unimplemented or mutating features")
				}
				if !s.Investigation.Enabled || s.Investigation.IncludeCommandLine || !c.IPC.AuthEnabled || c.IPC.TCPAddr != "" || c.API.DarkAPI.TelemetryEnabled {
					t.Fatal("unsafe profile")
				}
				if s.Canary.Enabled != (mode == "desktop") {
					t.Fatal("wrong canary profile")
				}
				if platform == "windows" && (s.PersistenceMonitor.Enabled || s.IntegrityMonitor.WatchedFiles[0] != `C:\Windows\System32\drivers\etc\hosts`) {
					t.Fatal("Unix defaults leaked into Windows")
				}
				if mode == "desktop" && s.ProcessMonitor.ProcessInterval != 30*time.Second {
					t.Fatal("desktop collection interval")
				}
			})
		}
	}
}
func TestInvalidProfilesAndLegacy(t *testing.T) {
	if _, err := DefaultConfigForMode("typo", "linux"); err == nil {
		t.Fatal("invalid mode accepted")
	}
	if _, err := DefaultConfigForMode("server", "unknown"); err == nil {
		t.Fatal("invalid platform accepted")
	}
	c, err := DefaultConfigForMode("", "linux")
	if err != nil || c.Services.Investigation.Enabled != DefaultConfig().Services.Investigation.Enabled {
		t.Fatal("legacy settings changed")
	}
}
