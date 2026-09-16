package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProfileConfigPreservesExplicitOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "darkd.yaml")
	raw := []byte("daemon:\n  mode: desktop\nservices:\n  canary:\n    enabled: false\n  process_monitor:\n    process_interval: 47s\n  investigation:\n    include_command_line: false\n")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Daemon.Mode != "desktop" || c.Services.Canary.Enabled || c.Services.ProcessMonitor.ProcessInterval != 47*time.Second {
		t.Fatal("YAML override lost")
	}
	v := NewViperConfig()
	v.SetConfigFile(path)
	c, err = v.Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Daemon.Mode != "desktop" || c.Services.Canary.Enabled || c.Services.ProcessMonitor.ProcessInterval != 47*time.Second {
		t.Fatal("Viper override lost", c.Daemon.Mode, c.Services.ProcessMonitor)
	}
	c, err = LoadConfigWithMode(path, "server")
	if err != nil || c.Daemon.Mode != "server" || c.Services.ProcessMonitor.ProcessInterval != 47*time.Second {
		t.Fatal("flag override lost", err)
	}
	t.Setenv("DARKD_DAEMON_MODE", "server")
	c, err = LoadConfig(path)
	if err != nil || c.Daemon.Mode != "server" {
		t.Fatal("environment override lost", err)
	}
	t.Setenv("DARKD_DAEMON_MODE", "typo")
	if _, err = LoadConfig(path); err == nil {
		t.Fatal("bad mode accepted")
	}
}
