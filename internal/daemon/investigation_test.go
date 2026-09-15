package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInvestigationConfiguration(t *testing.T) {
	p := filepath.Join(t.TempDir(), "darkd.yaml")
	if err := os.WriteFile(p, []byte("services:\n  investigation:\n    enabled: true\n    retention: 48h\n    max_events: 1234\n    include_command_line: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, loader := range []func(string) error{
		func(path string) error {
			cfg, err := LoadConfig(path)
			if err != nil {
				return err
			}
			if cfg.Services.Investigation.Retention != 48*time.Hour || cfg.Services.Investigation.MaxEvents != 1234 || !cfg.Services.Investigation.IncludeCommandLine || !cfg.Services.Investigation.Enabled {
				t.Fatalf("yaml config: %+v", cfg.Services.Investigation)
			}
			return nil
		},
		func(path string) error {
			cfg, err := LoadConfigViper(path)
			if err != nil {
				return err
			}
			if cfg.Services.Investigation.Retention != 48*time.Hour || cfg.Services.Investigation.MaxEvents != 1234 || !cfg.Services.Investigation.IncludeCommandLine || !cfg.Services.Investigation.Enabled {
				t.Fatalf("viper config: %+v", cfg.Services.Investigation)
			}
			return nil
		},
	} {
		if err := loader(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(p, []byte("services:\n  investigation:\n    enabled: true\n    max_events: -1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("invalid retention accepted")
	}
}
