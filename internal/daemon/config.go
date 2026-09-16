package daemon

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"gopkg.in/yaml.v3"
)

// LoadConfig loads configuration from the specified file
func LoadConfig(path string) (*models.Config, error) { return LoadConfigWithMode(path, "") }

func LoadConfigWithMode(path, override string) (*models.Config, error) {

	// Read config file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables
	data = []byte(os.ExpandEnv(string(data)))

	// Select profile defaults first, then preserve all explicit YAML settings.
	var header struct {
		Daemon struct {
			Mode string `yaml:"mode"`
		} `yaml:"daemon"`
	}
	if err := yaml.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	mode := header.Daemon.Mode
	if value, ok := os.LookupEnv("DARKD_DAEMON_MODE"); ok {
		mode = value
	}
	if override != "" {
		mode = override
	}
	cfg, err := models.DefaultConfigForMode(mode, runtime.GOOS)
	if err != nil {
		return nil, err
	}
	// Parse YAML
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	cfg.Daemon.Mode = mode

	// Validate configuration
	if err := ValidateConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// ValidateConfig validates the configuration
func ValidateConfig(cfg *models.Config) error {
	var errors []string
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}
	if !models.ValidMode(cfg.Daemon.Mode) {
		errors = append(errors, "daemon.mode must be server, desktop or legacy")
	}

	// Validate daemon config
	if cfg.Daemon.DataDir == "" {
		errors = append(errors, "daemon.data_dir is required")
	}

	if cfg.API.DarkAPI.TelemetryEnabled && cfg.Services.SIEM.Enabled {
		errors = append(errors, "choose DarkAPI telemetry or generic SIEM export; independent delivery cursors are not yet implemented")
	}
	// Validate API config
	if cfg.API.AfterDark.URL == "" {
		errors = append(errors, "api.afterdark.url is required")
	}
	if cfg.API.DarkAPI.URL == "" {
		errors = append(errors, "api.darkapi.url is required")
	}

	// Validate services config
	if cfg.Services.Investigation.Enabled && (cfg.Services.Investigation.Retention <= 0 || cfg.Services.Investigation.MaxEvents <= 0) {
		errors = append(errors, "services.investigation.retention and max_events must be positive")
	}
	if cfg.Services.PatchMonitor.Enabled {
		if cfg.Services.PatchMonitor.ScanInterval <= 0 {
			errors = append(errors, "services.patch_monitor.scan_interval must be positive")
		}
	}

	if cfg.Services.ThreatIntel.Enabled {
		if cfg.Services.ThreatIntel.SyncInterval <= 0 {
			errors = append(errors, "services.threat_intel.sync_interval must be positive")
		}
	}

	// Validate storage config
	if cfg.Storage.Path == "" {
		errors = append(errors, "storage.path is required")
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration errors:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

// SaveConfig saves configuration to the specified file
func SaveConfig(cfg *models.Config, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
