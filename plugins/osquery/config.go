package main

import (
	"fmt"
	"os"
)

// Config holds the configuration for the osquery manager
type Config struct {
	// Path to osqueryd binary. If empty, assumes "osqueryd" is in PATH
	BinaryPath string `mapstructure:"binary_path"`

	// Enrollment secret for authenticating with the management server
	EnrollSecret string `mapstructure:"enroll_secret"`

	// Hostname to identify this agent
	Hostname string `mapstructure:"hostname"`

	// TLS hostname of the management server
	TLSHostname string `mapstructure:"tls_hostname"`

	// Helper functionality: where to store generated secret file
	SecretFile string
}

// ParseConfig parses the raw configuration map
func ParseConfig(raw map[string]interface{}) (*Config, error) {
	cfg := &Config{
		BinaryPath: "osqueryd", // Default fallback
	}

	// Check for bundled binary options
	// 1. Relative to executable (development/standalone)
	// 2. Standard install location /opt/afterdark/bin/...

	// We can leave the detailed logic to the manager or just set a smart default here?
	// Let's keep the config clean and handle "search" in manager or here.
	// Let's assume standard bundle structure: ./bin/osqueryd relative to CWD
	if _, err := os.Stat("bin/osqueryd"); err == nil {
		cfg.BinaryPath = "bin/osqueryd"
	} else if _, err := os.Stat("../bin/osqueryd"); err == nil {
		cfg.BinaryPath = "../bin/osqueryd"
	}

	if val, ok := raw["binary_path"].(string); ok && val != "" {
		cfg.BinaryPath = val
	}

	if val, ok := raw["enroll_secret"].(string); ok {
		cfg.EnrollSecret = val
	}

	if val, ok := raw["hostname"].(string); ok {
		cfg.Hostname = val
	}

	if val, ok := raw["tls_hostname"].(string); ok {
		cfg.TLSHostname = val
	}

	if cfg.EnrollSecret == "" {
		return nil, fmt.Errorf("enroll_secret is required")
	}

	if cfg.TLSHostname == "" {
		return nil, fmt.Errorf("tls_hostname is required")
	}

	return cfg, nil
}

// GenerateFlags returns the command line flags for osqueryd
func (c *Config) GenerateFlags(secretFilePath string) []string {
	flags := []string{
		"--enroll_secret_path=" + secretFilePath,
		"--tls_hostname=" + c.TLSHostname,
		"--host_identifier=hostname", // Use the hostname we set (or system default if not overridden)
		"--enroll_tls_endpoint=/api/v1/osquery/enroll",
		"--config_plugin=tls",
		"--config_tls_endpoint=/api/v1/osquery/config",
		"--logger_plugin=tls",
		"--logger_tls_endpoint=/api/v1/osquery/log",
		"--disable_distributed=false",
		"--distributed_plugin=tls",
		"--distributed_tls_read_endpoint=/api/v1/osquery/distributed/read",
		"--distributed_tls_write_endpoint=/api/v1/osquery/distributed/write",
	}

	if c.Hostname != "" {
		// If we want to force a specific hostname override, we might need a different flag
		// or rely on osquery's detection. Here we assume standard osquery behavior.
		// But for now, let's keep it simple.
	}

	return flags
}
