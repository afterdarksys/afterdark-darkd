package main

import (
	"testing"
)

func TestGenerateFlags(t *testing.T) {
	config := &Config{
		BinaryPath:   "/usr/bin/osqueryd",
		EnrollSecret: "secret123",
		Hostname:     "test-host",
		TLSHostname:  "management.example.com",
	}

	secretFile := "/tmp/secret"
	flags := config.GenerateFlags(secretFile)

	expectedSubset := []string{
		"--enroll_secret_path=/tmp/secret",
		"--tls_hostname=management.example.com",
		"--host_identifier=hostname",
	}

	for _, exp := range expectedSubset {
		found := false
		for _, f := range flags {
			if f == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected flag %s not found in %v", exp, flags)
		}
	}
}

func TestParseConfig(t *testing.T) {
	raw := map[string]interface{}{
		"enroll_secret": "mysecret",
		"tls_hostname":  "tls.example.com",
		"hostname":      "myhost",
	}

	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}

	if cfg.EnrollSecret != "mysecret" {
		t.Errorf("Expected secret 'mysecret', got %s", cfg.EnrollSecret)
	}
	if cfg.BinaryPath != "osqueryd" {
		t.Errorf("Expected default binary path 'osqueryd', got %s", cfg.BinaryPath)
	}
}

func TestParseConfigMissingRequired(t *testing.T) {
	raw := map[string]interface{}{
		"enroll_secret": "mysecret",
		// missing tls_hostname
	}

	_, err := ParseConfig(raw)
	if err == nil {
		t.Error("Expected error for missing tls_hostname, got nil")
	}
}
