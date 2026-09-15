package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestThreatCheckRequiresRealCredentials(t *testing.T) {
	t.Setenv("DARKAPI_API_KEY", "")
	t.Setenv("DARKAPI_URL", "")
	command := newRoot()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"--credentials", filepath.Join(t.TempDir(), "missing.json"), "check", "domain", "example.com"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "credentials are missing") {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "CLEAN") || strings.Contains(output.String(), "SECURE") {
		t.Fatal("fabricated protection result")
	}
}
