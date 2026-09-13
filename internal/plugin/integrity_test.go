package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestPluginManifestRequired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plugin")
	t.Setenv("AFTERDARK_PLUGIN_MANIFEST", filepath.Join(dir, "manifest.json"))
	t.Setenv("AFTERDARK_PLUGIN_MANIFEST_PUBLIC_KEY", "")
	t.Setenv("AFTERDARK_REQUIRE_PLUGIN_SIGNATURE", "")
	if err := os.WriteFile(path, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	h := &Host{pluginDir: dir}
	if err := h.validatePluginPath(path); err == nil {
		t.Fatal("accepted unpinned plugin")
	}
	sum := sha256.Sum256([]byte("binary"))
	manifest := []byte(`{"plugin":"` + hex.EncodeToString(sum[:]) + `"}`)
	if err := os.WriteFile(os.Getenv("AFTERDARK_PLUGIN_MANIFEST"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.validatePluginPath(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := h.validatePluginPath(path); err == nil {
		t.Fatal("accepted tampered plugin")
	}
}
