package plugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	t.Setenv("AFTERDARK_REQUIRE_PLUGIN_SIGNATURE", "1")
	if err := os.WriteFile(path, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	h := &Host{pluginDir: dir}
	if err := h.verifyPluginIntegrity(path); err == nil {
		t.Fatal("accepted unpinned plugin")
	}
	sum := sha256.Sum256([]byte("binary"))
	manifest := []byte(`{"plugin":"` + hex.EncodeToString(sum[:]) + `"}`)
	if err := os.WriteFile(os.Getenv("AFTERDARK_PLUGIN_MANIFEST"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.verifyPluginIntegrity(path); err == nil {
		t.Fatal("accepted unsigned manifest")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AFTERDARK_PLUGIN_MANIFEST_PUBLIC_KEY", base64.StdEncoding.EncodeToString(public))
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, manifest))
	if err := os.WriteFile(os.Getenv("AFTERDARK_PLUGIN_MANIFEST")+".sig", []byte(signature), 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.verifyPluginIntegrity(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := h.verifyPluginIntegrity(path); err == nil {
		t.Fatal("accepted tampered plugin")
	}
}
