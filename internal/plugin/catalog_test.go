package plugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestCatalogRequiresTrustedSignatureAndSafeNames(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, name := range []string{"plugin", "../escape", `a\\b`, "plugin-manifest.json"} {
		manifest := []byte(fmt.Sprintf(`{%q:%q}`, name, strings.Repeat("a", 64)))
		sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifest)))
		_, err := VerifyCatalog(manifest, sig, base64.StdEncoding.EncodeToString(pub))
		if (err == nil) != (name == "plugin") {
			t.Fatalf("name=%q error=%v", name, err)
		}
		manifest = append(manifest, ' ')
		if _, err := VerifyCatalog(manifest, sig, base64.StdEncoding.EncodeToString(pub)); err == nil {
			t.Fatal("tampered catalog accepted")
		}
	}
}
