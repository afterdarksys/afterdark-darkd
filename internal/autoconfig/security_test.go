package autoconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"
)

func TestRemoteConfigRequiresSignature(t *testing.T) {
	t.Setenv("AFTERDARK_CONFIG_PUBLIC_KEY", "")
	if err := verifySignedConfig([]byte(`{}`), ""); err == nil {
		t.Fatal("accepted unsigned config")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AFTERDARK_CONFIG_PUBLIC_KEY", base64.StdEncoding.EncodeToString(pub))
	body := []byte(`{"features":{}}`)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, body))
	if err := verifySignedConfig(body, sig); err != nil {
		t.Fatal(err)
	}
	if err := verifySignedConfig([]byte(`{"features":{"x":true}}`), sig); err == nil {
		t.Fatal("accepted modified config")
	}
}

func TestEndpointAndRedirectRejection(t *testing.T) {
	t.Setenv("AFTERDARK_ALLOWED_API_HOSTS", "")
	for _, endpoint := range []string{"http://api.afterdark.io", "https://attacker.example", "https://api.afterdark.io/?next=evil", "https://127.0.0.1", "https://user:pass@api.afterdark.io"} {
		if err := validateAPIEndpoint(endpoint); err == nil {
			t.Fatalf("accepted %s", endpoint)
		}
	}
	ac := New("test")
	if ac.httpClient.CheckRedirect == nil || ac.httpClient.CheckRedirect(&http.Request{}, nil) == nil {
		t.Fatal("redirect allowed")
	}
}
