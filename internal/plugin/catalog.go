package plugin

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Catalog is a platform-specific, publisher-signed digest manifest. Publishers
// serve binaries alongside plugin-manifest.json and plugin-manifest.json.sig.
// The key must come from the administrator, never from the catalog itself.
type Catalog struct {
	Digests             map[string]string
	Manifest, Signature []byte
	BaseURL             string
}

func catalogFetch(ctx context.Context, address string, limit int64) ([]byte, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("catalog requires an HTTPS URL without credentials")
	}
	request, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("catalog HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("catalog artifact exceeds size limit")
	}
	return data, nil
}

func VerifyCatalog(manifest, signature []byte, publicKey string) (map[string]string, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKey))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid publisher public key")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signature)))
	if err != nil || !ed25519.Verify(key, manifest, sig) {
		return nil, fmt.Errorf("catalog signature invalid")
	}
	var digests map[string]string
	if err := json.Unmarshal(manifest, &digests); err != nil {
		return nil, err
	}
	if len(digests) == 0 {
		return nil, fmt.Errorf("empty catalog")
	}
	for name, digest := range digests {
		if name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\:\x00") || name == "plugin-manifest.json" || name == "plugin-manifest.json.sig" {
			return nil, fmt.Errorf("invalid catalog filename")
		}
		hash, err := hex.DecodeString(digest)
		if err != nil || len(hash) != sha256.Size {
			return nil, fmt.Errorf("invalid digest for %s", name)
		}
	}
	return digests, nil
}

func FetchCatalog(ctx context.Context, baseURL, publicKey string) (*Catalog, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	manifest, err := catalogFetch(ctx, baseURL+"/plugin-manifest.json", 1<<20)
	if err != nil {
		return nil, err
	}
	signature, err := catalogFetch(ctx, baseURL+"/plugin-manifest.json.sig", 1024)
	if err != nil {
		return nil, err
	}
	digests, err := VerifyCatalog(manifest, signature, publicKey)
	if err != nil {
		return nil, err
	}
	return &Catalog{Digests: digests, Manifest: manifest, Signature: signature, BaseURL: baseURL}, nil
}

// Install stages a new version directory atomically. It does not execute the
// plugin or replace an active installation. Configure the daemon to use the
// verified directory, with the same publisher key and signature enforcement.
func (c *Catalog) Install(ctx context.Context, name, destination, publicKey string) error {
	digests, err := VerifyCatalog(c.Manifest, c.Signature, publicKey)
	if err != nil {
		return err
	}
	expected, ok := digests[name]
	if !ok {
		return fmt.Errorf("plugin is not in signed catalog")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return fmt.Errorf("destination must not exist")
	}
	data, err := catalogFetch(ctx, c.BaseURL+"/"+url.PathEscape(name), 256<<20)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(hash[:]), expected) {
		return fmt.Errorf("plugin digest does not match signed catalog")
	}
	parent := filepath.Dir(destination)
	stage, err := os.MkdirTemp(parent, ".plugin-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := os.WriteFile(filepath.Join(stage, name), data, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, "plugin-manifest.json"), c.Manifest, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, "plugin-manifest.json.sig"), c.Signature, 0600); err != nil {
		return err
	}
	return os.Rename(stage, destination)
}
