package darkapi

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Account and device keys have different scopes and are never interchangeable.
type Credentials struct {
	BaseURL   string `json:"base_url"`
	APIKey    string `json:"api_key,omitempty"`
	DeviceID  string `json:"device_id,omitempty"`
	DeviceKey string `json:"device_key,omitempty"`
}

func DefaultCredentialPath() string {
	if path := os.Getenv("DARKAPI_CREDENTIAL_FILE"); path != "" {
		return path
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "afterdark", "darkapi.json")
}
func LoadCredentials(path string) (*Credentials, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read DarkAPI credentials: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("credentials must be a regular file")
	}
	if info.Size() > 16384 {
		return nil, fmt.Errorf("credential file too large")
	}
	if err := checkCredentialPermissions(path, info); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("invalid credential file")
	}
	if c.BaseURL == "" {
		return nil, fmt.Errorf("credential file must identify its base_url")
	}
	return &c, nil
}
func SaveCredentials(path string, c *Credentials) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".darkapi-credentials-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := secureCredentialFile(f.Name()); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
