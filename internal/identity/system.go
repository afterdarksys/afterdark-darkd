package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// SystemIdentity represents the unique identity of this system
type SystemIdentity struct {
	SystemID     string `yaml:"system_id" json:"system_id"`
	Hostname     string `yaml:"hostname" json:"hostname"`
	MachineID    string `yaml:"machine_id" json:"machine_id"`
	OS           string `yaml:"os" json:"os"`
	Arch         string `yaml:"arch" json:"arch"`
	Registered   bool   `yaml:"registered" json:"registered"`
	RegisteredAt string `yaml:"registered_at,omitempty" json:"registered_at,omitempty"`
	AccountEmail string `yaml:"account_email,omitempty" json:"account_email,omitempty"`
}

const (
	identityFile = "system-identity.yaml"
)

// GetDataDir returns the data directory for afterdark
func GetDataDir() string {
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "afterdark")
	case "linux":
		return "/var/lib/afterdark"
	case "windows":
		return filepath.Join(os.Getenv("PROGRAMDATA"), "AfterDark")
	default:
		return "/var/lib/afterdark"
	}
}

// GetIdentityPath returns the path to the identity file
func GetIdentityPath() string {
	return filepath.Join(GetDataDir(), identityFile)
}

// GetMachineID returns the unique machine identifier
func GetMachineID() (string, error) {
	var machineID string

	switch runtime.GOOS {
	case "darwin":
		// macOS: use IOPlatformSerialNumber via system_profiler
		// For now, fallback to hardware UUID
		data, err := os.ReadFile("/var/db/SystemConfiguration/com.apple.NetworkInterfaces.plist")
		if err == nil {
			hash := sha256.Sum256(data)
			machineID = hex.EncodeToString(hash[:16])
		}
	case "linux":
		// Linux: /etc/machine-id or /var/lib/dbus/machine-id
		paths := []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err == nil {
				machineID = strings.TrimSpace(string(data))
				break
			}
		}
	case "windows":
		// Windows: use MachineGuid from registry
		// For now, generate from hostname
		hostname, _ := os.Hostname()
		hash := sha256.Sum256([]byte(hostname + runtime.GOOS))
		machineID = hex.EncodeToString(hash[:16])
	}

	if machineID == "" {
		// Fallback: generate from hostname + boot time
		hostname, _ := os.Hostname()
		hash := sha256.Sum256([]byte(hostname + runtime.GOOS + runtime.GOARCH))
		machineID = hex.EncodeToString(hash[:16])
	}

	return machineID, nil
}

// GenerateSystemID creates a new unique system ID
func GenerateSystemID() (*SystemIdentity, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	machineID, err := GetMachineID()
	if err != nil {
		return nil, fmt.Errorf("failed to get machine ID: %w", err)
	}

	// Generate UUID from machine ID + hostname for consistency
	// Same machine will always get same UUID
	seed := machineID + ":" + hostname
	hash := sha256.Sum256([]byte(seed))

	// Create a UUID v5-like ID from the hash
	systemID := fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(hash[0:4]),
		hex.EncodeToString(hash[4:6]),
		hex.EncodeToString(hash[6:8]),
		hex.EncodeToString(hash[8:10]),
		hex.EncodeToString(hash[10:16]),
	)

	identity := &SystemIdentity{
		SystemID:   systemID,
		Hostname:   hostname,
		MachineID:  machineID,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Registered: false,
	}

	return identity, nil
}

// LoadIdentity loads the system identity from disk
func LoadIdentity() (*SystemIdentity, error) {
	path := GetIdentityPath()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No identity yet
		}
		return nil, fmt.Errorf("failed to read identity file: %w", err)
	}

	var identity SystemIdentity
	if err := yaml.Unmarshal(data, &identity); err != nil {
		return nil, fmt.Errorf("failed to parse identity file: %w", err)
	}

	return &identity, nil
}

// SaveIdentity saves the system identity to disk
func (id *SystemIdentity) Save() error {
	path := GetIdentityPath()

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	data, err := yaml.Marshal(id)
	if err != nil {
		return fmt.Errorf("failed to marshal identity: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write identity file: %w", err)
	}

	return nil
}

// GetOrCreateIdentity loads existing identity or creates a new one
func GetOrCreateIdentity() (*SystemIdentity, bool, error) {
	identity, err := LoadIdentity()
	if err != nil {
		return nil, false, err
	}

	if identity != nil {
		return identity, false, nil // Existing identity
	}

	// Create new identity
	identity, err = GenerateSystemID()
	if err != nil {
		return nil, false, err
	}

	if err := identity.Save(); err != nil {
		return nil, false, err
	}

	return identity, true, nil // New identity
}

// GenerateAPIToken generates a unique API token for this system
func GenerateAPIToken() string {
	return "dk_" + uuid.New().String()
}
