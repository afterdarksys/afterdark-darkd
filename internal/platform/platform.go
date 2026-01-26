package platform

import (
	"context"
	"runtime"
	"time"
)

// Platform defines the interface for OS-specific operations
type Platform interface {
	// System Information
	GetOSInfo() (*OSInfo, error)
	GetHostname() (string, error)

	// Patch Management
	ListInstalledPatches(ctx context.Context) ([]Patch, error)
	ListAvailablePatches(ctx context.Context) ([]Patch, error)
	InstallPatch(ctx context.Context, patchID string) error

	// Application Inventory
	ListInstalledApplications(ctx context.Context) ([]Application, error)

	// Network Operations
	GetNetworkInterfaces() ([]NetworkInterface, error)
	GetPublicIP(ctx context.Context) (string, error)
	SetDNSServers(servers []string) error

	// Security Controls
	EnableFirewall() error
	DisableICMP(enabled bool) error
	BlockIPFragmentation(enabled bool) error
}

// OSInfo contains operating system information
type OSInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Build        string `json:"build"`
	Architecture string `json:"architecture"`
	Kernel       string `json:"kernel"`
}

// PatchSeverity represents the severity level of a patch
type PatchSeverity int

const (
	SeverityUnknown PatchSeverity = iota
	SeverityLow
	SeverityModerate
	SeverityImportant
	SeverityCritical
	SeverityExploitActive
)

func (s PatchSeverity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityModerate:
		return "moderate"
	case SeverityImportant:
		return "important"
	case SeverityCritical:
		return "critical"
	case SeverityExploitActive:
		return "exploit-active"
	default:
		return "unknown"
	}
}

// PatchCategory represents the category of a patch
type PatchCategory int

const (
	CategoryUnknown PatchCategory = iota
	CategoryKernel
	CategoryNetwork
	CategorySoftware
	CategorySecurity
)

func (c PatchCategory) String() string {
	switch c {
	case CategoryKernel:
		return "kernel"
	case CategoryNetwork:
		return "network"
	case CategorySoftware:
		return "software"
	case CategorySecurity:
		return "security"
	default:
		return "unknown"
	}
}

// Patch represents an OS patch/update
type Patch struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Severity    PatchSeverity `json:"severity"`
	Category    PatchCategory `json:"category"`
	InstalledAt *time.Time    `json:"installed_at,omitempty"`
	ReleasedAt  time.Time     `json:"released_at"`
	CVEs        []string      `json:"cves,omitempty"`
	KBArticle   string        `json:"kb_article,omitempty"`
	Size        int64         `json:"size"`
}

// Application represents an installed application
type Application struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Vendor      string    `json:"vendor"`
	InstallDate time.Time `json:"install_date"`
	InstallPath string    `json:"install_path"`
}

// NetworkInterface represents a network interface
type NetworkInterface struct {
	Name       string `json:"name"`
	MACAddress string `json:"mac_address"`
	IPAddress  string `json:"ip_address"`
	Status     string `json:"status"`
}

// Detect returns the current operating system type
func Detect() string {
	return runtime.GOOS
}

// ErrUnsupportedPlatform is returned when the OS is not supported
type ErrUnsupportedPlatform struct {
	OS string
}

func (e *ErrUnsupportedPlatform) Error() string {
	return "unsupported platform: " + e.OS
}
