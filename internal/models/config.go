package models

import "time"

// Config represents the daemon configuration
type Config struct {
	Daemon   DaemonConfig   `yaml:"daemon" json:"daemon"`
	API      APIConfig      `yaml:"api" json:"api"`
	Services ServicesConfig `yaml:"services" json:"services"`
	Storage  StorageConfig  `yaml:"storage" json:"storage"`
	IPC      IPCConfig      `yaml:"ipc" json:"ipc"`
}

// DaemonConfig holds daemon-specific configuration
type DaemonConfig struct {
	LogLevel string `yaml:"log_level" json:"log_level"`
	DataDir  string `yaml:"data_dir" json:"data_dir"`
	PIDFile  string `yaml:"pid_file" json:"pid_file"`
}

// APIConfig holds all API endpoint configurations
type APIConfig struct {
	AfterDark  EndpointConfig `yaml:"afterdark" json:"afterdark"`
	DarkAPI    EndpointConfig `yaml:"darkapi" json:"darkapi"`
	DNSScience EndpointConfig `yaml:"dnsscience" json:"dnsscience"`
	Veribits   EndpointConfig `yaml:"veribits" json:"veribits"`
}

// EndpointConfig holds configuration for a single API endpoint
type EndpointConfig struct {
	URL     string        `yaml:"url" json:"url"`
	APIKey  string        `yaml:"api_key" json:"api_key,omitempty"`
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
	Retry   RetryConfig   `yaml:"retry" json:"retry"`
}

// RetryConfig holds retry behavior configuration
type RetryConfig struct {
	MaxAttempts int           `yaml:"max_attempts" json:"max_attempts"`
	InitialWait time.Duration `yaml:"initial_wait" json:"initial_wait"`
	MaxWait     time.Duration `yaml:"max_wait" json:"max_wait"`
}

// ServicesConfig holds configuration for all services
type ServicesConfig struct {
	PatchMonitor    PatchMonitorConfig    `yaml:"patch_monitor" json:"patch_monitor"`
	ThreatIntel     ThreatIntelConfig     `yaml:"threat_intel" json:"threat_intel"`
	BaselineScanner BaselineScannerConfig `yaml:"baseline_scanner" json:"baseline_scanner"`
	NetworkMonitor  NetworkMonitorConfig  `yaml:"network_monitor" json:"network_monitor"`
}

// PatchMonitorConfig holds patch monitoring configuration
type PatchMonitorConfig struct {
	Enabled            bool          `yaml:"enabled" json:"enabled"`
	ScanInterval       time.Duration `yaml:"scan_interval" json:"scan_interval"`
	AutoInstallWindows bool          `yaml:"auto_install_windows" json:"auto_install_windows"`
	UrgencyTiers       UrgencyTiers  `yaml:"urgency_tiers" json:"urgency_tiers"`
}

// UrgencyTiers defines the time limits for different patch urgency levels
type UrgencyTiers struct {
	Critical        time.Duration `yaml:"critical" json:"critical"`                 // 1 day - MAJOR, CRITICAL, EXPLOIT ACTIVE
	KernelNetwork   time.Duration `yaml:"kernel_network" json:"kernel_network"`     // 2 days - Network or Kernel
	Software        time.Duration `yaml:"software" json:"software"`                 // 3 days - Software patches
	WindowsStandard time.Duration `yaml:"windows_standard" json:"windows_standard"` // 7 days - Windows patches
}

// ThreatIntelConfig holds threat intelligence configuration
type ThreatIntelConfig struct {
	Enabled      bool          `yaml:"enabled" json:"enabled"`
	SyncInterval time.Duration `yaml:"sync_interval" json:"sync_interval"`
	CacheTTL     time.Duration `yaml:"cache_ttl" json:"cache_ttl"`
}

// BaselineScannerConfig holds baseline scanner configuration
type BaselineScannerConfig struct {
	Enabled      bool          `yaml:"enabled" json:"enabled"`
	ScanInterval time.Duration `yaml:"scan_interval" json:"scan_interval"`
}

// NetworkMonitorConfig holds network monitor configuration
type NetworkMonitorConfig struct {
	Enabled            bool     `yaml:"enabled" json:"enabled"`
	DNSServers         []string `yaml:"dns_servers" json:"dns_servers"`
	AllowICMP          bool     `yaml:"allow_icmp" json:"allow_icmp"`
	BlockFragmentation bool     `yaml:"block_fragmentation" json:"block_fragmentation"`
}

// StorageConfig holds storage configuration
type StorageConfig struct {
	Backend         string        `yaml:"backend" json:"backend"`
	Path            string        `yaml:"path" json:"path"`
	BackupEnabled   bool          `yaml:"backup_enabled" json:"backup_enabled"`
	BackupRetention time.Duration `yaml:"backup_retention" json:"backup_retention"`
}

// IPCConfig holds IPC configuration
type IPCConfig struct {
	SocketPath    string `yaml:"socket_path" json:"socket_path"`
	AuthEnabled   bool   `yaml:"auth_enabled" json:"auth_enabled"`
	AuthTokenFile string `yaml:"auth_token_file" json:"auth_token_file"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Daemon: DaemonConfig{
			LogLevel: "info",
			DataDir:  "/var/lib/afterdark",
			PIDFile:  "/var/run/afterdark/darkd.pid",
		},
		API: APIConfig{
			AfterDark: EndpointConfig{
				URL:     "https://api.afterdarksys.com",
				Timeout: 30 * time.Second,
				Retry: RetryConfig{
					MaxAttempts: 3,
					InitialWait: 1 * time.Second,
					MaxWait:     30 * time.Second,
				},
			},
			DarkAPI: EndpointConfig{
				URL:     "https://api.darkapi.io",
				Timeout: 30 * time.Second,
				Retry: RetryConfig{
					MaxAttempts: 3,
					InitialWait: 1 * time.Second,
					MaxWait:     30 * time.Second,
				},
			},
			DNSScience: EndpointConfig{
				URL:     "https://api.dnsscience.io",
				Timeout: 10 * time.Second,
				Retry: RetryConfig{
					MaxAttempts: 2,
					InitialWait: 500 * time.Millisecond,
					MaxWait:     5 * time.Second,
				},
			},
			Veribits: EndpointConfig{
				URL:     "https://api.veribits.com",
				Timeout: 20 * time.Second,
			},
		},
		Services: ServicesConfig{
			PatchMonitor: PatchMonitorConfig{
				Enabled:            true,
				ScanInterval:       1 * time.Hour,
				AutoInstallWindows: true,
				UrgencyTiers: UrgencyTiers{
					Critical:        24 * time.Hour,  // 1 day
					KernelNetwork:   48 * time.Hour,  // 2 days
					Software:        72 * time.Hour,  // 3 days
					WindowsStandard: 168 * time.Hour, // 7 days
				},
			},
			ThreatIntel: ThreatIntelConfig{
				Enabled:      true,
				SyncInterval: 6 * time.Hour,
				CacheTTL:     24 * time.Hour,
			},
			BaselineScanner: BaselineScannerConfig{
				Enabled:      true,
				ScanInterval: 24 * time.Hour,
			},
			NetworkMonitor: NetworkMonitorConfig{
				Enabled: true,
				DNSServers: []string{
					"cache01.dnsscience.io",
					"cache02.dnsscience.io",
					"cache03.dnsscience.io",
					"cache04.dnsscience.io",
				},
				AllowICMP:          false,
				BlockFragmentation: true,
			},
		},
		Storage: StorageConfig{
			Backend:         "json",
			Path:            "/var/lib/afterdark/data",
			BackupEnabled:   true,
			BackupRetention: 720 * time.Hour, // 30 days
		},
		IPC: IPCConfig{
			SocketPath:    "/var/run/afterdark/darkd.sock",
			AuthEnabled:   true,
			AuthTokenFile: "/var/lib/afterdark/.auth_token",
		},
	}
}
