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
	LogLevel  string `yaml:"log_level" json:"log_level"`
	DataDir   string `yaml:"data_dir" json:"data_dir"`
	PIDFile   string `yaml:"pid_file" json:"pid_file"`
	PluginDir string `yaml:"plugin_dir" json:"plugin_dir"`
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
	PatchMonitor       PatchMonitorConfig    `yaml:"patch_monitor" json:"patch_monitor"`
	ProcessMonitor     TrackingConfig        `yaml:"process_monitor" json:"process_monitor"`
	ThreatIntel        ThreatIntelConfig     `yaml:"threat_intel" json:"threat_intel"`
	BaselineScanner    BaselineScannerConfig `yaml:"baseline_scanner" json:"baseline_scanner"`
	NetworkMonitor     NetworkMonitorConfig  `yaml:"network_monitor" json:"network_monitor"`
	DetonationChamber  DetonationConfig      `yaml:"detonation_chamber" json:"detonation_chamber"`
	C2Detection        C2DetectionConfig     `yaml:"c2_detection" json:"c2_detection"`
	DNSTunnelDetection DNSTunnelConfig       `yaml:"dns_tunnel_detection" json:"dns_tunnel_detection"`
	MemoryScanner      MemoryScannerConfig   `yaml:"memory_scanner" json:"memory_scanner"`
	IntegrityMonitor   IntegrityConfig       `yaml:"integrity_monitor" json:"integrity_monitor"`
	PersistenceMonitor PersistenceConfig     `yaml:"persistence_monitor" json:"persistence_monitor"`
	SysMonitor         SysMonitorConfig      `yaml:"sys_monitor" json:"sys_monitor"`
	ActivityMonitor    ActivityConfig        `yaml:"activity_monitor" json:"activity_monitor"`
	MLEngine           MLEngineConfig        `yaml:"ml_engine" json:"ml_engine"`
	Canary             CanaryConfig          `yaml:"canary" json:"canary"`
	Honeypot           HoneypotConfig        `yaml:"honeypot" json:"honeypot"`
	DeviceControl      DeviceControlConfig   `yaml:"device_control" json:"device_control"`
	DLP                DLPConfig             `yaml:"dlp" json:"dlp"`
	NetworkDrift       NetworkDriftConfig    `yaml:"network_drift" json:"network_drift"`
	CloudMetadata      CloudMetadataConfig   `yaml:"cloud_metadata" json:"cloud_metadata"`
	AppLockdown        AppLockdownConfig     `yaml:"app_lockdown" json:"app_lockdown"`
	Scripting          ScriptingConfig       `yaml:"scripting" json:"scripting"`
	SIEM               SIEMConfig            `yaml:"siem" json:"siem"`
	EBPF               EBPFConfig            `yaml:"ebpf" json:"ebpf"`
	ESF                ESFConfig             `yaml:"esf" json:"esf"`
	ETW                ETWConfig             `yaml:"etw" json:"etw"`
	Registry           RegistryConfig        `yaml:"registry" json:"registry"`
}

// C2DetectionConfig holds C2/beaconing detection configuration
type C2DetectionConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	MinConnections        int           `yaml:"min_connections" json:"min_connections"`
	AnalysisWindow        time.Duration `yaml:"analysis_window" json:"analysis_window"`
	BeaconThreshold       float64       `yaml:"beacon_threshold" json:"beacon_threshold"`
	CheckInterval         time.Duration `yaml:"check_interval" json:"check_interval"`
	KnownGoodDestinations []string      `yaml:"known_good_destinations" json:"known_good_destinations"`
}

// DNSTunnelConfig holds DNS tunneling detection configuration
type DNSTunnelConfig struct {
	Enabled              bool          `yaml:"enabled" json:"enabled"`
	CaptureMethod        string        `yaml:"capture_method" json:"capture_method"` // "pcap", "logs", "etw"
	AnalysisWindow       time.Duration `yaml:"analysis_window" json:"analysis_window"`
	EntropyThreshold     float64       `yaml:"entropy_threshold" json:"entropy_threshold"`
	TunnelScoreThreshold float64       `yaml:"tunnel_score_threshold" json:"tunnel_score_threshold"`
	CheckInterval        time.Duration `yaml:"check_interval" json:"check_interval"`
	WhitelistDomains     []string      `yaml:"whitelist_domains" json:"whitelist_domains"`
}

// MemoryScannerConfig holds memory scanning configuration
type MemoryScannerConfig struct {
	Enabled            bool          `yaml:"enabled" json:"enabled"`
	ScanInterval       time.Duration `yaml:"scan_interval" json:"scan_interval"`
	ScanOnNewProcess   bool          `yaml:"scan_on_new_process" json:"scan_on_new_process"`
	YaraRulesDir       string        `yaml:"yara_rules_dir" json:"yara_rules_dir"`
	TargetProcesses    []string      `yaml:"target_processes" json:"target_processes"`
	ExcludeProcesses   []string      `yaml:"exclude_processes" json:"exclude_processes"`
	MaxMemoryPerScan   int64         `yaml:"max_memory_per_scan" json:"max_memory_per_scan"`
	ScanTimeout        time.Duration `yaml:"scan_timeout" json:"scan_timeout"`
	MaxConcurrentScans int           `yaml:"max_concurrent_scans" json:"max_concurrent_scans"`
	CheckRWXRegions    bool          `yaml:"check_rwx_regions" json:"check_rwx_regions"`
	CheckUnbackedCode  bool          `yaml:"check_unbacked_code" json:"check_unbacked_code"`
	DetectInjection    bool          `yaml:"detect_injection" json:"detect_injection"`
	MonitorLSASS       bool          `yaml:"monitor_lsass" json:"monitor_lsass"` // Windows only
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
	Enabled            bool           `yaml:"enabled" json:"enabled"`
	DNSServers         []string       `yaml:"dns_servers" json:"dns_servers"`
	AllowICMP          bool           `yaml:"allow_icmp" json:"allow_icmp"`
	BlockFragmentation bool           `yaml:"block_fragmentation" json:"block_fragmentation"`
	Tracking           TrackingConfig `yaml:"tracking" json:"tracking"`
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
			LogLevel:  "info",
			DataDir:   "/var/lib/afterdark",
			PIDFile:   "/var/run/afterdark/darkd.pid",
			PluginDir: "/var/lib/afterdark-darkd/plugins",
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
			DetonationChamber: DetonationConfig{
				Enabled:           false, // Disabled by default - requires explicit opt-in
				WatchDirs:         []string{"/var/lib/afterdark/quarantine"},
				QuarantineDir:     "/var/lib/afterdark/quarantine",
				SandboxType:       "docker",
				DockerImage:       "afterdark/detonation-chamber:latest",
				MaxConcurrent:     2,
				DetonationTimeout: 5 * time.Minute,
				MaxFileSize:       100 * 1024 * 1024, // 100MB
				SupportedTypes: []string{
					// Executables
					".exe", ".dll", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js",
					".jar", ".py", ".sh", ".elf", ".dmg", ".app", ".pkg", ".scr", ".com",
					// Documents (macro-enabled)
					".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm",
					".pdf", ".rtf", ".odt", ".ods",
					// Archives
					".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso", ".img",
					// Scripts
					".hta", ".wsf", ".wsh", ".lnk", ".url",
				},
				AutoSubmit:    true,
				RetainSamples: 30 * 24 * time.Hour, // 30 days
				EnableYara:    true,
				YaraRulesDir:  "/var/lib/afterdark/yara",
				PortalUpload: PortalUploadConfig{
					Enabled:        true,
					UploadSamples:  false, // Don't upload actual malware by default
					UploadReports:  true,
					UploadIOCs:     true,
					MinThreatScore: 50,
					BatchSize:      100,
					BatchInterval:  5 * time.Minute,
				},
			},
			C2Detection: C2DetectionConfig{
				Enabled:         true,
				MinConnections:  10,
				AnalysisWindow:  1 * time.Hour,
				BeaconThreshold: 60.0,
				CheckInterval:   5 * time.Minute,
				KnownGoodDestinations: []string{
					"*.microsoft.com",
					"*.apple.com",
					"*.google.com",
					"*.amazonaws.com",
				},
			},
			DNSTunnelDetection: DNSTunnelConfig{
				Enabled:              true,
				CaptureMethod:        "logs", // Safe default, pcap requires elevated privileges
				AnalysisWindow:       15 * time.Minute,
				EntropyThreshold:     3.8,
				TunnelScoreThreshold: 60.0,
				CheckInterval:        1 * time.Minute,
				WhitelistDomains: []string{
					"*.cloudflare.com",
					"*.akamai.com",
					"*.fastly.net",
				},
			},
			MemoryScanner: MemoryScannerConfig{
				Enabled:            false, // Disabled by default - performance impact
				ScanInterval:       30 * time.Minute,
				ScanOnNewProcess:   true,
				YaraRulesDir:       "/var/lib/afterdark/yara",
				TargetProcesses:    []string{}, // Empty = all with network connections
				ExcludeProcesses:   []string{"systemd", "kernel", "init"},
				MaxMemoryPerScan:   100 * 1024 * 1024, // 100MB
				ScanTimeout:        60 * time.Second,
				MaxConcurrentScans: 2,
				CheckRWXRegions:    true,
				CheckUnbackedCode:  true,
				DetectInjection:    true,
				MonitorLSASS:       true, // Windows only
			},
			IntegrityMonitor: IntegrityConfig{
				Enabled:  true,
				Interval: 5 * time.Minute,
			},
			PersistenceMonitor: PersistenceConfig{
				Enabled:  true,
				Interval: 10 * time.Minute,
			},
			SysMonitor: SysMonitorConfig{
				Enabled:  true,
				Interval: 30 * time.Second,
			},
			ActivityMonitor: ActivityConfig{
				Enabled:  true,
				Interval: 1 * time.Minute,
			},
			MLEngine: MLEngineConfig{
				Enabled:          true,
				TrainingInterval: 1 * time.Hour,
				ModelPath:        "/var/lib/afterdark/models",
			},
			Canary: CanaryConfig{
				Enabled:        true,
				DecoyPaths:     []string{"/tmp"},
				DecoyFilenames: []string{".canary.docx"},
			},
			Honeypot: HoneypotConfig{
				Enabled: true,
				Ports:   []int{2323, 33890},
			},
			DeviceControl: DeviceControlConfig{
				Enabled:        true,
				BlockedVendors: []string{},
			},
			DLP: DLPConfig{
				Enabled:  true,
				Keywords: []string{"CONFIDENTIAL", "PASSWORD", "API KEY"},
			},
			NetworkDrift: NetworkDriftConfig{
				Enabled:      true,
				ScanInterval: 5 * time.Minute,
			},
			CloudMetadata: CloudMetadataConfig{
				Enabled:      true,
				MetadataIPs:  []string{"169.254.169.254"},
				AllowedUsers: []string{"root", "daemon"},
			},
			AppLockdown: AppLockdownConfig{
				Enabled:           false,
				Allowlist:         []string{},
				BlockNewProcesses: false,
			},
			Scripting: ScriptingConfig{
				Enabled:    true,
				PolicyPath: "/etc/afterdark/policies",
			},
			SIEM: SIEMConfig{
				Enabled:   false,
				BatchSize: 100,
			},
			EBPF: EBPFConfig{
				Enabled: true,
			},
			ESF: ESFConfig{
				Enabled: true,
			},
			ETW: ETWConfig{
				Enabled: true,
			},
			Registry: RegistryConfig{
				Enabled:  true,
				Interval: 30 * time.Second,
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

// IntegrityConfig holds integrity monitoring configuration
type IntegrityConfig struct {
	Enabled      bool          `yaml:"enabled" json:"enabled"`
	Interval     time.Duration `yaml:"interval" json:"interval"`
	WatchedFiles []string      `yaml:"watched_files" json:"watched_files"`
}

// PersistenceConfig holds persistence monitoring configuration
type PersistenceConfig struct {
	Enabled  bool          `yaml:"enabled" json:"enabled"`
	Interval time.Duration `yaml:"interval" json:"interval"`
}

// SysMonitorConfig holds system monitoring configuration
type SysMonitorConfig struct {
	Enabled  bool          `yaml:"enabled" json:"enabled"`
	Interval time.Duration `yaml:"interval" json:"interval"`
}

// ActivityConfig holds activity monitoring configuration
type ActivityConfig struct {
	Enabled  bool          `yaml:"enabled" json:"enabled"`
	Interval time.Duration `yaml:"interval" json:"interval"`
}

// MLEngineConfig holds machine learning engine configuration
type MLEngineConfig struct {
	Enabled          bool          `yaml:"enabled" json:"enabled"`
	TrainingInterval time.Duration `yaml:"training_interval" json:"training_interval"`
	ModelPath        string        `yaml:"model_path" json:"model_path"`
}

// CanaryConfig holds ransomware canary configuration
type CanaryConfig struct {
	Enabled        bool     `yaml:"enabled" json:"enabled"`
	DecoyPaths     []string `yaml:"decoy_paths" json:"decoy_paths"`
	DecoyFilenames []string `yaml:"decoy_filenames" json:"decoy_filenames"`
}

// HoneypotConfig holds honeypot configuration
type HoneypotConfig struct {
	Enabled bool  `yaml:"enabled" json:"enabled"`
	Ports   []int `yaml:"ports" json:"ports"`
}

// DeviceControlConfig holds device control configuration
type DeviceControlConfig struct {
	Enabled        bool     `yaml:"enabled" json:"enabled"`
	BlockedVendors []string `yaml:"blocked_vendors" json:"blocked_vendors"`
}

// DLPConfig holds data loss prevention configuration
type DLPConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	Keywords      []string `yaml:"keywords" json:"keywords"`
	RegexPatterns []string `yaml:"regex_patterns" json:"regex_patterns"`
}

// NetworkDriftConfig holds network drift configuration
type NetworkDriftConfig struct {
	Enabled      bool          `yaml:"enabled" json:"enabled"`
	ScanInterval time.Duration `yaml:"scan_interval" json:"scan_interval"`
}

// CloudMetadataConfig holds cloud metadata sentinel configuration
type CloudMetadataConfig struct {
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	MetadataIPs  []string `yaml:"metadata_ips" json:"metadata_ips"`
	AllowedUsers []string `yaml:"allowed_users" json:"allowed_users"`
}

// AppLockdownConfig holds application lockdown configuration
type AppLockdownConfig struct {
	Enabled           bool     `yaml:"enabled" json:"enabled"`
	Allowlist         []string `yaml:"allowlist" json:"allowlist"`
	BlockNewProcesses bool     `yaml:"block_new_processes" json:"block_new_processes"`
}

// ScriptingConfig holds scripting engine configuration
type ScriptingConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	PolicyPath string `yaml:"policy_path" json:"policy_path"`
}

// SIEMConfig holds SIEM forwarder configuration
type SIEMConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	URL       string `yaml:"url" json:"url"`
	AuthToken string `yaml:"auth_token" json:"auth_token"`
	BatchSize int    `yaml:"batch_size" json:"batch_size"`
}

// EBPFConfig holds eBPF service configuration
type EBPFConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// ESFConfig holds ESF service configuration
type ESFConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// ETWConfig holds ETW service configuration (Windows)
type ETWConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// RegistryConfig holds Registry monitoring configuration (Windows)
type RegistryConfig struct {
	Enabled  bool          `yaml:"enabled" json:"enabled"`
	Interval time.Duration `yaml:"interval" json:"interval"`
}
