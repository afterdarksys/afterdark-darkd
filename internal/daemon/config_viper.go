package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// ViperConfig wraps Viper for configuration management
type ViperConfig struct {
	v *viper.Viper
}

// NewViperConfig creates a new Viper configuration manager
func NewViperConfig() *ViperConfig {
	v := viper.New()

	// Set defaults from models.DefaultConfig()
	setDefaults(v)

	// Environment variable configuration
	v.SetEnvPrefix("DARKD") // DARKD_DAEMON_LOGLEVEL, etc.
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	return &ViperConfig{v: v}
}

// LoadConfigViper loads configuration using Viper with full feature support
func LoadConfigViper(paths ...string) (*models.Config, error) {
	vc := NewViperConfig()
	return vc.Load(paths...)
}

// Load reads configuration from files, environment, and returns the config
func (vc *ViperConfig) Load(paths ...string) (*models.Config, error) {
	v := vc.v

	// Set config file search paths
	v.SetConfigName("darkd")
	v.SetConfigType("yaml")

	// Add default paths
	v.AddConfigPath("/etc/afterdark/")
	v.AddConfigPath("$HOME/.afterdark/")
	v.AddConfigPath(".")

	// Add any custom paths
	for _, p := range paths {
		if dir := filepath.Dir(p); dir != "" {
			v.AddConfigPath(dir)
		}
		if base := filepath.Base(p); base != "" {
			ext := filepath.Ext(base)
			name := strings.TrimSuffix(base, ext)
			v.SetConfigName(name)
			if ext != "" {
				v.SetConfigType(strings.TrimPrefix(ext, "."))
			}
		}
	}

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
		// Config file not found is OK, we'll use defaults + env
	}

	// Watch for config changes (optional - for hot reload)
	// v.WatchConfig()
	// v.OnConfigChange(func(e fsnotify.Event) {
	//     fmt.Println("Config file changed:", e.Name)
	// })

	// Unmarshal into config struct
	cfg := models.DefaultConfig()
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate
	if err := ValidateConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// GetViper returns the underlying Viper instance for advanced usage
func (vc *ViperConfig) GetViper() *viper.Viper {
	return vc.v
}

// ConfigFile returns the config file path being used
func (vc *ViperConfig) ConfigFile() string {
	return vc.v.ConfigFileUsed()
}

// WatchConfig enables hot reloading of config file changes
func (vc *ViperConfig) WatchConfig(onChange func(cfg *models.Config)) {
	vc.v.WatchConfig()
	vc.v.OnConfigChange(func(e fsnotify.Event) {
		cfg := models.DefaultConfig()
		if err := vc.v.Unmarshal(cfg); err == nil {
			if onChange != nil {
				onChange(cfg)
			}
		}
	})
}

// setDefaults configures Viper defaults from models.DefaultConfig
func setDefaults(v *viper.Viper) {
	// Daemon defaults
	v.SetDefault("daemon.log_level", "info")
	v.SetDefault("daemon.data_dir", "/var/lib/afterdark")
	v.SetDefault("daemon.pid_file", "/var/run/afterdark/darkd.pid")
	v.SetDefault("daemon.plugin_dir", "/var/lib/afterdark-darkd/plugins")

	// API defaults - AfterDark
	v.SetDefault("api.afterdark.url", "https://api.afterdarksys.com")
	v.SetDefault("api.afterdark.timeout", 30*time.Second)
	v.SetDefault("api.afterdark.retry.max_attempts", 3)
	v.SetDefault("api.afterdark.retry.initial_wait", time.Second)
	v.SetDefault("api.afterdark.retry.max_wait", 30*time.Second)

	// API defaults - DarkAPI
	v.SetDefault("api.darkapi.url", "https://api.darkapi.io")
	v.SetDefault("api.darkapi.timeout", 30*time.Second)
	v.SetDefault("api.darkapi.retry.max_attempts", 3)
	v.SetDefault("api.darkapi.retry.initial_wait", time.Second)
	v.SetDefault("api.darkapi.retry.max_wait", 30*time.Second)

	// API defaults - DNSScience
	v.SetDefault("api.dnsscience.url", "https://api.dnsscience.io")
	v.SetDefault("api.dnsscience.timeout", 10*time.Second)
	v.SetDefault("api.dnsscience.retry.max_attempts", 2)
	v.SetDefault("api.dnsscience.retry.initial_wait", 500*time.Millisecond)
	v.SetDefault("api.dnsscience.retry.max_wait", 5*time.Second)

	// API defaults - Veribits
	v.SetDefault("api.veribits.url", "https://api.veribits.com")
	v.SetDefault("api.veribits.timeout", 20*time.Second)

	// Services - Patch Monitor
	v.SetDefault("services.patch_monitor.enabled", true)
	v.SetDefault("services.patch_monitor.scan_interval", time.Hour)
	v.SetDefault("services.patch_monitor.auto_install_windows", true)
	v.SetDefault("services.patch_monitor.urgency_tiers.critical", 24*time.Hour)
	v.SetDefault("services.patch_monitor.urgency_tiers.kernel_network", 48*time.Hour)
	v.SetDefault("services.patch_monitor.urgency_tiers.software", 72*time.Hour)
	v.SetDefault("services.patch_monitor.urgency_tiers.windows_standard", 168*time.Hour)

	// Services - Threat Intel
	v.SetDefault("services.threat_intel.enabled", true)
	v.SetDefault("services.threat_intel.sync_interval", 6*time.Hour)
	v.SetDefault("services.threat_intel.cache_ttl", 24*time.Hour)

	// Services - Baseline Scanner
	v.SetDefault("services.baseline_scanner.enabled", true)
	v.SetDefault("services.baseline_scanner.scan_interval", 24*time.Hour)

	// Services - Network Monitor
	v.SetDefault("services.network_monitor.enabled", true)
	v.SetDefault("services.network_monitor.dns_servers", []string{
		"cache01.dnsscience.io",
		"cache02.dnsscience.io",
		"cache03.dnsscience.io",
		"cache04.dnsscience.io",
	})
	v.SetDefault("services.network_monitor.allow_icmp", false)
	v.SetDefault("services.network_monitor.block_fragmentation", true)

	// Services - Detonation Chamber
	v.SetDefault("services.detonation_chamber.enabled", false)
	v.SetDefault("services.detonation_chamber.watch_dirs", []string{"/var/lib/afterdark/quarantine"})
	v.SetDefault("services.detonation_chamber.quarantine_dir", "/var/lib/afterdark/quarantine")
	v.SetDefault("services.detonation_chamber.sandbox_type", "docker")
	v.SetDefault("services.detonation_chamber.docker_image", "afterdark/detonation-chamber:latest")
	v.SetDefault("services.detonation_chamber.max_concurrent", 2)
	v.SetDefault("services.detonation_chamber.detonation_timeout", 5*time.Minute)
	v.SetDefault("services.detonation_chamber.max_file_size", 100*1024*1024) // 100MB
	v.SetDefault("services.detonation_chamber.supported_types", []string{
		".exe", ".dll", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js",
		".jar", ".py", ".sh", ".elf", ".dmg", ".app", ".pkg", ".scr", ".com",
		".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm",
		".pdf", ".rtf", ".odt", ".ods",
		".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso", ".img",
		".hta", ".wsf", ".wsh", ".lnk", ".url",
	})
	v.SetDefault("services.detonation_chamber.auto_submit", true)
	v.SetDefault("services.detonation_chamber.retain_samples", 30*24*time.Hour)
	v.SetDefault("services.detonation_chamber.enable_yara", true)
	v.SetDefault("services.detonation_chamber.yara_rules_dir", "/var/lib/afterdark/yara")
	v.SetDefault("services.detonation_chamber.portal_upload.enabled", true)
	v.SetDefault("services.detonation_chamber.portal_upload.upload_samples", false)
	v.SetDefault("services.detonation_chamber.portal_upload.upload_reports", true)
	v.SetDefault("services.detonation_chamber.portal_upload.upload_iocs", true)
	v.SetDefault("services.detonation_chamber.portal_upload.min_threat_score", 50)
	v.SetDefault("services.detonation_chamber.portal_upload.batch_size", 100)
	v.SetDefault("services.detonation_chamber.portal_upload.batch_interval", 5*time.Minute)

	// Storage
	v.SetDefault("storage.backend", "json")
	v.SetDefault("storage.path", "/var/lib/afterdark/data")
	v.SetDefault("storage.backup_enabled", true)
	v.SetDefault("storage.backup_retention", 720*time.Hour) // 30 days

	// IPC
	v.SetDefault("ipc.socket_path", "/var/run/afterdark/darkd.sock")
	v.SetDefault("ipc.auth_enabled", true)
	v.SetDefault("ipc.auth_token_file", "/var/lib/afterdark/.auth_token")
}

// BindFlags binds cobra command flags to viper for CLI integration
func (vc *ViperConfig) BindFlags(flagName, configKey string) {
	// This would be called from cmd/ to bind CLI flags
	// Example: vc.BindFlags("log-level", "daemon.log_level")
}

// SetConfigFile explicitly sets the config file to use
func (vc *ViperConfig) SetConfigFile(path string) {
	vc.v.SetConfigFile(path)
}

// GetString returns a string config value
func (vc *ViperConfig) GetString(key string) string {
	return vc.v.GetString(key)
}

// GetInt returns an int config value
func (vc *ViperConfig) GetInt(key string) int {
	return vc.v.GetInt(key)
}

// GetBool returns a bool config value
func (vc *ViperConfig) GetBool(key string) bool {
	return vc.v.GetBool(key)
}

// GetDuration returns a duration config value
func (vc *ViperConfig) GetDuration(key string) time.Duration {
	return vc.v.GetDuration(key)
}

// Set sets a config value (for runtime updates)
func (vc *ViperConfig) Set(key string, value interface{}) {
	vc.v.Set(key, value)
}

// WriteConfig writes the current config to file
func (vc *ViperConfig) WriteConfig() error {
	return vc.v.WriteConfig()
}

// WriteConfigAs writes config to a specific file
func (vc *ViperConfig) WriteConfigAs(filename string) error {
	return vc.v.WriteConfigAs(filename)
}

// SafeWriteConfig writes config only if file doesn't exist
func (vc *ViperConfig) SafeWriteConfig() error {
	return vc.v.SafeWriteConfig()
}

// PrintConfig outputs current config for debugging
func (vc *ViperConfig) PrintConfig() {
	for _, key := range vc.v.AllKeys() {
		fmt.Printf("%s = %v\n", key, vc.v.Get(key))
	}
}

// Environment variable mappings for common settings
// These can be set instead of editing config files:
//
// DARKD_DAEMON_LOGLEVEL=debug
// DARKD_API_AFTERDARK_APIKEY=xxx
// DARKD_API_DARKAPI_APIKEY=xxx
// DARKD_SERVICES_DETONATION_CHAMBER_ENABLED=true
// DARKD_STORAGE_PATH=/custom/path
// etc.

// GetEnvHelp returns help text for environment variables
func GetEnvHelp() string {
	return `
Environment Variables:

All configuration options can be set via environment variables using the
DARKD_ prefix. Nested keys use underscores.

Examples:
  DARKD_DAEMON_LOGLEVEL=debug          Set log level to debug
  DARKD_API_AFTERDARK_APIKEY=xxx       Set AfterDark API key
  DARKD_API_DARKAPI_APIKEY=xxx         Set DarkAPI key
  DARKD_SERVICES_DETONATION_CHAMBER_ENABLED=true  Enable detonation chamber
  DARKD_STORAGE_PATH=/data             Set storage path

For secrets, environment variables are recommended over config files.
`
}

// initConfigDir creates the config directory if it doesn't exist
func initConfigDir() error {
	dirs := []string{
		"/etc/afterdark",
		filepath.Join(os.Getenv("HOME"), ".afterdark"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			// Skip if can't create (e.g., no permissions for /etc)
			continue
		}
	}

	return nil
}
