// Package autoconfig provides automatic configuration discovery for the agent.
//
// The agent can discover its API key and configuration from multiple sources:
//
// 1. Environment Variables:
//    - AFTERDARK_API_KEY: API key for authentication
//    - AFTERDARK_API_ENDPOINT: Custom API endpoint
//    - AFTERDARK_DEVICE_TOKEN: Pre-provisioned device token
//
// 2. Configuration Files (checked in order):
//    - /etc/afterdark/api-key (Linux/macOS)
//    - C:\ProgramData\AfterDark\api-key (Windows)
//    - ~/.afterdark/api-key (user-level)
//
// 3. Cloud Metadata Services:
//    - AWS EC2 Instance Metadata (tags)
//    - Azure Instance Metadata
//    - GCP Instance Metadata
//
// 4. MDM/Enterprise Deployment:
//    - Jamf Pro (macOS)
//    - Microsoft Intune (Windows)
//    - Ansible/Puppet/Chef pushed configurations
//
// 5. Enrollment Token:
//    - One-time use enrollment token from portal
//    - Exchanges token for permanent API key
//
// 6. Manual Configuration:
//    - darkd-config GUI helper
//    - CLI: afterdark-darkdadm config set-key
package autoconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	// API endpoints
	defaultAPIEndpoint = "https://api.afterdark.io"
	enrollmentPath     = "/v1/devices/enroll"
	configPath         = "/v1/devices/config"
	heartbeatPath      = "/v1/devices/heartbeat"

	// Cloud metadata endpoints
	awsMetadataURL   = "http://169.254.169.254/latest/meta-data/"
	awsIMDSTokenURL  = "http://169.254.169.254/latest/api/token"
	azureMetadataURL = "http://169.254.169.254/metadata/instance"
	gcpMetadataURL   = "http://metadata.google.internal/computeMetadata/v1/"

	// Environment variables
	envAPIKey        = "AFTERDARK_API_KEY"
	envAPIEndpoint   = "AFTERDARK_API_ENDPOINT"
	envDeviceToken   = "AFTERDARK_DEVICE_TOKEN"
	envEnrollToken   = "AFTERDARK_ENROLL_TOKEN"
	envOrgID         = "AFTERDARK_ORG_ID"
	envDisableCloud  = "AFTERDARK_DISABLE_CLOUD"
)

// Source represents where configuration was discovered
type Source string

const (
	SourceUnknown     Source = "unknown"
	SourceEnv         Source = "environment"
	SourceFile        Source = "file"
	SourceAWS         Source = "aws"
	SourceAzure       Source = "azure"
	SourceGCP         Source = "gcp"
	SourceMDM         Source = "mdm"
	SourceEnrollment  Source = "enrollment"
	SourceManual      Source = "manual"
)

// Config represents the discovered configuration
type Config struct {
	// Authentication
	APIKey       string `json:"api_key"`
	APIEndpoint  string `json:"api_endpoint"`
	DeviceToken  string `json:"device_token,omitempty"`
	OrgID        string `json:"org_id,omitempty"`

	// Device identification
	DeviceID     string `json:"device_id"`
	Hostname     string `json:"hostname"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`

	// Discovery metadata
	Source       Source    `json:"source"`
	DiscoveredAt time.Time `json:"discovered_at"`
	LastSync     time.Time `json:"last_sync,omitempty"`

	// Feature flags from cloud
	Features     map[string]bool   `json:"features,omitempty"`
	Settings     map[string]string `json:"settings,omitempty"`

	// Enterprise configuration
	EnterpriseConfig *EnterpriseConfig `json:"enterprise_config,omitempty"`
}

// EnterpriseConfig contains enterprise-specific settings
type EnterpriseConfig struct {
	// Fleet management
	FleetID        string   `json:"fleet_id,omitempty"`
	HostTemplateID string   `json:"host_template_id,omitempty"`
	Tags           []string `json:"tags,omitempty"`

	// Policy
	PolicyID       string `json:"policy_id,omitempty"`
	PolicyVersion  int    `json:"policy_version,omitempty"`

	// Reporting
	ReportEndpoint string `json:"report_endpoint,omitempty"`
	SIEMEndpoint   string `json:"siem_endpoint,omitempty"`

	// Management
	MDMManaged     bool   `json:"mdm_managed"`
	MDMProvider    string `json:"mdm_provider,omitempty"`
}

// EnrollmentRequest is sent when enrolling a new device
type EnrollmentRequest struct {
	EnrollmentToken string `json:"enrollment_token,omitempty"`
	DeviceToken     string `json:"device_token,omitempty"`
	Hostname        string `json:"hostname"`
	Platform        string `json:"platform"`
	Architecture    string `json:"architecture"`
	AgentVersion    string `json:"agent_version"`
	MachineID       string `json:"machine_id,omitempty"`
}

// EnrollmentResponse is returned after successful enrollment
type EnrollmentResponse struct {
	Success     bool   `json:"success"`
	DeviceID    string `json:"device_id"`
	APIKey      string `json:"api_key"`
	Message     string `json:"message,omitempty"`
	ConfigURL   string `json:"config_url,omitempty"`
}

// AutoConfig handles automatic configuration discovery
type AutoConfig struct {
	mu           sync.RWMutex
	config       *Config
	httpClient   *http.Client
	agentVersion string

	// Callbacks
	onConfigUpdate func(*Config)
	onError        func(error)
}

// New creates a new AutoConfig instance
func New(agentVersion string) *AutoConfig {
	return &AutoConfig{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		agentVersion: agentVersion,
	}
}

// SetOnConfigUpdate sets the callback for configuration updates
func (ac *AutoConfig) SetOnConfigUpdate(fn func(*Config)) {
	ac.onConfigUpdate = fn
}

// SetOnError sets the callback for errors
func (ac *AutoConfig) SetOnError(fn func(error)) {
	ac.onError = fn
}

// Discover attempts to discover configuration from all sources
func (ac *AutoConfig) Discover(ctx context.Context) (*Config, error) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// Check if cloud is disabled
	if os.Getenv(envDisableCloud) == "true" {
		return ac.discoverOffline()
	}

	// Try sources in order of priority
	sources := []func(context.Context) (*Config, error){
		ac.discoverFromEnv,
		ac.discoverFromFile,
		ac.discoverFromCloudMetadata,
		ac.discoverFromMDM,
		ac.discoverFromEnrollmentToken,
	}

	for _, discover := range sources {
		cfg, err := discover(ctx)
		if err != nil {
			continue
		}
		if cfg != nil && cfg.APIKey != "" {
			ac.config = cfg
			return cfg, nil
		}
	}

	return nil, fmt.Errorf("no configuration found from any source")
}

// discoverFromEnv checks environment variables
func (ac *AutoConfig) discoverFromEnv(ctx context.Context) (*Config, error) {
	apiKey := os.Getenv(envAPIKey)
	if apiKey == "" {
		return nil, fmt.Errorf("no API key in environment")
	}

	endpoint := os.Getenv(envAPIEndpoint)
	if endpoint == "" {
		endpoint = defaultAPIEndpoint
	}

	return &Config{
		APIKey:       apiKey,
		APIEndpoint:  endpoint,
		DeviceToken:  os.Getenv(envDeviceToken),
		OrgID:        os.Getenv(envOrgID),
		Hostname:     ac.getHostname(),
		Platform:     runtime.GOOS,
		Architecture: runtime.GOARCH,
		Source:       SourceEnv,
		DiscoveredAt: time.Now(),
	}, nil
}

// discoverFromFile checks configuration files
func (ac *AutoConfig) discoverFromFile(ctx context.Context) (*Config, error) {
	paths := ac.getConfigPaths()

	for _, path := range paths {
		apiKey, err := ac.readAPIKeyFile(path)
		if err != nil {
			continue
		}
		if apiKey != "" {
			return &Config{
				APIKey:       apiKey,
				APIEndpoint:  defaultAPIEndpoint,
				Hostname:     ac.getHostname(),
				Platform:     runtime.GOOS,
				Architecture: runtime.GOARCH,
				Source:       SourceFile,
				DiscoveredAt: time.Now(),
			}, nil
		}
	}

	return nil, fmt.Errorf("no API key file found")
}

// discoverFromCloudMetadata checks cloud provider metadata
func (ac *AutoConfig) discoverFromCloudMetadata(ctx context.Context) (*Config, error) {
	// Try each cloud provider
	providers := []struct {
		name    string
		fn      func(context.Context) (*Config, error)
		source  Source
	}{
		{"AWS", ac.discoverFromAWS, SourceAWS},
		{"Azure", ac.discoverFromAzure, SourceAzure},
		{"GCP", ac.discoverFromGCP, SourceGCP},
	}

	for _, provider := range providers {
		cfg, err := provider.fn(ctx)
		if err == nil && cfg != nil {
			cfg.Source = provider.source
			return cfg, nil
		}
	}

	return nil, fmt.Errorf("not running in cloud environment")
}

// discoverFromAWS checks AWS EC2 instance metadata
func (ac *AutoConfig) discoverFromAWS(ctx context.Context) (*Config, error) {
	// Get IMDSv2 token
	tokenReq, _ := http.NewRequestWithContext(ctx, "PUT", awsIMDSTokenURL, nil)
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	tokenResp, err := ac.httpClient.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("not on AWS: %w", err)
	}
	defer tokenResp.Body.Close()

	token, _ := io.ReadAll(tokenResp.Body)

	// Get instance tags
	tagsReq, _ := http.NewRequestWithContext(ctx, "GET", awsMetadataURL+"tags/instance/", nil)
	tagsReq.Header.Set("X-aws-ec2-metadata-token", string(token))

	tagsResp, err := ac.httpClient.Do(tagsReq)
	if err != nil {
		return nil, err
	}
	defer tagsResp.Body.Close()

	// Look for afterdark-api-key tag
	tagList, _ := io.ReadAll(tagsResp.Body)
	tags := strings.Split(string(tagList), "\n")

	for _, tag := range tags {
		if strings.HasPrefix(strings.ToLower(tag), "afterdark") {
			// Get tag value
			valueReq, _ := http.NewRequestWithContext(ctx, "GET", awsMetadataURL+"tags/instance/"+tag, nil)
			valueReq.Header.Set("X-aws-ec2-metadata-token", string(token))

			valueResp, err := ac.httpClient.Do(valueReq)
			if err != nil {
				continue
			}
			value, _ := io.ReadAll(valueResp.Body)
			valueResp.Body.Close()

			if strings.ToLower(tag) == "afterdark-api-key" {
				return &Config{
					APIKey:       string(value),
					APIEndpoint:  defaultAPIEndpoint,
					Hostname:     ac.getHostname(),
					Platform:     runtime.GOOS,
					Architecture: runtime.GOARCH,
					Source:       SourceAWS,
					DiscoveredAt: time.Now(),
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no AfterDark tags found")
}

// discoverFromAzure checks Azure instance metadata
func (ac *AutoConfig) discoverFromAzure(ctx context.Context) (*Config, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", azureMetadataURL+"?api-version=2021-02-01", nil)
	req.Header.Set("Metadata", "true")

	resp, err := ac.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("not on Azure: %w", err)
	}
	defer resp.Body.Close()

	var metadata struct {
		Compute struct {
			TagsList []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"tagsList"`
		} `json:"compute"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, err
	}

	for _, tag := range metadata.Compute.TagsList {
		if strings.ToLower(tag.Name) == "afterdark-api-key" {
			return &Config{
				APIKey:       tag.Value,
				APIEndpoint:  defaultAPIEndpoint,
				Hostname:     ac.getHostname(),
				Platform:     runtime.GOOS,
				Architecture: runtime.GOARCH,
				Source:       SourceAzure,
				DiscoveredAt: time.Now(),
			}, nil
		}
	}

	return nil, fmt.Errorf("no AfterDark tags found")
}

// discoverFromGCP checks GCP instance metadata
func (ac *AutoConfig) discoverFromGCP(ctx context.Context) (*Config, error) {
	// Check for afterdark-api-key attribute
	req, _ := http.NewRequestWithContext(ctx, "GET",
		gcpMetadataURL+"instance/attributes/afterdark-api-key", nil)
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := ac.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("not on GCP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("no afterdark-api-key attribute")
	}

	apiKey, _ := io.ReadAll(resp.Body)

	return &Config{
		APIKey:       string(apiKey),
		APIEndpoint:  defaultAPIEndpoint,
		Hostname:     ac.getHostname(),
		Platform:     runtime.GOOS,
		Architecture: runtime.GOARCH,
		Source:       SourceGCP,
		DiscoveredAt: time.Now(),
	}, nil
}

// discoverFromMDM checks for MDM-pushed configuration
func (ac *AutoConfig) discoverFromMDM(ctx context.Context) (*Config, error) {
	switch runtime.GOOS {
	case "darwin":
		return ac.discoverFromJamf()
	case "windows":
		return ac.discoverFromIntune()
	}
	return nil, fmt.Errorf("no MDM support for this platform")
}

// discoverFromJamf checks for Jamf Pro configuration
func (ac *AutoConfig) discoverFromJamf() (*Config, error) {
	// Jamf typically uses profiles to push configuration
	// Check for managed preference
	prefPath := "/Library/Managed Preferences/com.afterdark.darkd.plist"
	if _, err := os.Stat(prefPath); err != nil {
		return nil, fmt.Errorf("no Jamf configuration")
	}

	// Would parse plist here
	return nil, fmt.Errorf("Jamf configuration parsing not implemented")
}

// discoverFromIntune checks for Microsoft Intune configuration
func (ac *AutoConfig) discoverFromIntune() (*Config, error) {
	// Intune uses registry for configuration
	// Would check: HKLM\SOFTWARE\AfterDark\
	return nil, fmt.Errorf("Intune configuration not implemented")
}

// discoverFromEnrollmentToken exchanges an enrollment token for an API key
func (ac *AutoConfig) discoverFromEnrollmentToken(ctx context.Context) (*Config, error) {
	enrollToken := os.Getenv(envEnrollToken)
	if enrollToken == "" {
		// Check file
		paths := []string{
			"/etc/afterdark/enroll-token",
			filepath.Join(os.Getenv("HOME"), ".afterdark", "enroll-token"),
		}
		if runtime.GOOS == "windows" {
			paths = append(paths, `C:\ProgramData\AfterDark\enroll-token`)
		}

		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err == nil {
				enrollToken = strings.TrimSpace(string(data))
				break
			}
		}
	}

	if enrollToken == "" {
		return nil, fmt.Errorf("no enrollment token")
	}

	// Exchange token for API key
	return ac.enroll(ctx, enrollToken)
}

// enroll exchanges an enrollment token for a permanent API key
func (ac *AutoConfig) enroll(ctx context.Context, token string) (*Config, error) {
	req := EnrollmentRequest{
		EnrollmentToken: token,
		Hostname:        ac.getHostname(),
		Platform:        runtime.GOOS,
		Architecture:    runtime.GOARCH,
		AgentVersion:    ac.agentVersion,
		MachineID:       ac.getMachineID(),
	}

	body, _ := json.Marshal(req)

	httpReq, _ := http.NewRequestWithContext(ctx, "POST",
		defaultAPIEndpoint+enrollmentPath, strings.NewReader(string(body)))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := ac.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("enrollment failed: %w", err)
	}
	defer resp.Body.Close()

	var enrollResp EnrollmentResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return nil, fmt.Errorf("failed to parse enrollment response: %w", err)
	}

	if !enrollResp.Success {
		return nil, fmt.Errorf("enrollment rejected: %s", enrollResp.Message)
	}

	// Save the API key
	cfg := &Config{
		APIKey:       enrollResp.APIKey,
		APIEndpoint:  defaultAPIEndpoint,
		DeviceID:     enrollResp.DeviceID,
		Hostname:     ac.getHostname(),
		Platform:     runtime.GOOS,
		Architecture: runtime.GOARCH,
		Source:       SourceEnrollment,
		DiscoveredAt: time.Now(),
	}

	// Persist the API key
	ac.saveAPIKey(cfg.APIKey)

	// Delete the enrollment token
	ac.deleteEnrollmentToken()

	return cfg, nil
}

// discoverOffline returns a minimal offline configuration
func (ac *AutoConfig) discoverOffline() (*Config, error) {
	return &Config{
		APIEndpoint:  "",
		Hostname:     ac.getHostname(),
		Platform:     runtime.GOOS,
		Architecture: runtime.GOARCH,
		Source:       SourceManual,
		DiscoveredAt: time.Now(),
		Features: map[string]bool{
			"offline_mode": true,
		},
	}, nil
}

// SyncConfig fetches the latest configuration from the cloud
func (ac *AutoConfig) SyncConfig(ctx context.Context) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if ac.config == nil || ac.config.APIKey == "" {
		return fmt.Errorf("no configuration to sync")
	}

	req, _ := http.NewRequestWithContext(ctx, "GET",
		ac.config.APIEndpoint+configPath, nil)
	req.Header.Set("Authorization", "Bearer "+ac.config.APIKey)
	req.Header.Set("X-Device-ID", ac.config.DeviceID)

	resp, err := ac.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("sync returned status %d", resp.StatusCode)
	}

	var cloudConfig struct {
		Features         map[string]bool       `json:"features"`
		Settings         map[string]string     `json:"settings"`
		EnterpriseConfig *EnterpriseConfig     `json:"enterprise_config"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&cloudConfig); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	ac.config.Features = cloudConfig.Features
	ac.config.Settings = cloudConfig.Settings
	ac.config.EnterpriseConfig = cloudConfig.EnterpriseConfig
	ac.config.LastSync = time.Now()

	if ac.onConfigUpdate != nil {
		ac.onConfigUpdate(ac.config)
	}

	return nil
}

// StartConfigSync starts periodic configuration sync
func (ac *AutoConfig) StartConfigSync(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ac.SyncConfig(ctx); err != nil {
				if ac.onError != nil {
					ac.onError(err)
				}
			}
		}
	}
}

// GetConfig returns the current configuration
func (ac *AutoConfig) GetConfig() *Config {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.config
}

// Helper methods

func (ac *AutoConfig) getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func (ac *AutoConfig) getMachineID() string {
	// Platform-specific machine ID
	switch runtime.GOOS {
	case "linux":
		id, _ := os.ReadFile("/etc/machine-id")
		return strings.TrimSpace(string(id))
	case "darwin":
		// Would use IOPlatformSerialNumber
		return ""
	case "windows":
		// Would use MachineGuid from registry
		return ""
	}
	return ""
}

func (ac *AutoConfig) getConfigPaths() []string {
	var paths []string

	switch runtime.GOOS {
	case "darwin", "linux":
		paths = []string{
			"/etc/afterdark/api-key",
			"/etc/afterdark/config.json",
			filepath.Join(os.Getenv("HOME"), ".afterdark", "api-key"),
		}
	case "windows":
		paths = []string{
			`C:\ProgramData\AfterDark\api-key`,
			`C:\ProgramData\AfterDark\config.json`,
			filepath.Join(os.Getenv("APPDATA"), "AfterDark", "api-key"),
		}
	}

	return paths
}

func (ac *AutoConfig) readAPIKeyFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (ac *AutoConfig) saveAPIKey(apiKey string) error {
	var path string
	switch runtime.GOOS {
	case "darwin", "linux":
		path = "/etc/afterdark/api-key"
	case "windows":
		path = `C:\ProgramData\AfterDark\api-key`
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(apiKey), 0600)
}

func (ac *AutoConfig) deleteEnrollmentToken() {
	paths := []string{
		"/etc/afterdark/enroll-token",
		filepath.Join(os.Getenv("HOME"), ".afterdark", "enroll-token"),
	}
	if runtime.GOOS == "windows" {
		paths = append(paths, `C:\ProgramData\AfterDark\enroll-token`)
	}

	for _, path := range paths {
		os.Remove(path)
	}
}
