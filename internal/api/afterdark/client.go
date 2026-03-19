package afterdark

import (
	"context"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/api"
	"github.com/afterdarksys/afterdark-darkd/internal/platform"
)

// Client is the AfterDark Systems API client
type Client struct {
	client *api.Client
}

// Config holds AfterDark client configuration
type Config struct {
	BaseURL string
	APIKey  string
	Timeout time.Duration
}

// New creates a new AfterDark API client
func New(cfg *Config) *Client {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.afterdarksys.com"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	client := api.NewClient(&api.Config{
		BaseURL:    cfg.BaseURL,
		Timeout:    cfg.Timeout,
		MaxRetries: 3,
	})

	if cfg.APIKey != "" {
		client.SetAuth(&api.APIKeyAuth{
			Key:       cfg.APIKey,
			HeaderKey: "X-API-Key",
		})
	}

	return &Client{client: client}
}

// PatchIntel contains patch intelligence data
type PatchIntel struct {
	PatchID       string    `json:"patch_id"`
	Severity      string    `json:"severity"`
	ExploitActive bool      `json:"exploit_active"`
	CVEs          []string  `json:"cves"`
	Description   string    `json:"description"`
	AffectedOS    []string  `json:"affected_os"`
	ReleasedAt    time.Time `json:"released_at"`
	LastUpdated   time.Time `json:"last_updated"`
}

// EndpointRegistration represents an endpoint registration
type EndpointRegistration struct {
	EndpointID   string             `json:"endpoint_id"`
	Hostname     string             `json:"hostname"`
	OSInfo       *platform.OSInfo   `json:"os_info"`
	RegisteredAt time.Time          `json:"registered_at"`
	LastSeen     time.Time          `json:"last_seen"`
	Status       string             `json:"status"`
}

// PatchReport represents a patch status report
type PatchReport struct {
	EndpointID      string           `json:"endpoint_id"`
	ReportedAt      time.Time        `json:"reported_at"`
	InstalledPatches []platform.Patch `json:"installed_patches"`
	MissingPatches   []platform.Patch `json:"missing_patches"`
	ComplianceStatus string           `json:"compliance_status"`
}

// GetPatchIntel retrieves patch intelligence data
func (c *Client) GetPatchIntel(ctx context.Context, patchID string) (*PatchIntel, error) {
	var result PatchIntel
	if err := c.client.Get(ctx, "/v1/patches/intel/"+patchID, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetActiveExploits retrieves patches with active exploits
func (c *Client) GetActiveExploits(ctx context.Context) ([]PatchIntel, error) {
	var result struct {
		Patches []PatchIntel `json:"patches"`
	}
	if err := c.client.Get(ctx, "/v1/patches/exploits/active", &result); err != nil {
		return nil, err
	}
	return result.Patches, nil
}

// RegisterEndpoint registers an endpoint with the API
func (c *Client) RegisterEndpoint(ctx context.Context, reg *EndpointRegistration) error {
	return c.client.Post(ctx, "/v1/endpoints/register", reg, nil)
}

// ReportPatches reports patch status to the API
func (c *Client) ReportPatches(ctx context.Context, report *PatchReport) error {
	return c.client.Post(ctx, "/v1/endpoints/patches", report, nil)
}

// TelemetryReport represents a full system software inventory report
type TelemetryReport struct {
	SystemID         string                 `json:"system_id"`
	Hostname         string                 `json:"hostname"`
	OSFamily         string                 `json:"os_family"`
	OSVersion        string                 `json:"os_version"`
	KernelVersion    string                 `json:"kernel_version"`
	InstalledPatches []string               `json:"installed_patches"` // IDs or KB articles
	SoftwareCatalog  []platform.Application `json:"software_catalog"`
}

// ReportTelemetry submits the software inventory and OS catalog to DarkAPI/darkd endpoint
func (c *Client) ReportTelemetry(ctx context.Context, report *TelemetryReport) error {
	return c.client.Post(ctx, "/api/v1/darkd/telemetry", report, nil)
}

// GetEndpointStatus retrieves endpoint status
func (c *Client) GetEndpointStatus(ctx context.Context, endpointID string) (*EndpointRegistration, error) {
	var result EndpointRegistration
	if err := c.client.Get(ctx, "/v1/endpoints/"+endpointID, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Health checks the API health
func (c *Client) Health(ctx context.Context) error {
	return c.client.Get(ctx, "/health", nil)
}

// DetonationReport represents a malware detonation analysis report
type DetonationReport struct {
	ID              string      `json:"id"`
	SampleID        string      `json:"sample_id"`
	Duration        int64       `json:"duration_ms"`
	SandboxType     string      `json:"sandbox_type"`
	ThreatScore     int         `json:"threat_score"`
	Verdict         string      `json:"verdict"`
	GeneratedAt     time.Time   `json:"generated_at"`
	StaticAnalysis  interface{} `json:"static_analysis,omitempty"`
	DynamicAnalysis interface{} `json:"dynamic_analysis,omitempty"`
	NetworkActivity interface{} `json:"network_activity,omitempty"`
	FileActivity    interface{} `json:"file_activity,omitempty"`
	IOCs            []IOC       `json:"iocs,omitempty"`
}

// IOC represents an Indicator of Compromise
type IOC struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	Context    string `json:"context,omitempty"`
	Confidence int    `json:"confidence"`
}

// SampleReputation represents the reputation data for a file
type SampleReputation struct {
	SHA256           string   `json:"sha256"`
	FirstSeen        string   `json:"first_seen"`
	LastSeen         string   `json:"last_seen"`
	TotalSightings   int      `json:"total_sightings"`
	ThreatScore      int      `json:"threat_score"`
	Verdict          string   `json:"verdict"`
	MalwareFamily    string   `json:"malware_family,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	Confidence       float64  `json:"confidence"`
	GlobalPrevalence float64  `json:"global_prevalence"`
}

// SubmitDetonationReports uploads detonation analysis reports to the portal
func (c *Client) SubmitDetonationReports(ctx context.Context, reports []DetonationReport) error {
	payload := struct {
		Reports []DetonationReport `json:"reports"`
	}{
		Reports: reports,
	}
	return c.client.Post(ctx, "/v1/detonation/reports", payload, nil)
}

// SubmitDetonationReportsRaw uploads raw JSON detonation reports
func (c *Client) SubmitDetonationReportsRaw(ctx context.Context, data []byte) error {
	return c.client.Post(ctx, "/v1/detonation/reports", data, nil)
}

// GetSampleReputation queries the reputation of a file hash
func (c *Client) GetSampleReputation(ctx context.Context, sha256 string) (*SampleReputation, error) {
	var result SampleReputation
	if err := c.client.Get(ctx, "/v1/reputation/"+sha256, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SubmitIOCs uploads Indicators of Compromise to the portal
func (c *Client) SubmitIOCs(ctx context.Context, iocs []IOC) error {
	payload := struct {
		IOCs []IOC `json:"iocs"`
	}{
		IOCs: iocs,
	}
	return c.client.Post(ctx, "/v1/iocs/submit", payload, nil)
}

// ThreatIntelResponse contains threat intelligence data
type ThreatIntelResponse struct {
	UpdatedAt        string      `json:"updated_at"`
	MaliciousIPs     []string    `json:"malicious_ips"`
	MaliciousDomains []string    `json:"malicious_domains"`
	MaliciousHashes  []string    `json:"malicious_hashes"`
	BlockRules       []BlockRule `json:"block_rules"`
}

// BlockRule represents a firewall/block rule
type BlockRule struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	Action      string `json:"action"`
	Description string `json:"description"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// GetThreatIntel fetches the latest threat intelligence
func (c *Client) GetThreatIntel(ctx context.Context, since string) (*ThreatIntelResponse, error) {
	var result ThreatIntelResponse
	path := "/v1/threat-intel"
	if since != "" {
		path += "?since=" + since
	}
	if err := c.client.Get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
