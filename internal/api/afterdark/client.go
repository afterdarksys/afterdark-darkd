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
