package darkapi

import (
	"context"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/api"
)

// Client is the DarkAPI.io client
type Client struct {
	client *api.Client
}

// Config holds DarkAPI client configuration
type Config struct {
	BaseURL  string
	APIKey   string
	Timeout  time.Duration
}

// New creates a new DarkAPI client
func New(cfg *Config) *Client {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.darkapi.io"
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

// BadDomainList represents a list of malicious domains
type BadDomainList struct {
	Updated  time.Time `json:"updated"`
	Count    int       `json:"count"`
	Domains  []string  `json:"domains"`
	Checksum string    `json:"checksum,omitempty"`
}

// BadIPList represents a list of malicious IPs
type BadIPList struct {
	Updated  time.Time `json:"updated"`
	Count    int       `json:"count"`
	IPs      []string  `json:"ips"`
	Checksum string    `json:"checksum,omitempty"`
}

// ThreatInfo contains detailed threat information
type ThreatInfo struct {
	Indicator   string    `json:"indicator"`
	Type        string    `json:"type"` // "domain" or "ip"
	Severity    string    `json:"severity"`
	Categories  []string  `json:"categories"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Description string    `json:"description,omitempty"`
	Sources     []string  `json:"sources,omitempty"`
}

// GetBadDomains retrieves the list of malicious domains
func (c *Client) GetBadDomains(ctx context.Context) (*BadDomainList, error) {
	var result BadDomainList
	if err := c.client.Get(ctx, "/v1/threats/domains", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetBadDomainsIncremental retrieves domains updated since the given time
func (c *Client) GetBadDomainsIncremental(ctx context.Context, since time.Time) (*BadDomainList, error) {
	var result BadDomainList
	path := "/v1/threats/domains?since=" + since.Format(time.RFC3339)
	if err := c.client.Get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetBadIPs retrieves the list of malicious IPs
func (c *Client) GetBadIPs(ctx context.Context) (*BadIPList, error) {
	var result BadIPList
	if err := c.client.Get(ctx, "/v1/threats/ips", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetBadIPsIncremental retrieves IPs updated since the given time
func (c *Client) GetBadIPsIncremental(ctx context.Context, since time.Time) (*BadIPList, error) {
	var result BadIPList
	path := "/v1/threats/ips?since=" + since.Format(time.RFC3339)
	if err := c.client.Get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// LookupDomain checks if a domain is malicious
func (c *Client) LookupDomain(ctx context.Context, domain string) (*ThreatInfo, error) {
	var result ThreatInfo
	if err := c.client.Get(ctx, "/v1/lookup/domain/"+domain, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// LookupIP checks if an IP is malicious
func (c *Client) LookupIP(ctx context.Context, ip string) (*ThreatInfo, error) {
	var result ThreatInfo
	if err := c.client.Get(ctx, "/v1/lookup/ip/"+ip, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BulkLookup performs bulk threat lookups
type BulkLookupRequest struct {
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}

type BulkLookupResponse struct {
	Results []ThreatInfo `json:"results"`
}

func (c *Client) BulkLookup(ctx context.Context, req *BulkLookupRequest) (*BulkLookupResponse, error) {
	var result BulkLookupResponse
	if err := c.client.Post(ctx, "/v1/lookup/bulk", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Health checks the API health
func (c *Client) Health(ctx context.Context) error {
	return c.client.Get(ctx, "/health", nil)
}
