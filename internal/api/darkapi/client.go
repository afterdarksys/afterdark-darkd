package darkapi

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net"
	"strings"
	"time"
)

type ThreatInfo struct {
	Indicator   string    `json:"indicator"`
	Type        string    `json:"indicator_type"`
	Severity    string    `json:"severity,omitempty"`
	Reputation  string    `json:"reputation"`
	Score       int       `json:"score"`
	Categories  []string  `json:"categories,omitempty"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
	Description string    `json:"description,omitempty"`
	Sources     []string  `json:"sources,omitempty"`
	Error       string    `json:"error,omitempty"`
}

func (c *Client) Lookup(ctx context.Context, indicator, kind string) (*ThreatInfo, error) {
	var result ThreatInfo
	if strings.TrimSpace(indicator) == "" {
		return nil, fmt.Errorf("indicator is required")
	}
	err := c.request(ctx, "POST", "/v1/reputation/lookup", "account", map[string]string{"indicator": indicator, "type": kind}, &result, false)
	if err != nil {
		return nil, err
	}
	if result.Indicator == "" || result.Reputation == "" || result.Error != "" {
		return nil, fmt.Errorf("invalid reputation response")
	}
	return &result, nil
}
func (c *Client) LookupDomain(ctx context.Context, domain string) (*ThreatInfo, error) {
	return c.Lookup(ctx, strings.ToLower(strings.TrimSuffix(domain, ".")), "domain")
}
func (c *Client) LookupIP(ctx context.Context, ip string) (*ThreatInfo, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("invalid IP address")
	}
	return c.Lookup(ctx, ip, "ip")
}

type BulkLookupRequest struct {
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}
type BulkLookupResponse struct {
	Results []ThreatInfo `json:"results"`
}

func (c *Client) BulkLookup(ctx context.Context, req *BulkLookupRequest) (*BulkLookupResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("lookup request required")
	}
	items := append(append([]string{}, req.Domains...), req.IPs...)
	if len(items) == 0 || len(items) > 100 {
		return nil, fmt.Errorf("bulk lookup requires 1 to 100 indicators")
	}
	var result BulkLookupResponse
	err := c.request(ctx, "POST", "/v1/reputation/lookup/bulk", "account", map[string]interface{}{"indicators": items}, &result, false)
	if err != nil {
		return nil, err
	}
	if len(result.Results) != len(items) {
		return nil, fmt.Errorf("incomplete bulk lookup response")
	}
	return &result, nil
}
func (c *Client) Health(ctx context.Context) error {
	return c.request(ctx, "GET", "/health", "", nil, nil, true)
}
func (c *Client) Account(ctx context.Context) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.request(ctx, "GET", "/v1/account", "account", nil, &result, true)
	return result, err
}

type LoginResponse struct {
	Success bool   `json:"success"`
	APIKey  string `json:"api_key"`
	Email   string `json:"email"`
}

func (c *Client) Login(ctx context.Context, email, password string) (*LoginResponse, error) {
	if email == "" || password == "" {
		return nil, fmt.Errorf("email and password required")
	}
	var result LoginResponse
	if err := c.request(ctx, "POST", "/v1/auth/login", "", map[string]string{"email": email, "password": password}, &result, false); err != nil {
		return nil, err
	}
	if !result.Success || result.APIKey == "" {
		return nil, fmt.Errorf("login did not return a credential")
	}
	return &result, nil
}

type EnrollmentRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	Hostname        string `json:"hostname"`
	Platform        string `json:"platform"`
	Architecture    string `json:"architecture"`
	AgentVersion    string `json:"agent_version"`
}
type EnrollmentResponse struct {
	Success  bool   `json:"success"`
	DeviceID string `json:"device_id"`
	APIKey   string `json:"api_key"`
}

func (c *Client) Enroll(ctx context.Context, request EnrollmentRequest) (*EnrollmentResponse, error) {
	if request.EnrollmentToken == "" {
		request.EnrollmentToken = c.accountKey
	}
	if request.EnrollmentToken == "" {
		return nil, fmt.Errorf("an account API key with write permission is required for enrollment")
	}
	var result EnrollmentResponse
	if err := c.request(ctx, "POST", "/v1/devices/enroll", "", request, &result, false); err != nil {
		return nil, err
	}
	if !result.Success || result.DeviceID == "" || result.APIKey == "" {
		return nil, fmt.Errorf("enrollment did not return device credentials")
	}
	return &result, nil
}
func (c *Client) Heartbeat(ctx context.Context) error {
	var result struct {
		Success bool `json:"success"`
	}
	if err := c.request(ctx, "POST", "/v1/devices/heartbeat", "device", map[string]interface{}{}, &result, true); err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("heartbeat rejected")
	}
	return nil
}
func (c *Client) DeviceConfig(ctx context.Context) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.request(ctx, "GET", "/v1/devices/config", "device", nil, &result, true)
	return result, err
}

type TelemetryReport struct {
	EventID          string          `json:"event_id"`
	SystemID         string          `json:"system_id"`
	Hostname         string          `json:"hostname,omitempty"`
	OSFamily         string          `json:"os_family,omitempty"`
	OSVersion        string          `json:"os_version,omitempty"`
	KernelVersion    string          `json:"kernel_version,omitempty"`
	InstalledPatches []string        `json:"installed_patches,omitempty"`
	SoftwareCatalog  interface{}     `json:"software_catalog,omitempty"`
	Event            json.RawMessage `json:"event,omitempty"`
}

func (c *Client) ReportTelemetry(ctx context.Context, report *TelemetryReport) error {
	if report == nil {
		return fmt.Errorf("telemetry report required")
	}
	if _, err := uuid.Parse(report.EventID); err != nil {
		return fmt.Errorf("telemetry requires a stable UUID event_id")
	}
	payload := *report
	if payload.SystemID != "" && payload.SystemID != c.deviceID {
		return fmt.Errorf("telemetry system_id must match enrolled device")
	}
	payload.SystemID = c.deviceID
	var result struct {
		Success bool   `json:"success"`
		EventID string `json:"event_id"`
		Status  string `json:"status"`
	}
	if err := c.request(ctx, "POST", "/api/v1/darkd/telemetry", "device", payload, &result, true); err != nil {
		return err
	}
	if !result.Success || result.EventID != payload.EventID || result.Status != "accepted" {
		return fmt.Errorf("telemetry acknowledgement does not match event")
	}
	return nil
}

// AccountRequest supports additional account-authenticated v1 endpoints without
// silently retrying mutations. Device and firewall-app keys have separate scopes.
func (c *Client) AccountRequest(ctx context.Context, method, path string, body json.RawMessage) (json.RawMessage, error) {
	method = strings.ToUpper(method)
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
	default:
		return nil, fmt.Errorf("unsupported HTTP method")
	}
	if !strings.HasPrefix(path, "/v1/") || strings.Contains(path, "#") || strings.Contains(path, "\r") || strings.Contains(path, "\n") {
		return nil, fmt.Errorf("account request path must start with /v1/")
	}
	var payload interface{}
	if len(body) > 0 {
		if !json.Valid(body) {
			return nil, fmt.Errorf("request body is not valid JSON")
		}
		payload = body
	}
	var result json.RawMessage
	err := c.request(ctx, method, path, "account", payload, &result, method == "GET")
	return result, err
}
