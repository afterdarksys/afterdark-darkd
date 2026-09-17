// Package ecosystem implements the read/enrichment contracts verified against
// the provider server sources. It does not provision resources or run workflows.
package ecosystem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Client struct {
	provider, base, credential string
	http                       *http.Client
}
type Contract struct{ Provider, Operation, DefaultURL, CredentialEnv string }

var Contracts = []Contract{
	{"dnsscience", "domain", "https://api.dnsscience.io", "DNSSCIENCE_API_KEY"},
	{"veribits", "dns", "https://veribits.com", "VERIBITS_TOKEN"},
	{"systemapi", "fleet", "https://systemapi.io", "SYSTEMAPI_API_KEY"},
	{"computeapi", "databases", "https://api.computeapi.io", "COMPUTEAPI_API_KEY"},
	{"planetapi", "ip-blacklist", "https://api.planetapi.ai", "PLANETAPI_API_KEY"},
}

func New(provider, base, credential string, timeout time.Duration) (*Client, error) {
	var found bool
	for _, contract := range Contracts {
		if provider == contract.Provider {
			found = true
			if base == "" {
				base = contract.DefaultURL
			}
		}
	}
	if !found {
		return nil, errors.New("unknown ecosystem provider")
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("base URL must contain only scheme and host")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return nil, errors.New("HTTPS required except literal loopback test addresses")
	}
	if strings.TrimSpace(credential) == "" || strings.ContainsAny(credential, "\r\n") {
		return nil, errors.New("provider credential required")
	}
	if timeout <= 0 || timeout > 2*time.Minute {
		return nil, errors.New("timeout must be between zero and two minutes")
	}
	return &Client{provider: provider, base: strings.TrimRight(base, "/"), credential: credential, http: &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("provider redirects are not allowed") }}}, nil
}

var label = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

func domain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if len(value) > 253 || len(strings.Split(value, ".")) < 2 {
		return "", errors.New("a fully qualified ASCII domain is required")
	}
	for _, part := range strings.Split(value, ".") {
		if !label.MatchString(part) {
			return "", errors.New("invalid domain")
		}
	}
	return value, nil
}

// Query performs exactly one request; enrichment POSTs are never retried implicitly.
// Provider JSON is returned unchanged rather than translated into a clean verdict.
func (c *Client) Query(ctx context.Context, operation, value string) (json.RawMessage, error) {
	method, path := http.MethodGet, ""
	var payload any
	switch c.provider + "/" + operation {
	case "dnsscience/domain", "veribits/dns":
		d, err := domain(value)
		if err != nil {
			return nil, err
		}
		method = http.MethodPost
		if c.provider == "dnsscience" {
			path = "/api/v1/enrich/domain"
			payload = map[string]any{"domain": d}
		} else {
			path = "/api/v1/dns/check"
			payload = map[string]any{"domain": d, "check_type": "records"}
		}
	case "systemapi/fleet":
		path = "/api/v1/fleet"
	case "computeapi/databases":
		path = "/api/v2/dbaas/instances"
	case "planetapi/ip-blacklist":
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, errors.New("IP address required")
		}
		path = "/v1/ip-blacklist/" + url.PathEscape(ip.String())
	default:
		return nil, errors.New("unsupported provider operation")
	}
	if payload == nil && c.provider != "planetapi" && value != "" {
		return nil, errors.New("this operation takes no target")
	}
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.provider == "veribits" {
		req.Header.Set("Authorization", "Bearer "+c.credential)
	} else {
		req.Header.Set("X-API-Key", c.credential)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s request failed (transport or timeout)", c.provider)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s returned HTTP %d", c.provider, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024+1))
	if err != nil {
		return nil, errors.New("unable to read provider response")
	}
	if len(b) > 4*1024*1024 {
		return nil, errors.New("provider response exceeds 4 MiB")
	}
	b = bytes.TrimSpace(b)
	if !json.Valid(b) || len(b) == 0 || (b[0] != '{' && b[0] != '[') {
		return nil, errors.New("provider returned invalid JSON evidence")
	}
	var envelope map[string]json.RawMessage
	if b[0] == '{' {
		if err := json.Unmarshal(b, &envelope); err != nil {
			return nil, err
		}
		if e, ok := envelope["error"]; ok && string(e) != "null" && string(e) != `""` && string(e) != "false" {
			return nil, errors.New("provider reported an error")
		}
		if s, ok := envelope["success"]; ok && string(s) == "false" {
			return nil, errors.New("provider reported unsuccessful result")
		}
	}
	return json.RawMessage(b), nil
}
