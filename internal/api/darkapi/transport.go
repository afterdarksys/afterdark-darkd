package darkapi

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
	"strconv"
	"strings"
	"time"
)

const DefaultURL = "https://api.darkapi.io"
const maxResponseBytes = 16 << 20

// APIError deliberately excludes response bodies, which may contain credentials.
type APIError struct {
	StatusCode int
	RetryAfter time.Duration
}

func (e *APIError) Error() string { return fmt.Sprintf("DarkAPI returned HTTP %d", e.StatusCode) }

type Client struct {
	baseURL                         string
	accountKey, deviceID, deviceKey string
	http                            *http.Client
	initErr                         error
}
type Config struct {
	BaseURL, APIKey, CredentialFile string
	Timeout                         time.Duration
	AllowHTTP                       bool
}

func NormalizeURL(raw string, allowHTTP bool) (string, error) {
	if raw == "" {
		raw = DefaultURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid DarkAPI base URL")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if !allowHTTP || u.Scheme != "http" || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return "", fmt.Errorf("DarkAPI requires HTTPS (HTTP is only allowed for explicit loopback tests)")
		}
	}
	// The web-host alias is accepted as configuration, but the repository's
	// ingress serves the API on its dedicated hostname.
	if strings.EqualFold(u.Host, "darkapi.io") && strings.TrimRight(u.Path, "/") == "/api" {
		return DefaultURL, nil
	}
	if u.Path != "" && u.Path != "/" && u.Path != "/api" && u.Path != "/api/" {
		return "", fmt.Errorf("DarkAPI base path must be empty or /api")
	}
	return strings.TrimRight(u.String(), "/"), nil
}
func New(cfg *Config) *Client {
	if cfg == nil {
		cfg = &Config{}
	}
	c := &Client{accountKey: cfg.APIKey}
	c.baseURL, c.initErr = NormalizeURL(cfg.BaseURL, cfg.AllowHTTP)
	if cfg.CredentialFile != "" && c.initErr == nil {
		credentials, err := LoadCredentials(cfg.CredentialFile)
		c.initErr = err
		if err == nil {
			if credentials.BaseURL != "" {
				saved, e := NormalizeURL(credentials.BaseURL, cfg.AllowHTTP)
				if e != nil || saved != c.baseURL {
					c.initErr = fmt.Errorf("credentials belong to a different DarkAPI endpoint")
				}
			}
			if c.accountKey == "" {
				c.accountKey = credentials.APIKey
			}
			c.deviceID = credentials.DeviceID
			c.deviceKey = credentials.DeviceKey
		}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	c.http = &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c
}
func (c *Client) Validate() error  { return c.initErr }
func (c *Client) DeviceID() string { return c.deviceID }
func (c *Client) HasDeviceCredentials() bool {
	return c.initErr == nil && c.deviceID != "" && c.deviceKey != ""
}
func (c *Client) request(ctx context.Context, method, path, auth string, body, out interface{}, retry bool) error {
	if c.initErr != nil {
		return c.initErr
	}
	var key string
	switch auth {
	case "account":
		key = c.accountKey
	case "device":
		key = c.deviceKey
		if c.deviceID == "" {
			return fmt.Errorf("enroll this device before using device endpoints")
		}
	}
	if auth != "" && key == "" {
		return fmt.Errorf("DarkAPI %s credentials are missing", auth)
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	if body == nil {
		data = nil
	}
	if strings.HasSuffix(c.baseURL, "/api") && strings.HasPrefix(path, "/api/") {
		path = strings.TrimPrefix(path, "/api")
	}
	attempts := 1
	if retry {
		attempts = 3
	}
	delay := time.Duration(0)
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("invalid DarkAPI request")
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "afterdark-darkd")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if key != "" {
			req.Header.Set("X-API-Key", key)
		}
		if auth == "device" {
			req.Header.Set("X-Device-ID", c.deviceID)
		}
		resp, err := c.http.Do(req)
		delay = time.Second * time.Duration(1<<attempt)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = fmt.Errorf("DarkAPI connection failed: %w", sanitizeTransportError(err))
			continue
		}
		b, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("DarkAPI response read failed")
			continue
		}
		if len(b) > maxResponseBytes {
			return fmt.Errorf("DarkAPI response exceeds size limit")
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			apiErr := &APIError{StatusCode: resp.StatusCode}
			apiErr.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
			lastErr = apiErr
			if resp.StatusCode != 429 && resp.StatusCode < 500 {
				return apiErr
			}
			if apiErr.RetryAfter > delay {
				delay = apiErr.RetryAfter
			}
			if delay > 30*time.Second {
				return apiErr
			}
			continue
		}
		if out != nil {
			if len(b) == 0 {
				if resp.StatusCode == http.StatusNoContent {
					return nil
				}
				return fmt.Errorf("DarkAPI returned an empty response")
			}
			if err := json.Unmarshal(b, out); err != nil {
				return fmt.Errorf("DarkAPI returned invalid JSON")
			}
		}
		return nil
	}
	return lastErr
}
func sanitizeTransportError(err error) error {
	var u *url.Error
	if errors.As(err, &u) {
		return u.Err
	}
	return err
}
func parseRetryAfter(value string) time.Duration {
	if n, err := strconv.Atoi(value); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	if deadline, err := http.ParseTime(value); err == nil {
		if d := time.Until(deadline); d > 0 {
			return d
		}
	}
	return 0
}
