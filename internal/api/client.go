package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a base HTTP client with retry and rate limiting
type Client struct {
	httpClient  *http.Client
	baseURL     string
	auth        AuthMethod
	maxRetries  int
	retryWait   time.Duration
	maxRetryWait time.Duration
	rateLimits  *RateLimitStatus
}

// Config holds client configuration
type Config struct {
	BaseURL      string
	Timeout      time.Duration
	MaxRetries   int
	RetryWait    time.Duration
	MaxRetryWait time.Duration
}

// AuthMethod defines how to authenticate requests
type AuthMethod interface {
	Apply(req *http.Request) error
}

// APIKeyAuth authenticates using an API key header
type APIKeyAuth struct {
	Key       string
	HeaderKey string
}

func (a *APIKeyAuth) Apply(req *http.Request) error {
	if a.HeaderKey == "" {
		a.HeaderKey = "X-API-Key"
	}
	req.Header.Set(a.HeaderKey, a.Key)
	return nil
}

// BearerAuth authenticates using a Bearer token
type BearerAuth struct {
	Token string
}

func (a *BearerAuth) Apply(req *http.Request) error {
	req.Header.Set("Authorization", "Bearer "+a.Token)
	return nil
}

// RateLimitStatus tracks rate limit information
type RateLimitStatus struct {
	Limit     int
	Remaining int
	ResetAt   time.Time
}

// NewClient creates a new API client
func NewClient(cfg *Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.RetryWait == 0 {
		cfg.RetryWait = 1 * time.Second
	}
	if cfg.MaxRetryWait == 0 {
		cfg.MaxRetryWait = 30 * time.Second
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		baseURL:      cfg.BaseURL,
		maxRetries:   cfg.MaxRetries,
		retryWait:    cfg.RetryWait,
		maxRetryWait: cfg.MaxRetryWait,
		rateLimits:   &RateLimitStatus{},
	}
}

// SetAuth sets the authentication method
func (c *Client) SetAuth(auth AuthMethod) {
	c.auth = auth
}

// Get performs a GET request
func (c *Client) Get(ctx context.Context, path string, result interface{}) error {
	return c.doRequest(ctx, http.MethodGet, path, nil, result)
}

// Post performs a POST request
func (c *Client) Post(ctx context.Context, path string, body, result interface{}) error {
	return c.doRequest(ctx, http.MethodPost, path, body, result)
}

// Put performs a PUT request
func (c *Client) Put(ctx context.Context, path string, body, result interface{}) error {
	return c.doRequest(ctx, http.MethodPut, path, body, result)
}

// Delete performs a DELETE request
func (c *Client) Delete(ctx context.Context, path string, result interface{}) error {
	return c.doRequest(ctx, http.MethodDelete, path, nil, result)
}

func (c *Client) doRequest(ctx context.Context, method, path string, body, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	url := c.baseURL + path
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			wait := c.retryWait * time.Duration(1<<(attempt-1))
			if wait > c.maxRetryWait {
				wait = c.maxRetryWait
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "afterdark-darkd/0.1.0")

		if c.auth != nil {
			if err := c.auth.Apply(req); err != nil {
				return fmt.Errorf("failed to apply auth: %w", err)
			}
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		defer resp.Body.Close()

		// Update rate limits from headers
		c.updateRateLimits(resp)

		// Handle response
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read response: %w", err)
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if result != nil && len(respBody) > 0 {
				if err := json.Unmarshal(respBody, result); err != nil {
					return fmt.Errorf("failed to unmarshal response: %w", err)
				}
			}
			return nil
		}

		// Check if retryable
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			lastErr = &APIError{
				StatusCode: resp.StatusCode,
				Message:    string(respBody),
			}
			continue
		}

		// Non-retryable error
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(respBody),
		}
	}

	return fmt.Errorf("request failed after %d attempts: %w", c.maxRetries+1, lastErr)
}

func (c *Client) updateRateLimits(resp *http.Response) {
	// Parse rate limit headers if present
	// Common headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
}

// GetRateLimits returns current rate limit status
func (c *Client) GetRateLimits() *RateLimitStatus {
	return c.rateLimits
}

// APIError represents an API error response
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Message)
}
