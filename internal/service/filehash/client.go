package filehash

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// APIClient is a client for the filehashes.io API
type APIClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewAPIClient creates a new API client
func NewAPIClient(baseURL, apiKey string) *APIClient {
	return &APIClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SubmitHashRequest represents a hash submission
type SubmitHashRequest struct {
	SHA256   string  `json:"sha256"`
	SHA1     *string `json:"sha1,omitempty"`
	MD5      *string `json:"md5,omitempty"`
	Filename *string `json:"filename,omitempty"`
	FileSize *int64  `json:"file_size,omitempty"`
}

// SubmitHashResponse represents the API response
type SubmitHashResponse struct {
	Success bool `json:"success"`
	New     bool `json:"new"`
}

// SubmitHash submits a file hash to the API
func (c *APIClient) SubmitHash(ctx context.Context, record *FileRecord) error {
	req := &SubmitHashRequest{
		SHA256:   record.SHA256,
		SHA1:     &record.SHA1,
		MD5:      &record.MD5,
		Filename: &record.Filename,
		FileSize: &record.Size,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/hash", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "afterdark-darkd/1.0")
	if c.apiKey != "" {
		httpReq.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// LookupHash looks up a hash in the API
func (c *APIClient) LookupHash(ctx context.Context, sha256 string) (*LookupResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/v1/hash/"+sha256, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("User-Agent", "afterdark-darkd/1.0")
	if c.apiKey != "" {
		httpReq.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	var result LookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

// HealthCheck checks if the API is available
func (c *APIClient) HealthCheck(ctx context.Context) error {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/health", nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API unhealthy: %d", resp.StatusCode)
	}

	return nil
}

// LookupResponse represents a hash lookup response
type LookupResponse struct {
	Found bool       `json:"found"`
	Hash  *HashData  `json:"hash,omitempty"`
}

// HashData represents hash information from the API
type HashData struct {
	ID        int64  `json:"id"`
	SHA256    string `json:"sha256"`
	SHA1      string `json:"sha1,omitempty"`
	MD5       string `json:"md5,omitempty"`
	Filename  string `json:"filename,omitempty"`
	FileSize  int64  `json:"file_size,omitempty"`
	TimesSeen int    `json:"times_seen"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}
