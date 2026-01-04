// Example data source plugin for threat intelligence feeds
//
// This plugin demonstrates how to create a data source plugin that
// provides threat intelligence data to the afterdark-darkd daemon.
//
// Build: go build -o threatfeed-datasource .
// Install: cp threatfeed-datasource /var/lib/afterdark-darkd/plugins/
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	sdk "github.com/afterdarksys/afterdark-darkd/pkg/pluginsdk"
)

// ThreatFeedDataSource provides threat intelligence from external feeds
type ThreatFeedDataSource struct {
	sdk.BaseDataSourcePlugin

	mu          sync.RWMutex
	feedURL     string
	apiKey      string
	client      *http.Client
	cache       []ThreatIndicator
	lastRefresh time.Time
	cacheTTL    time.Duration
}

// ThreatIndicator represents a threat intelligence indicator
type ThreatIndicator struct {
	Type       string    `json:"type"`       // ip, domain, hash, url
	Value      string    `json:"value"`      // The actual indicator
	Severity   string    `json:"severity"`   // low, medium, high, critical
	Source     string    `json:"source"`     // Feed source name
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Tags       []string  `json:"tags"`
	Confidence float64   `json:"confidence"` // 0.0 - 1.0
}

// Info returns plugin metadata
func (d *ThreatFeedDataSource) Info() sdk.PluginInfo {
	return sdk.PluginInfo{
		Name:        "threatfeed-datasource",
		Version:     "1.0.0",
		Type:        sdk.PluginTypeDataSource,
		Description: "Threat intelligence feed data source plugin",
		Author:      "After Dark Systems, LLC",
		License:     "MIT",
		Capabilities: []string{
			"ip-reputation",
			"domain-reputation",
			"hash-lookup",
			"url-analysis",
		},
	}
}

// Configure sets up the data source
func (d *ThreatFeedDataSource) Configure(config map[string]interface{}) error {
	if err := d.BaseDataSourcePlugin.Configure(config); err != nil {
		return err
	}

	// Extract configuration
	if url, ok := config["feed_url"].(string); ok {
		d.feedURL = url
	} else {
		d.feedURL = "https://api.threatfeed.example.com/v1"
	}

	if key, ok := config["api_key"].(string); ok {
		d.apiKey = key
	}

	if ttl, ok := config["cache_ttl_seconds"].(float64); ok {
		d.cacheTTL = time.Duration(ttl) * time.Second
	} else {
		d.cacheTTL = 5 * time.Minute
	}

	d.SetState(sdk.PluginStateReady, "configured")
	return nil
}

// Connect establishes connection to the data source
func (d *ThreatFeedDataSource) Connect(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.client = &http.Client{
		Timeout: 30 * time.Second,
	}

	// Initial cache refresh
	if err := d.refreshCache(ctx); err != nil {
		d.SetState(sdk.PluginStateError, fmt.Sprintf("failed to connect: %v", err))
		return err
	}

	d.SetState(sdk.PluginStateRunning, "connected")
	return nil
}

// Disconnect closes the connection
func (d *ThreatFeedDataSource) Disconnect(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.client = nil
	d.cache = nil
	d.SetState(sdk.PluginStateStopped, "disconnected")
	return nil
}

// Query retrieves data from the source
func (d *ThreatFeedDataSource) Query(ctx context.Context, query string, params map[string]interface{}) ([]map[string]interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.client == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Check if cache needs refresh
	if time.Since(d.lastRefresh) > d.cacheTTL {
		d.mu.RUnlock()
		d.mu.Lock()
		if err := d.refreshCache(ctx); err != nil {
			d.mu.Unlock()
			d.mu.RLock()
			return nil, fmt.Errorf("cache refresh failed: %w", err)
		}
		d.mu.Unlock()
		d.mu.RLock()
	}

	// Filter based on query
	var results []map[string]interface{}

	indicatorType, _ := params["type"].(string)
	minSeverity, _ := params["min_severity"].(string)
	minConfidence, _ := params["min_confidence"].(float64)

	for _, indicator := range d.cache {
		// Apply filters
		if indicatorType != "" && indicator.Type != indicatorType {
			continue
		}
		if minSeverity != "" && !severityMeets(indicator.Severity, minSeverity) {
			continue
		}
		if minConfidence > 0 && indicator.Confidence < minConfidence {
			continue
		}

		// Search by value if query provided
		if query != "" && indicator.Value != query {
			continue
		}

		results = append(results, map[string]interface{}{
			"type":       indicator.Type,
			"value":      indicator.Value,
			"severity":   indicator.Severity,
			"source":     indicator.Source,
			"first_seen": indicator.FirstSeen.Format(time.RFC3339),
			"last_seen":  indicator.LastSeen.Format(time.RFC3339),
			"tags":       indicator.Tags,
			"confidence": indicator.Confidence,
		})
	}

	return results, nil
}

// Subscribe sets up real-time updates (streaming threat feed)
func (d *ThreatFeedDataSource) Subscribe(ctx context.Context, topic string, handler func(data map[string]interface{})) error {
	// Start a goroutine that periodically checks for new threats
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		lastCount := len(d.cache)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.mu.Lock()
				d.refreshCache(ctx)
				currentCount := len(d.cache)
				d.mu.Unlock()

				// Notify if new indicators found
				if currentCount > lastCount {
					d.mu.RLock()
					for i := lastCount; i < currentCount; i++ {
						indicator := d.cache[i]
						handler(map[string]interface{}{
							"event":    "new_indicator",
							"type":     indicator.Type,
							"value":    indicator.Value,
							"severity": indicator.Severity,
						})
					}
					d.mu.RUnlock()
					lastCount = currentCount
				}
			}
		}
	}()

	return nil
}

// Health returns the current health status
func (d *ThreatFeedDataSource) Health() sdk.PluginHealth {
	d.mu.RLock()
	defer d.mu.RUnlock()

	health := d.BaseDataSourcePlugin.Health()
	health.Metrics = map[string]interface{}{
		"cached_indicators": len(d.cache),
		"last_refresh":      d.lastRefresh.Format(time.RFC3339),
		"cache_age_seconds": time.Since(d.lastRefresh).Seconds(),
		"connected":         d.client != nil,
	}

	return health
}

func (d *ThreatFeedDataSource) refreshCache(ctx context.Context) error {
	// In a real implementation, this would fetch from the feed URL
	// For this example, we'll simulate with mock data
	d.cache = []ThreatIndicator{
		{
			Type:       "ip",
			Value:      "192.168.1.100",
			Severity:   "high",
			Source:     "example-feed",
			FirstSeen:  time.Now().Add(-24 * time.Hour),
			LastSeen:   time.Now(),
			Tags:       []string{"malware", "c2"},
			Confidence: 0.95,
		},
		{
			Type:       "domain",
			Value:      "malicious.example.com",
			Severity:   "critical",
			Source:     "example-feed",
			FirstSeen:  time.Now().Add(-48 * time.Hour),
			LastSeen:   time.Now(),
			Tags:       []string{"phishing"},
			Confidence: 0.99,
		},
	}

	// If we have a real feed URL and API key, fetch from it
	if d.feedURL != "" && d.apiKey != "" && d.client != nil {
		req, err := http.NewRequestWithContext(ctx, "GET", d.feedURL+"/indicators", nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+d.apiKey)
		req.Header.Set("Accept", "application/json")

		resp, err := d.client.Do(req)
		if err != nil {
			// Fall back to mock data on error
			d.lastRefresh = time.Now()
			return nil
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			var indicators []ThreatIndicator
			if err := json.Unmarshal(body, &indicators); err == nil {
				d.cache = indicators
			}
		}
	}

	d.lastRefresh = time.Now()
	return nil
}

func severityMeets(actual, minimum string) bool {
	levels := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}
	return levels[actual] >= levels[minimum]
}

func main() {
	sdk.ServeDataSourcePlugin(&ThreatFeedDataSource{})
}
