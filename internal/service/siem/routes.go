package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"

	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
)

type Route = models.SIEMRoute

func (s *Service) routes() []Route {
	routes := append([]Route(nil), s.config.Routes...)
	if s.config.URL != "" {
		routes = append(routes, Route{Name: "default", URL: s.config.URL, AuthToken: s.config.AuthToken})
	}
	return routes
}

func (s *Service) validateRoutes() error {
	routes := s.routes()
	if len(routes) == 0 && s.config.DarkAPI == nil {
		return fmt.Errorf("SIEM requires at least one destination")
	}
	for _, route := range routes {
		u, err := url.Parse(route.URL)
		if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("invalid SIEM destination %q", route.Name)
		}
		switch route.Format {
		case "", "webhook", "splunk", "datadog":
		case "elastic":
			if route.Index == "" {
				return fmt.Errorf("Elasticsearch route requires index")
			}
		default:
			return fmt.Errorf("unsupported SIEM format %q", route.Format)
		}
	}
	return nil
}

func matches(route Route, event events.Event) bool {
	return (len(route.Severities) == 0 || slices.Contains(route.Severities, event.Severity)) && (len(route.Types) == 0 || slices.Contains(route.Types, event.Type))
}

// Delivery is at least once. The durable store is acknowledged only after all
// matching destinations and cloud telemetry accept the batch. Consumers should
// deduplicate by the stable event ID; Elasticsearch uses it as the document ID.
func (s *Service) deliver(ctx context.Context, route Route, batch []events.Event) error {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	contentType := "application/json"
	switch route.Format {
	case "splunk":
		for _, e := range batch {
			if err := enc.Encode(map[string]any{"event": e, "time": float64(e.Time.UnixNano()) / 1e9, "host": e.Endpoint, "source": e.Source}); err != nil {
				return err
			}
		}
	case "elastic":
		contentType = "application/x-ndjson"
		for _, e := range batch {
			if err := enc.Encode(map[string]any{"index": map[string]string{"_index": route.Index, "_id": e.ID}}); err != nil {
				return err
			}
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
	case "datadog":
		logs := make([]map[string]any, 0, len(batch))
		for _, e := range batch {
			logs = append(logs, map[string]any{"message": e, "service": e.Source, "hostname": e.Endpoint, "ddsource": "afterdark", "event_id": e.ID})
		}
		if err := enc.Encode(logs); err != nil {
			return err
		}
	default:
		if err := enc.Encode(batch); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, route.URL, &body)
	if err != nil {
		return fmt.Errorf("create SIEM request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	if route.AuthToken != "" {
		switch route.Format {
		case "splunk":
			req.Header.Set("Authorization", "Splunk "+route.AuthToken)
		case "datadog":
			req.Header.Set("DD-API-KEY", route.AuthToken)
		case "elastic":
			req.Header.Set("Authorization", "ApiKey "+route.AuthToken)
		default:
			req.Header.Set("Authorization", "Bearer "+route.AuthToken)
		}
	}
	// Do not forward credentials through redirects or treat login pages as success.
	client := *s.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("delivery to %q failed", route.Name)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("destination %q rejected batch: HTTP %d", route.Name, resp.StatusCode)
	}
	if route.Format == "splunk" || route.Format == "elastic" {
		var result struct {
			Code   *int  `json:"code"`
			Errors *bool `json:"errors"`
			Items  []map[string]struct {
				Status int `json:"status"`
			} `json:"items"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&result); err != nil {
			return fmt.Errorf("invalid acknowledgement from %q", route.Name)
		}
		if route.Format == "splunk" && (result.Code == nil || *result.Code != 0) {
			return fmt.Errorf("Splunk rejected batch")
		}
		if route.Format == "elastic" {
			if result.Errors == nil || *result.Errors || len(result.Items) != len(batch) {
				return fmt.Errorf("Elasticsearch rejected or incompletely acknowledged batch")
			}
			for _, item := range result.Items {
				op, ok := item["index"]
				if !ok || op.Status < 200 || op.Status >= 300 {
					return fmt.Errorf("Elasticsearch rejected document")
				}
			}
		}
	}
	return nil
}
