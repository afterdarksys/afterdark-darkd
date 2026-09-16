package main

import (
	"context"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// API credentials are separate from the local daemon's IPC token.
func executeAPI(cmd *cobra.Command, method, endpoint, data string) error {
	base, err := url.Parse(apiURL)
	if err != nil || base.Host == "" || base.User != nil || (base.Scheme != "https" && !(base.Scheme == "http" && (base.Hostname() == "localhost" || base.Hostname() == "127.0.0.1"))) {
		return fmt.Errorf("API URL must use HTTPS (HTTP allowed on loopback)")
	}
	relative, err := url.Parse(endpoint)
	if err != nil || relative.IsAbs() || relative.Host != "" || !strings.HasPrefix(endpoint, "/") {
		return fmt.Errorf("endpoint must be an absolute path on the configured API")
	}
	target := base.ResolveReference(relative)
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, target.String(), strings.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if key := os.Getenv("AFTERDARK_API_KEY"); key != "" {
		req.Header.Set("X-API-Key", key)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil {
		return err
	}
	if len(body) > 4<<20 {
		return fmt.Errorf("API response exceeds 4 MiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API rejected request: HTTP %d", resp.StatusCode)
	}
	if _, err = cmd.OutOrStdout().Write(body); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "HTTP %d in %s\n", resp.StatusCode, time.Since(start).Round(time.Millisecond))
	return nil
}
