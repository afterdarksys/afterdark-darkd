package darkapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testEventID = "b7ad5c3a-d1b1-43f1-b350-d7be39b16a0f"

// Fixtures mirror api/{app,agent_routes,repscore_routes}.py in darkapi.io.
func TestAccountEnrollmentAndDeviceContract(t *testing.T) {
	for _, prefix := range []string{"", "/api"} {
		t.Run("prefix="+prefix, func(t *testing.T) {
			var telemetryIDs []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				path := strings.TrimPrefix(r.URL.Path, prefix)
				if path == "/v1/darkd/telemetry" {
					path = "/api/v1/darkd/telemetry"
				}
				switch path {
				case "/v1/auth/login":
					var b map[string]string
					json.NewDecoder(r.Body).Decode(&b)
					if b["email"] != "user@example.com" || b["password"] != "password" {
						t.Error("wrong login body")
					}
					w.Write([]byte(`{"success":true,"api_key":"account-key"}`))
				case "/v1/account":
					if r.Header.Get("X-API-Key") != "account-key" {
						t.Error("account key missing")
					}
					w.Write([]byte(`{"user":{"email":"user@example.com"},"usage_30d":{}}`))
				case "/v1/devices/enroll":
					var b EnrollmentRequest
					json.NewDecoder(r.Body).Decode(&b)
					if b.EnrollmentToken != "account-key" || b.Platform == "" {
						t.Error("wrong enrollment body")
					}
					w.WriteHeader(201)
					w.Write([]byte(`{"success":true,"device_id":"dev_123","api_key":"device-key"}`))
				case "/v1/devices/config", "/v1/devices/heartbeat", "/api/v1/darkd/telemetry":
					if r.Header.Get("X-API-Key") != "device-key" || r.Header.Get("X-Device-ID") != "dev_123" {
						t.Error("device credentials missing or account key leaked")
					}
					if path == "/v1/devices/config" {
						w.Write([]byte(`{"observe_only":true}`))
						return
					}
					if path == "/v1/devices/heartbeat" {
						w.Write([]byte(`{"success":true}`))
						return
					}
					var b TelemetryReport
					json.NewDecoder(r.Body).Decode(&b)
					if b.SystemID != "dev_123" || b.EventID != testEventID {
						t.Error("incorrect telemetry identity")
					}
					telemetryIDs = append(telemetryIDs, b.EventID)
					if len(telemetryIDs) == 1 {
						w.WriteHeader(503)
						return
					}
					w.WriteHeader(202)
					w.Write([]byte(`{"success":true,"status":"accepted","event_id":"` + testEventID + `"}`))
				default:
					t.Errorf("unexpected route %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			cfg := &Config{BaseURL: server.URL + prefix, AllowHTTP: true}
			c := New(cfg)
			login, err := c.Login(context.Background(), "user@example.com", "password")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "credentials.json")
			saved := &Credentials{BaseURL: cfg.BaseURL, APIKey: login.APIKey}
			if err := SaveCredentials(path, saved); err != nil {
				t.Fatal(err)
			}
			cfg.CredentialFile = path
			c = New(cfg)
			if _, err := c.Account(context.Background()); err != nil {
				t.Fatal(err)
			}
			enrollment, err := c.Enroll(context.Background(), EnrollmentRequest{Platform: "linux"})
			if err != nil {
				t.Fatal(err)
			}
			saved.DeviceID = enrollment.DeviceID
			saved.DeviceKey = enrollment.APIKey
			if err := SaveCredentials(path, saved); err != nil {
				t.Fatal(err)
			}
			c = New(cfg)
			if _, err := c.DeviceConfig(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := c.Heartbeat(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := c.ReportTelemetry(context.Background(), &TelemetryReport{EventID: testEventID}); err != nil {
				t.Fatal(err)
			}
			if len(telemetryIDs) != 2 || telemetryIDs[0] != telemetryIDs[1] {
				t.Fatal("telemetry retry changed identity")
			}
		})
	}
}
func TestReputationAndFeedsContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "account-key" {
			t.Error("missing account auth")
		}
		switch r.URL.Path {
		case "/v1/reputation/lookup":
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			if b["indicator"] != "192.0.2.1" || b["type"] != "ip" {
				t.Error("wrong lookup body")
			}
			w.Write([]byte(`{"indicator":"192.0.2.1","indicator_type":"ip","reputation":"suspicious","score":35}`))
		case "/v1/reputation/lookup/bulk":
			var b map[string][]string
			json.NewDecoder(r.Body).Decode(&b)
			if len(b["indicators"]) != 2 {
				t.Error("wrong bulk body")
			}
			w.Write([]byte(`{"results":[{"indicator":"a.example","reputation":"clean"},{"indicator":"192.0.2.1","reputation":"suspicious"}]}`))
		case "/v1/feeds":
			w.Write([]byte(`{"feeds":[{"feed_name":"test","accessible":true},{"feed_name":"premium","accessible":false}]}`))
		case "/v1/feeds/test":
			if r.URL.Query().Get("limit") != "1000" || r.URL.Query().Get("offset") != "0" {
				t.Error("pagination missing")
			}
			w.Write([]byte(`{"returned":2,"entries":[{"indicator_type":"ip","indicator_value":"192.0.2.1"},{"indicator_type":"domain","indicator_value":"a.example"}]}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c := New(&Config{BaseURL: server.URL, AllowHTTP: true, APIKey: "account-key"})
	if r, err := c.LookupIP(context.Background(), "192.0.2.1"); err != nil || r.Score != 35 {
		t.Fatalf("lookup=%+v err=%v", r, err)
	}
	if _, err := c.BulkLookup(context.Background(), &BulkLookupRequest{Domains: []string{"a.example"}, IPs: []string{"192.0.2.1"}}); err != nil {
		t.Fatal(err)
	}
	d, i, err := c.ThreatSnapshot(context.Background(), time.Time{})
	if err != nil || d.Count != 1 || i.Count != 1 {
		t.Fatalf("snapshot %v %v %v", d, i, err)
	}
}
func TestRejectionsDoNotLeakSecretsOrRetryEnrollment(t *testing.T) {
	var count atomic.Int32
	for _, status := range []int{401, 403, 429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			count.Store(0)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				w.WriteHeader(status)
				w.Write([]byte(`{"api_key":"secret-key","error":"secret-key"}`))
			}))
			defer server.Close()
			c := New(&Config{BaseURL: server.URL, AllowHTTP: true, APIKey: "secret-key"})
			_, err := c.Enroll(context.Background(), EnrollmentRequest{})
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != status || strings.Contains(err.Error(), "secret-key") {
				t.Fatalf("unsafe error %v", err)
			}
			if count.Load() != 1 {
				t.Fatal("enrollment automatically retried")
			}
		})
	}
}
func TestRedirectAndCredentialOrigin(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer server.Close()
	c := New(&Config{BaseURL: server.URL, AllowHTTP: true, APIKey: "secret"})
	if _, err := c.Account(context.Background()); err == nil {
		t.Fatal("redirect accepted")
	}
	if leaked.Load() {
		t.Fatal("redirect followed")
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := SaveCredentials(path, &Credentials{BaseURL: "https://api.darkapi.io", APIKey: "secret"}); err != nil {
		t.Fatal(err)
	}
	if New(&Config{BaseURL: "https://example.com", CredentialFile: path}).Validate() == nil {
		t.Fatal("credential sent to another endpoint")
	}
	if _, err := NormalizeURL("http://api.darkapi.io", false); err == nil {
		t.Fatal("plaintext accepted")
	}
	for _, alias := range []string{"https://darkapi.io/api/", "https://api.darkapi.io/"} {
		if normalized, err := NormalizeURL(alias, false); err != nil || normalized != DefaultURL {
			t.Fatal(normalized, err)
		}
	}
	if err := os.WriteFile(filepath.Join(t.TempDir(), "bad.json"), []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestCancellationAndInvalidAcknowledgement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"status":"accepted","event_id":"wrong"}`))
	}))
	defer server.Close()
	c := New(&Config{BaseURL: server.URL, AllowHTTP: true})
	c.deviceID = "dev_123"
	c.deviceKey = "key"
	if err := c.ReportTelemetry(context.Background(), &TelemetryReport{EventID: testEventID}); err == nil {
		t.Fatal("mismatched acknowledgement accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Heartbeat(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
