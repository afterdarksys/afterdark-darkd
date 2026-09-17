package ecosystem

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProviderContracts(t *testing.T) {
	cases := []struct{ provider, operation, target, method, path, auth string }{
		{"dnsscience", "domain", "Example.COM", "POST", "/api/v1/enrich/domain", "X-API-Key"},
		{"veribits", "dns", "example.com", "POST", "/api/v1/dns/check", "Authorization"},
		{"systemapi", "fleet", "", "GET", "/api/v1/fleet", "X-API-Key"},
		{"computeapi", "databases", "", "GET", "/api/v2/dbaas/instances", "X-API-Key"},
		{"planetapi", "ip-blacklist", "192.0.2.1", "GET", "/v1/ip-blacklist/192.0.2.1", "X-API-Key"},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != tc.method || r.URL.Path != tc.path {
					t.Errorf("wrong contract %s %s", r.Method, r.URL.Path)
				}
				expected := "test-credential"
				if tc.auth == "Authorization" {
					expected = "Bearer " + expected
				}
				if r.Header.Get(tc.auth) != expected || r.URL.RawQuery != "" {
					t.Error("missing or leaked auth")
				}
				if tc.method == "POST" {
					var payload map[string]any
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Error(err)
					}
					if payload["domain"] != "example.com" {
						t.Error(payload)
					}
					if tc.provider == "veribits" && payload["check_type"] != "records" {
						t.Error(payload)
					}
				}
				fmt.Fprint(w, `{"evidence":"provider output"}`)
			}))
			defer server.Close()
			c, err := New(tc.provider, server.URL, "test-credential", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			result, err := c.Query(context.Background(), tc.operation, tc.target)
			if err != nil || string(result) != `{"evidence":"provider output"}` || calls != 1 {
				t.Fatalf("%s %v calls=%d", result, err, calls)
			}
		})
	}
}

func TestProviderFailuresAndRedirectNeverLeakCredentials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"unauthorized", 401, `{"secret":"do not echo"}`}, {"limited", 429, `{}`}, {"upstream", 502, `{}`},
		{"invalid", 200, `<html>oops</html>`}, {"null", 200, `null`}, {"error envelope", 200, `{"error":"failed"}`},
		{"failure envelope", 200, `{"success":false}`}, {"oversize", 200, strings.Repeat(" ", 4*1024*1024+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer s.Close()
			c, _ := New("systemapi", s.URL, "do not echo", time.Second)
			_, err := c.Query(context.Background(), "fleet", "")
			if err == nil || strings.Contains(err.Error(), "do not echo") || calls != 1 {
				t.Fatalf("%v calls=%d", err, calls)
			}
		})
	}
	calls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer source.Close()
	c, _ := New("systemapi", source.URL, "credential", time.Second)
	if _, err := c.Query(context.Background(), "fleet", ""); err == nil || calls != 0 {
		t.Fatal("followed credential redirect")
	}
}

func TestValidationAndCancellation(t *testing.T) {
	for _, base := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/path", "https://example.com?key=secret"} {
		if _, err := New("systemapi", base, "key", time.Second); err == nil {
			t.Fatal(base)
		}
	}
	if _, err := New("systemapi", "https://example.com", "", time.Second); err == nil {
		t.Fatal("missing key")
	}
	c, _ := New("dnsscience", "https://example.com", "key", time.Second)
	for _, d := range []string{"localhost", "a/../../b.com", "https://example.com", "example.com?key=secret", "-a.example"} {
		if _, err := c.Query(context.Background(), "domain", d); err == nil {
			t.Fatal(d)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Query(ctx, "domain", "example.com"); err == nil {
		t.Fatal("ignored cancellation")
	}
}
