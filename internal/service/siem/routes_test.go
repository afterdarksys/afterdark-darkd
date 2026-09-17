package siem

import (
	"context"
	"encoding/json"
	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVendorAcknowledgements(t *testing.T) {
	for _, tc := range []struct {
		format, reply, header, value string
		reject                       bool
	}{
		{"splunk", `{"code":0}`, "Authorization", "Splunk secret", false},
		{"splunk", `{"code":4}`, "Authorization", "Splunk secret", true},
		{"splunk", `{}`, "Authorization", "Splunk secret", true},
		{"elastic", `{"errors":false,"items":[{"index":{"status":201}}]}`, "Authorization", "ApiKey secret", false},
		{"elastic", `{"errors":true,"items":[]}`, "Authorization", "ApiKey secret", true},
		{"elastic", `{"errors":false}`, "Authorization", "ApiKey secret", true},
		{"datadog", `{}`, "DD-API-KEY", "secret", false},
	} {
		t.Run(tc.format+tc.reply, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(tc.header) != tc.value {
					t.Error("missing vendor credentials")
				}
				data, _ := io.ReadAll(r.Body)
				if !strings.Contains(string(data), "stable-id") {
					t.Error("event identity missing")
				}
				if tc.format == "elastic" && (!strings.HasSuffix(string(data), "\n") || strings.Count(string(data), "\n") != 2) {
					t.Error("invalid bulk framing")
				}
				if tc.format == "datadog" {
					var logs []struct {
						Message string `json:"message"`
					}
					if err := json.Unmarshal(data, &logs); err != nil || len(logs) != 1 || !json.Valid([]byte(logs[0].Message)) {
						t.Error("Datadog message must contain a JSON string")
					}
				}
				io.WriteString(w, tc.reply)
			}))
			defer srv.Close()
			s, _ := New(&Config{}, nil)
			err := s.deliver(context.Background(), Route{Format: tc.format, URL: srv.URL, AuthToken: "secret", Index: "events"}, []events.Event{{ID: "stable-id", Time: time.Now()}})
			if (err != nil) != tc.reject {
				t.Fatalf("error=%v, reject=%v", err, tc.reject)
			}
		})
	}
}

func TestAllRoutesMustAcceptBeforeAcknowledgement(t *testing.T) {
	ctx := context.Background()
	store := events.New(filepath.Join(t.TempDir(), "events.db"), "host")
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer store.Stop(ctx)
	reg := service.NewRegistry()
	reg.Register(store)
	accepted := 0
	reject := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" && reject {
			w.WriteHeader(503)
			return
		}
		accepted++
	}))
	defer srv.Close()
	s, _ := New(&Config{Routes: []Route{{URL: srv.URL + "/ok", Severities: []string{"high"}}, {URL: srv.URL + "/fail"}}}, reg)
	if err := store.Publish(ctx, events.Event{ID: "event", Type: "detection", Source: "fixture", Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	if err := s.forward(ctx); err == nil {
		t.Fatal("failed route acknowledged")
	}
	pending, _ := store.List(ctx, 10, true, time.Time{}, "", "")
	if len(pending) != 1 {
		t.Fatal("event lost")
	}
	reject = false
	if err := s.forward(ctx); err != nil {
		t.Fatal(err)
	}
	pending, _ = store.List(ctx, 10, true, time.Time{}, "", "")
	if len(pending) != 0 || accepted != 3 {
		t.Fatalf("pending=%d accepted=%d", len(pending), accepted)
	}
	if matches(Route{Types: []string{"other"}}, events.Event{Type: "detection"}) {
		t.Fatal("filter ignored")
	}
}

func TestRedirectIsNotAcknowledgement(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect followed") }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer source.Close()
	s, _ := New(&Config{}, nil)
	if err := s.deliver(context.Background(), Route{URL: source.URL}, []events.Event{{ID: "one"}}); err == nil {
		t.Fatal("redirect accepted")
	}
}
