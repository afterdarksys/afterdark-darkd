package siem

import (
	"context"
	"encoding/json"
	"github.com/afterdarksys/afterdark-darkd/internal/api/darkapi"
	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestRejectedBatchRemainsPending(t *testing.T) {
	ctx := context.Background()
	store := events.New(filepath.Join(t.TempDir(), "events.db"), "host")
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer store.Stop(ctx)
	r := service.NewRegistry()
	r.Register(store)
	code := 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
	defer server.Close()
	s, _ := New(&Config{URL: server.URL, BatchSize: 10}, r)
	if err := store.Publish(ctx, events.Event{Source: "test", Type: "test", ID: "one"}); err != nil {
		t.Fatal(err)
	}
	if s.forward(ctx) == nil {
		t.Fatal("rejection accepted")
	}
	pending, _ := store.List(ctx, 10, true, time.Time{}, "", "")
	if len(pending) != 1 {
		t.Fatal("batch lost")
	}
	code = 200
	if err := s.forward(ctx); err != nil {
		t.Fatal(err)
	}
	pending, _ = store.List(ctx, 10, true, time.Time{}, "", "")
	if len(pending) != 0 {
		t.Fatal("batch not acknowledged")
	}
}

func TestDarkAPIAcknowledgementAndRestartReplay(t *testing.T) {
	ctx := context.Background()
	var accept atomic.Bool
	const id = "b7ad5c3a-d1b1-43f1-b350-d7be39b16a0f"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "device-key" || r.Header.Get("X-Device-ID") != "dev_123" {
			t.Error("device auth missing")
		}
		if r.URL.Path == "/v1/devices/heartbeat" {
			w.Write([]byte(`{"success":true}`))
			return
		}
		if r.URL.Path == "/api/v1/endpoints/darkd/commands/claim" {
			w.Write([]byte(`{"command":null}`))
			return
		}
		if r.URL.Path != "/api/v1/darkd/telemetry" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		var report darkapi.TelemetryReport
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Error(err)
		}
		var event events.Event
		json.Unmarshal(report.Event, &event)
		if report.SystemID != "dev_123" || event.ID != report.EventID || (event.Type == "test" && event.ID != id) {
			t.Error("event envelope lost identity")
		}
		if !accept.Load() {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(202)
		w.Write([]byte(`{"success":true,"status":"accepted","event_id":"` + report.EventID + `"}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	credentials := filepath.Join(dir, "credentials.json")
	if err := darkapi.SaveCredentials(credentials, &darkapi.Credentials{BaseURL: server.URL, DeviceID: "dev_123", DeviceKey: "device-key"}); err != nil {
		t.Fatal(err)
	}
	client := darkapi.New(&darkapi.Config{BaseURL: server.URL, CredentialFile: credentials, AllowHTTP: true})
	dbpath := filepath.Join(dir, "events.db")
	store := events.New(dbpath, "local-host")
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Publish(ctx, events.Event{ID: id, Type: "test", Source: "fixture"}); err != nil {
		t.Fatal(err)
	}
	registry := service.NewRegistry()
	registry.Register(store)
	forwarder, _ := New(&Config{DarkAPI: client, BatchSize: 10}, registry)
	if err := forwarder.forward(ctx); err == nil {
		t.Fatal("rejection was acknowledged")
	}
	store.Stop(ctx)
	store = events.New(dbpath, "local-host")
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer store.Stop(ctx)
	registry = service.NewRegistry()
	registry.Register(store)
	forwarder, _ = New(&Config{DarkAPI: client, BatchSize: 10}, registry)
	pending, err := store.List(ctx, 10, true, time.Time{}, "test", "")
	if err != nil || len(pending) != 1 {
		t.Fatal("pending event not replayed", err)
	}
	accept.Store(true)
	if err := forwarder.forward(ctx); err != nil {
		t.Fatal(err)
	}
	pending, err = store.List(ctx, 10, true, time.Time{}, "", "")
	if err != nil || len(pending) != 0 {
		t.Fatal("accepted event not acknowledged", err)
	}
}
