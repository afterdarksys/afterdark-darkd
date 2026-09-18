package events

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
)

func TestEmitNormalizesProcessObservation(t *testing.T) {
	ctx := context.Background()
	store := New(filepath.Join(t.TempDir(), "events.db"), "endpoint-a")
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer store.Stop(ctx)
	registry := service.NewRegistry()
	if err := registry.Register(store); err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	process := models.Process{PID: 41, PPID: 1, Name: "curl", Executable: "/usr/bin/curl", Username: "analyst", CommandLine: "curl --header token=secret", StartTime: started}
	if err := Emit(registry, "process_tracker", "process.observed", "info", process); err != nil {
		t.Fatal(err)
	}
	rows, err := store.List(ctx, 10, false, time.Time{}, "", "")
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	event := rows[0]
	processEntity, ok := event.Entities["process"].(map[string]interface{})
	if !ok || processEntity["pid"] != float64(41) || processEntity["executable"] != "/usr/bin/curl" {
		t.Fatalf("missing normalized process entity: %#v", event.Entities)
	}
	if event.Facts["collection_method"] != "polling" || event.Facts["process.ppid"] != float64(1) {
		t.Fatalf("missing process facts: %#v", event.Facts)
	}
	if _, present := event.Facts["process.command_line"]; present {
		t.Fatalf("command line leaked into correlation facts: %#v", event.Facts)
	}
}

func TestEmitNormalizesNetworkObservation(t *testing.T) {
	ctx := context.Background()
	store := New(filepath.Join(t.TempDir(), "events.db"), "endpoint-a")
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer store.Stop(ctx)
	registry := service.NewRegistry()
	if err := registry.Register(store); err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	connection := models.NetworkConnection{PID: 41, ProcessName: "curl", ProcessStartTime: started, Protocol: "tcp", LocalAddr: "10.0.0.4", LocalPort: 50213, RemoteAddr: "198.51.100.7", RemotePort: 443, State: "ESTABLISHED"}
	if err := Emit(registry, "connection_tracker", "network.connect", "info", connection); err != nil {
		t.Fatal(err)
	}
	rows, err := store.List(ctx, 10, false, time.Time{}, "", "")
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	event := rows[0]
	if event.Entities["network"] == nil || event.Facts["network.remote_port"] != float64(443) || event.Facts["collection_method"] != "polling" {
		t.Fatalf("missing normalized connection data: entities=%#v facts=%#v", event.Entities, event.Facts)
	}
}

func TestProcessAndNetworkObservationsShareProcessCorrelationID(t *testing.T) {
	ctx := context.Background()
	store := New(filepath.Join(t.TempDir(), "events.db"), "endpoint-a")
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer store.Stop(ctx)
	registry := service.NewRegistry()
	if err := registry.Register(store); err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	if err := Emit(registry, "process_tracker", "process.observed", "info", models.Process{PID: 41, Name: "curl", StartTime: started}); err != nil {
		t.Fatal(err)
	}
	if err := Emit(registry, "connection_tracker", "network.connect", "info", models.NetworkConnection{PID: 41, ProcessName: "curl", ProcessStartTime: started, Protocol: "tcp", RemoteAddr: "198.51.100.7", RemotePort: 443}); err != nil {
		t.Fatal(err)
	}
	rows, err := store.List(ctx, 10, false, time.Time{}, "", "")
	if err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	want := ProcessEntityID("endpoint-a", 41, started)
	if rows[0].CorrelationID != want || rows[1].CorrelationID != want {
		t.Fatalf("process lineage is not correlated: %#v", rows)
	}
}

func TestProcessEntityIDRejectsUnstableInputs(t *testing.T) {
	if got := ProcessEntityID("endpoint", 41, time.Time{}); got != "" {
		t.Fatalf("unstable identity: %q", got)
	}
	started := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	if got := ProcessEntityID("endpoint", 41, started); got != "endpoint:41:1789732800000000000" {
		t.Fatalf("unexpected identity: %q", got)
	}
}
