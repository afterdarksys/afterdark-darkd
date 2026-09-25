package events

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/journal"
)

func TestJournalReadsPartialFlowFromTheStore(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "events.sqlite")
	store := New(path, "endpoint-a")
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	registry := service.NewRegistry()
	if err := registry.Register(store); err != nil {
		t.Fatal(err)
	}
	if err := Emit(registry, "connection_tracker", "network.connect", "info", models.NetworkConnection{PID: 7, ProcessName: "curl", Protocol: "tcp", RemoteAddr: "198.51.100.8", RemotePort: 443}); err != nil {
		t.Fatal(err)
	}
	if err := Emit(registry, "dns_tunnel_detection", "dns.query", "info", DNSEvent("example.com", "A", "logs", 7, time.Time{})); err != nil {
		t.Fatal(err)
	}
	if err := store.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	reader, err := journal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	rows, err := reader.List(ctx, journal.Query{Types: []string{"network.connect", "dns.query"}, Limit: 10})
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	summary := journal.Summarize(rows)
	if summary.Complete || summary.Statuses[journal.StatusPartial] != 2 {
		t.Fatalf("polling flow without a process start looked complete: %+v", summary)
	}
}
