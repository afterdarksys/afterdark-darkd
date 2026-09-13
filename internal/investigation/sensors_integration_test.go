//go:build integration

package investigation_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/investigation"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service/conntrack"
	"github.com/afterdarksys/afterdark-darkd/internal/service/process"
)

// This opt-in test reads real OS process/connection tables. It verifies both
// sensor callbacks reach the durable journal and stop before the journal closes.
func TestLiveSensorsRecordEvidence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dir := t.TempDir()
	recorder := investigation.NewRecorder(dir, models.InvestigationConfig{Retention: time.Hour, MaxEvents: 10000})
	if err := recorder.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer recorder.Stop(context.Background())
	cfg := &models.TrackingConfig{ProcessInterval: time.Hour, NetworkInterval: time.Hour, TrackLocalConns: true}
	procs := process.New(cfg)
	procs.SetObserver(recorder.ObserveProcesses)
	if err := procs.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer procs.Stop(context.Background())
	network := conntrack.New(cfg)
	connectionsObserved := false
	network.SetObserver(func(events []models.ConnectionEvent) { connectionsObserved = true; recorder.ObserveConnections(events) })
	if err := network.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := network.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := procs.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if !connectionsObserved {
		t.Fatalf("connection sensor did not publish: %+v", network.Health())
	}
	reader, err := investigation.OpenReader(filepath.Join(dir, "investigation", "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	processCount := 0
	if err := reader.Walk(ctx, investigation.Filter{Kind: "process.observed"}, func(e investigation.Event) error {
		processCount++
		if _, exists := e.Fields["process.command_line"]; exists {
			t.Error("command line collected without opt-in")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if processCount == 0 {
		t.Fatal("no live process observations persisted")
	}
}
