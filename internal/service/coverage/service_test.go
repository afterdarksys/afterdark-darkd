package coverage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
)

func TestCoverageStartsLocallyWithoutForwarder(t *testing.T) {
	ctx := context.Background()
	store := events.New(filepath.Join(t.TempDir(), "events.db"), "endpoint-a")
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer store.Stop(ctx)
	registry := service.NewRegistry()
	if err := registry.Register(store); err != nil {
		t.Fatal(err)
	}
	called := 0
	coverage := &Service{
		registry: registry, deploymentMode: "dogfood",
		collector: func(ctx context.Context, store *events.Store, _ service.RegistryInterface, mode string) error {
			called++
			if mode != "dogfood" {
				t.Fatalf("deployment mode lost: %q", mode)
			}
			return store.Publish(ctx, events.Event{Source: ServiceName, Type: "sensor.health"})
		},
	}
	if err := coverage.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer coverage.Stop(ctx)
	if called != 1 || coverage.Health().Status != service.HealthHealthy {
		t.Fatalf("local coverage did not collect: called=%d health=%+v", called, coverage.Health())
	}
	rows, err := store.ListRecent(ctx, 1, time.Time{}, "sensor.health", "")
	if err != nil || len(rows) != 1 || rows[0].Source != ServiceName {
		t.Fatal(rows, err)
	}
}

func TestCoverageRequiresDurableEventStore(t *testing.T) {
	coverage := New(service.NewRegistry(), "dogfood")
	if err := coverage.Start(context.Background()); err == nil {
		t.Fatal("coverage started without a durable event store")
	}
}
