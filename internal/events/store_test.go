package events

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReplayAndDeduplicate(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "events.db")
	s := New(p, "host")
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	e := Event{ID: "stable", Source: "test", Type: "process.exec"}
	for i := 0; i < 2; i++ {
		if err := s.Publish(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	s.Stop(ctx)
	s = New(p, "host")
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	batch, err := s.List(ctx, 10, true, time.Time{}, "", "")
	if err != nil || len(batch) != 1 || batch[0].ID != "stable" {
		t.Fatal(batch, err)
	}
	if err := s.Ack(ctx, []string{"stable"}); err != nil {
		t.Fatal(err)
	}
	batch, err = s.List(ctx, 10, true, time.Time{}, "", "")
	if err != nil || len(batch) != 0 {
		t.Fatal(batch, err)
	}
}

func TestProvenanceSurvivesRestartAndFailedWrites(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "events.db")
	s := New(path, "host")
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	first := Event{ID: "one", Source: "fixture", Type: "process.exec"}
	if err := s.Publish(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(ctx, first); err != nil {
		t.Fatal(err)
	}
	oversized, _ := json.Marshal(map[string]string{"value": strings.Repeat("x", MaxPayload)})
	if err := s.Publish(ctx, Event{ID: "oversized", Source: "fixture", Type: "test", Data: oversized}); err == nil {
		t.Fatal("expected size rejection")
	}
	s.Stop(ctx)
	s = New(path, "host")
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	if err := s.Publish(ctx, Event{ID: "two", Source: "fixture", Type: "test"}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.List(ctx, 10, true, time.Time{}, "", "")
	if err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	byID := map[string]Event{}
	for _, e := range rows {
		byID[e.ID] = e
	}
	a, b := byID["one"], byID["two"]
	if a.SchemaVersion != SchemaVersion || a.StreamID == "" || a.StreamID != b.StreamID || a.Sequence != 1 || b.Sequence != 2 || a.CollectionStatus != "observed" {
		t.Fatalf("bad provenance: %+v %+v", a, b)
	}
}

func TestCollectionStatusIsPreservedAndValidated(t *testing.T) {
	ctx := context.Background()
	s := New(filepath.Join(t.TempDir(), "events.db"), "host")
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	if err := s.Publish(ctx, Event{ID: "partial", Source: "fixture", Type: "sensor.health", CollectionStatus: CollectionPartial}); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(ctx, Event{ID: "invalid", Source: "fixture", Type: "sensor.health", CollectionStatus: "complete"}); err == nil {
		t.Fatal("expected invalid collection status to be rejected")
	}
	rows, err := s.List(ctx, 10, true, time.Time{}, "", "")
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	if rows[0].CollectionStatus != CollectionPartial {
		t.Fatalf("collection status was rewritten: %+v", rows[0])
	}
}

func TestListRecentDoesNotChangeOutboxOrder(t *testing.T) {
	ctx := context.Background()
	s := New(filepath.Join(t.TempDir(), "events.db"), "host")
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	for _, id := range []string{"old", "new"} {
		if err := s.Publish(ctx, Event{ID: id, Source: "fixture", Type: "sensor.health"}); err != nil {
			t.Fatal(err)
		}
	}
	recent, err := s.ListRecent(ctx, 10, time.Time{}, "sensor.health", "")
	if err != nil || len(recent) != 2 || recent[0].ID != "new" || recent[1].ID != "old" {
		t.Fatal(recent, err)
	}
	pending, err := s.List(ctx, 10, true, time.Time{}, "sensor.health", "")
	if err != nil || len(pending) != 2 || pending[0].ID != "old" || pending[1].ID != "new" {
		t.Fatal(pending, err)
	}
}

func TestCommandReceiptAndCanaryAreAtomicAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "commands.db")
	s := New(path, "host")
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	receipt := CommandReceipt{ID: "command", Action: "delivery_canary", Status: "succeeded", Result: json.RawMessage(`{"event_id":"command"}`)}
	oversized, _ := json.Marshal(map[string]string{"value": strings.Repeat("x", MaxPayload)})
	if err := s.CompleteCommand(ctx, receipt, &Event{Source: "response", Type: "delivery.canary", Data: oversized}); err == nil {
		t.Fatal("expected rejection")
	}
	if result, err := s.CommandReceipt(ctx, "command"); err != nil || result != nil {
		t.Fatal("receipt survived rejected event", result, err)
	}
	if err := s.CompleteCommand(ctx, receipt, &Event{Source: "response", Type: "delivery.canary"}); err != nil {
		t.Fatal(err)
	}
	s.Stop(ctx)
	s = New(path, "host")
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	if err := s.CompleteCommand(ctx, receipt, &Event{Source: "response", Type: "delivery.canary"}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.List(ctx, 10, true, time.Time{}, "", "")
	if err != nil || len(rows) != 1 || rows[0].ID != "command" {
		t.Fatal(rows, err)
	}
	saved, err := s.CommandReceipt(ctx, "command")
	if err != nil || saved.Action != receipt.Action {
		t.Fatal(saved, err)
	}
}
