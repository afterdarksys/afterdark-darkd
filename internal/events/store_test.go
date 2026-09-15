package events

import (
	"context"
	"path/filepath"
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
