package siem

import (
	"context"
	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
