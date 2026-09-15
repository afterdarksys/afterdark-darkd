package threat

import (
	"context"
	"github.com/afterdarksys/afterdark-darkd/internal/api/darkapi"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/internal/storage"
	storejson "github.com/afterdarksys/afterdark-darkd/internal/storage/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestFailedAuthenticationDoesNotRefreshThreatCache(t *testing.T) {
	var reject atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reject.Load() {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/feeds":
			w.Write([]byte(`{"feeds":[{"feed_name":"fixture","accessible":true}]}`))
		case "/v1/feeds/fixture":
			w.Write([]byte(`{"returned":1,"entries":[{"indicator_type":"domain","indicator_value":"bad.example"}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	store := storejson.New()
	if err := store.Initialize(context.Background(), &storage.Config{Path: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := models.DefaultConfig().Services.ThreatIntel
	cfg.SyncInterval = time.Minute
	s := New(&cfg, store, darkapi.New(&darkapi.Config{BaseURL: server.URL, AllowHTTP: true, APIKey: "account-key"}))
	s.performSync(context.Background())
	first := s.GetLastSync()
	if first.IsZero() {
		t.Fatal("successful sync was not recorded")
	}
	reject.Store(true)
	s.performSync(context.Background())
	if !s.GetLastSync().Equal(first) {
		t.Fatal("failed authentication refreshed cache time")
	}
	if bad, _ := s.IsDomainMalicious("bad.example"); !bad {
		t.Fatal("last known threat data discarded")
	}
	if s.Health().Status != service.HealthDegraded {
		t.Fatal("authentication failure hidden from health")
	}
}
