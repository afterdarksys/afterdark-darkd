package ipc

import (
	"context"
	"encoding/json"
	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/metadata"
)

const tokenCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func TestGenerateSecureToken_IsRandom(t *testing.T) {
	t1, err := generateSecureToken(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t2, err := generateSecureToken(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if t1 == t2 {
		t.Error("two tokens should not be identical")
	}
	if len(t1) != 32 {
		t.Errorf("expected length 32, got %d", len(t1))
	}
	// Verify all chars are from the charset
	for _, c := range t1 {
		if !strings.ContainsRune(tokenCharset, c) {
			t.Errorf("unexpected character %q not in charset", c)
		}
	}
}

func TestGenerateSecureToken_Length(t *testing.T) {
	for _, n := range []int{16, 32, 64} {
		tok, err := generateSecureToken(n)
		if err != nil {
			t.Fatalf("length %d: unexpected error: %v", n, err)
		}
		if len(tok) != n {
			t.Errorf("length %d: got %d", n, len(tok))
		}
	}
}

func TestGenerateSecureToken_ZeroLength(t *testing.T) {
	tok, err := generateSecureToken(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "" {
		t.Errorf("expected empty string for length 0, got %q", tok)
	}
}

func TestValidateAuth_RejectsNoMetadata(t *testing.T) {
	s := &Server{config: &Config{RequireAuth: true}, authToken: "correcttoken"}
	err := s.validateAuth(context.Background())
	if err == nil {
		t.Error("expected error with no metadata in context")
	}
}

func TestValidateAuth_RejectsNoAuthHeader(t *testing.T) {
	s := &Server{config: &Config{RequireAuth: true}, authToken: "correcttoken"}
	md := metadata.New(map[string]string{"other": "value"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	err := s.validateAuth(ctx)
	if err == nil {
		t.Error("expected error with no authorization header")
	}
}

func TestValidateAuth_RejectsBadToken(t *testing.T) {
	s := &Server{config: &Config{RequireAuth: true}, authToken: "correcttoken"}
	md := metadata.Pairs("authorization", "Bearer wrongtoken")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	err := s.validateAuth(ctx)
	if err == nil {
		t.Error("expected error with wrong token")
	}
}

func TestValidateAuth_AcceptsCorrectToken(t *testing.T) {
	s := &Server{config: &Config{RequireAuth: true}, authToken: "correcttoken"}
	md := metadata.Pairs("authorization", "Bearer correcttoken")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if err := s.validateAuth(ctx); err != nil {
		t.Errorf("expected no error with correct token, got: %v", err)
	}
}

func TestValidateAuth_SkipsWhenAuthDisabled(t *testing.T) {
	s := &Server{config: &Config{RequireAuth: false}, authToken: ""}
	err := s.validateAuth(context.Background())
	if err != nil {
		t.Errorf("expected no error when auth disabled, got: %v", err)
	}
}

func TestUnavailableOperations(t *testing.T) {
	s := &Server{}
	ctx := context.Background()
	if _, err := s.StopService(ctx, &pb.ServiceRequest{Name: "missing"}); status.Code(err) != codes.Unimplemented {
		t.Fatal(err)
	}
	if _, err := s.CheckBulk(ctx, &pb.CheckBulkRequest{Domains: []string{"example.com"}}); status.Code(err) != codes.Unavailable {
		t.Fatal(err)
	}
	s.registry = service.NewRegistry()
	if _, err := s.TriggerScan(ctx, &pb.TriggerScanRequest{ScanType: "bogus"}); status.Code(err) != codes.InvalidArgument {
		t.Fatal(err)
	}
}

func TestGetEventsExposesCanonicalEvidenceMetadata(t *testing.T) {
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
	if err := store.Publish(ctx, events.Event{
		ID: "partial-observation", Source: "fixture", Type: "process.observed", Severity: "warning",
		CollectionStatus: events.CollectionPartial,
		Entities:         map[string]any{"process": map[string]any{"pid": 41}},
		Facts:            map[string]any{"collection_method": "polling"},
	}); err != nil {
		t.Fatal(err)
	}
	server := &Server{registry: registry}
	response, err := server.GetEvents(ctx, &pb.GetEventsRequest{Limit: 10})
	if err != nil || len(response.Events) != 1 {
		t.Fatal(response, err)
	}
	metadata := response.Events[0].Metadata
	if metadata["collection_status"] != events.CollectionPartial || metadata["schema_version"] != "2" || metadata["sequence"] != "1" || metadata["endpoint_id"] != "endpoint-a" {
		t.Fatalf("canonical metadata missing: %#v", metadata)
	}
	var entities map[string]any
	if err := json.Unmarshal([]byte(metadata["entities"]), &entities); err != nil || entities["process"] == nil {
		t.Fatalf("entities metadata was not structured JSON: %q (%v)", metadata["entities"], err)
	}
	var facts map[string]any
	if err := json.Unmarshal([]byte(metadata["facts"]), &facts); err != nil || facts["collection_method"] != "polling" {
		t.Fatalf("facts metadata was not structured JSON: %q (%v)", metadata["facts"], err)
	}
	if response.Events[0].Timestamp == nil || response.Events[0].Timestamp.Seconds <= 0 {
		t.Fatalf("event timestamp missing: %#v", response.Events[0])
	}
}

func TestGetEventsReturnsNewestEvidenceFirst(t *testing.T) {
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
	for _, id := range []string{"old", "new"} {
		if err := store.Publish(ctx, events.Event{ID: id, Source: "fixture", Type: "sensor.health"}); err != nil {
			t.Fatal(err)
		}
	}
	response, err := (&Server{registry: registry}).GetEvents(ctx, &pb.GetEventsRequest{Limit: 10})
	if err != nil || len(response.Events) != 2 || response.Events[0].Id != "new" || response.Events[1].Id != "old" {
		t.Fatal(response, err)
	}
}
