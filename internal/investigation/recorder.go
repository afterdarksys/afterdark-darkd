package investigation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
)

// Recorder serializes sensor batches to disk. It retains only process identities
// in memory, and exposes write failures through the existing service health API.
type Recorder struct {
	mu            sync.Mutex
	config        models.InvestigationConfig
	path          string
	store         *Store
	endpoint      string
	seen          map[string][32]byte
	lastWrite     time.Time
	lastError     string
	failedBatches uint64
}

func NewRecorder(dataDir string, cfg models.InvestigationConfig) *Recorder {
	return &Recorder{config: cfg, path: filepath.Join(dataDir, "investigation", "events.db"), seen: map[string][32]byte{}}
}
func (r *Recorder) Name() string { return "investigation" }
func (r *Recorder) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.store != nil {
		return nil
	}
	if r.config.Retention <= 0 || r.config.MaxEvents <= 0 {
		return fmt.Errorf("investigation retention and max_events must be positive")
	}
	s, err := OpenStore(r.path)
	if err != nil {
		return err
	}
	id, err := s.EndpointID()
	if err == nil {
		err = s.Append(ctx, nil, time.Now().Add(-r.config.Retention), r.config.MaxEvents)
	}
	if err != nil {
		s.Close()
		return err
	}
	r.store, r.endpoint = s, id
	r.seen = map[string][32]byte{}
	return nil
}
func (r *Recorder) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.store == nil {
		return nil
	}
	err := r.store.Close()
	r.store = nil
	return err
}
func (r *Recorder) Configure(config interface{}) error {
	return fmt.Errorf("investigation configuration changes require a daemon restart")
}
func (r *Recorder) Health() service.HealthStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, message := service.HealthHealthy, "recording polling observations"
	if r.lastWrite.IsZero() {
		state, message = service.HealthUnknown, "waiting for sensor observations"
	}
	if r.lastError != "" {
		state, message = service.HealthDegraded, r.lastError
	}
	if r.store == nil {
		state, message = service.HealthUnhealthy, "recorder stopped"
	}
	return service.HealthStatus{Status: state, Message: message, LastCheck: time.Now(), Metrics: map[string]interface{}{
		"endpoint_id": r.endpoint, "last_write": r.lastWrite, "failed_batches": r.failedBatches,
		"collection_method": "polling", "command_line_collection": r.config.IncludeCommandLine,
	}}
}
func (r *Recorder) record(events []Event) bool {
	if r.store == nil {
		r.lastError = "recorder is not running"
		r.failedBatches++
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := r.store.Append(ctx, events, time.Now().Add(-r.config.Retention), r.config.MaxEvents)
	if err != nil {
		r.lastError = err.Error()
		r.failedBatches++
		return false
	}
	r.lastError = ""
	r.lastWrite = time.Now().UTC()
	return true
}

// ObserveProcesses records new instances and changes to observed metadata, not
// invented launch or exit events. Failed writes remain eligible for the next scan.
func (r *Recorder) ObserveProcesses(snapshot models.ProcessSnapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	parents := map[int32]*models.Process{}
	for i := range snapshot.Processes {
		parents[snapshot.Processes[i].PID] = &snapshot.Processes[i]
	}
	seen := map[string][32]byte{}
	events := []Event{}
	for _, p := range snapshot.Processes {
		e := ProcessEvent(r.endpoint, p, parents[p.PPID], snapshot.Timestamp, r.config.IncludeCommandLine)
		key := e.EntityID
		body, _ := json.Marshal(struct {
			Fields map[string]string
			Parent string
		}{e.Fields, e.ParentEntityID})
		fingerprint := sha256.Sum256(body)
		previous, exists := r.seen[key]
		// No durable correlation for unknown start times; observe each scan.
		if key == "" || !exists || previous != fingerprint {
			events = append(events, e)
		}
		if key != "" {
			seen[key] = fingerprint
		}
	}
	if r.record(events) {
		r.seen = seen
	}
}

func (r *Recorder) ObserveConnections(observations []models.ConnectionEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	events := make([]Event, 0, len(observations))
	for _, event := range observations {
		events = append(events, ConnectionEvent(r.endpoint, event))
	}
	r.record(events)
}
