// Package events persists normalized endpoint observations before export.
package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const ServiceName = "event_store"
const MaxPayload = 64 * 1024
const MaxEvents = 10000

// Event retains a stable ID across retries. Data holds source-specific fields.
type Event struct {
	CorrelationID    string          `json:"correlation_id,omitempty"`
	SchemaVersion    int             `json:"schema_version,omitempty"`
	BootID           string          `json:"boot_id,omitempty"`
	StreamID         string          `json:"stream_id,omitempty"`
	Sequence         int64           `json:"sequence,omitempty"`
	AgentVersion     string          `json:"agent_version,omitempty"`
	CollectionStatus string          `json:"collection_status,omitempty"`
	Entities         map[string]any  `json:"entities,omitempty"`
	Facts            map[string]any  `json:"facts,omitempty"`
	ID               string          `json:"id"`
	Version          int             `json:"version"`
	Endpoint         string          `json:"endpoint_id"`
	Session          string          `json:"session_id"`
	Time             time.Time       `json:"time"`
	Source           string          `json:"source"`
	Type             string          `json:"type"`
	Severity         string          `json:"severity"`
	Data             json.RawMessage `json:"data"`
}
type Store struct {
	mu                      sync.Mutex
	db                      *sql.DB
	path, endpoint, session string
	dropped                 atomic.Uint64
}

func New(path, endpoint string) *Store {
	return &Store{path: path, endpoint: endpoint, session: uuid.NewString()}
}
func (s *Store) Name() string { return ServiceName }
func (s *Store) Configure(interface{}) error {
	return fmt.Errorf("event store configuration requires restart")
}
func (s *Store) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	f.Close()
	if err = os.Chmod(s.path, 0600); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", s.path)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", `CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,time INTEGER NOT NULL,kind TEXT NOT NULL,severity TEXT NOT NULL,payload BLOB NOT NULL,delivered INTEGER NOT NULL DEFAULT 0)`, `CREATE INDEX IF NOT EXISTS events_pending ON events(delivered,seq)`, `CREATE TABLE IF NOT EXISTS event_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)`, `CREATE TABLE IF NOT EXISTS command_results(id TEXT PRIMARY KEY,action TEXT NOT NULL,result BLOB NOT NULL,status TEXT NOT NULL)`, "PRAGMA user_version=1"} {
		if _, err = db.ExecContext(ctx, q); err != nil {
			db.Close()
			return err
		}
	}
	for key, value := range map[string]string{"stream_id": uuid.NewString(), "sequence": "0"} {
		if _, err = db.ExecContext(ctx, "INSERT OR IGNORE INTO event_metadata(key,value) VALUES(?,?)", key, value); err != nil {
			db.Close()
			return err
		}
	}
	s.db = db
	return nil
}
func (s *Store) Stop(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}
func (s *Store) Health() service.HealthStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := service.HealthStatus{Status: service.HealthHealthy, Message: "durable event store active", LastCheck: time.Now(), Metrics: map[string]interface{}{"rejected_events": s.dropped.Load()}}
	if s.db == nil {
		h.Status = service.HealthUnhealthy
		h.Message = "event store stopped"
	} else if s.dropped.Load() > 0 {
		h.Status = service.HealthDegraded
		h.Message = "event ingestion has rejected events"
	}
	return h
}
func (s *Store) Publish(ctx context.Context, e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.publishLocked(ctx, e, nil)
}
func (s *Store) publishLocked(ctx context.Context, e Event, receipt *CommandReceipt) error {
	fail := func(err error) error { s.dropped.Add(1); return err }
	if s.db == nil {
		return fail(fmt.Errorf("event store unavailable"))
	}
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE id=?", e.ID).Scan(&exists); err != nil {
		return fail(err)
	}
	if exists > 0 {
		if receipt != nil {
			_, err := s.db.ExecContext(ctx, "INSERT OR IGNORE INTO command_results(id,action,result,status) VALUES(?,?,?,?)", receipt.ID, receipt.Action, receipt.Result, receipt.Status)
			return err
		}
		return nil
	}
	e.Version = 1 // Preserve the existing event-store version field; schema_version governs the new envelope.
	e.SchemaVersion = 2
	e.BootID = reportBootID()
	e.AgentVersion = reportAgentVersion()
	e.CollectionStatus = "observed"
	e.Endpoint = s.endpoint
	e.Session = s.session
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.Severity == "" {
		e.Severity = "info"
	}
	if e.Source == "" || e.Type == "" {
		return fail(fmt.Errorf("event source and type required"))
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, "SELECT value FROM event_metadata WHERE key='stream_id'").Scan(&e.StreamID); err != nil {
		return fail(err)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE event_metadata SET value=CAST(value AS INTEGER)+1 WHERE key='sequence'"); err != nil {
		return fail(err)
	}
	if err = tx.QueryRowContext(ctx, "SELECT CAST(value AS INTEGER) FROM event_metadata WHERE key='sequence'").Scan(&e.Sequence); err != nil {
		return fail(err)
	}
	payload, err := json.Marshal(e)
	if err != nil {
		return fail(err)
	}
	if len(payload) > MaxPayload {
		return fail(fmt.Errorf("event exceeds payload limit"))
	}
	// Bound history; never evict unacknowledged evidence to admit another event.
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM events").Scan(&count); err != nil {
		return fail(err)
	}
	if count >= MaxEvents {
		r, err := tx.ExecContext(ctx, "DELETE FROM events WHERE seq IN (SELECT seq FROM events WHERE delivered=1 ORDER BY seq LIMIT 100)")
		if err != nil {
			return fail(err)
		}
		n, _ := r.RowsAffected()
		if n == 0 {
			return fail(fmt.Errorf("event outbox capacity reached"))
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO events(id,time,kind,severity,payload) VALUES(?,?,?,?,?)", e.ID, e.Time.UnixNano(), e.Type, e.Severity, payload); err != nil {
		return fail(err)
	}
	if receipt != nil {
		if _, err = tx.ExecContext(ctx, "INSERT INTO command_results(id,action,result,status) VALUES(?,?,?,?)", receipt.ID, receipt.Action, receipt.Result, receipt.Status); err != nil {
			return fail(err)
		}
	}
	return tx.Commit()
}
func (s *Store) List(ctx context.Context, limit int, pending bool, since time.Time, kind, severity string) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, fmt.Errorf("event store unavailable")
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := "SELECT payload FROM events WHERE time>=?"
	args := []interface{}{since.UnixNano()}
	if since.IsZero() {
		args[0] = int64(0)
	}
	if pending {
		q += " AND delivered=0"
	}
	if kind != "" {
		q += " AND kind=?"
		args = append(args, kind)
	}
	if severity != "" {
		q += " AND severity=?"
		args = append(args, severity)
	}
	q += " ORDER BY seq LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Event{}
	for rows.Next() {
		var data []byte
		var e Event
		if err = rows.Scan(&data); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(data, &e); err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}
func (s *Store) Ack(ctx context.Context, ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return fmt.Errorf("event store unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err = tx.ExecContext(ctx, "UPDATE events SET delivered=1 WHERE id=?", id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func Emit(reg service.RegistryInterface, source, kind, severity string, data interface{}) error {
	if reg == nil {
		return fmt.Errorf("registry unavailable")
	}
	s, ok := reg.Get(ServiceName).(*Store)
	if !ok {
		return fmt.Errorf("event store unavailable")
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	event := Event{Source: source, Type: kind, Severity: severity, Data: payload}
	if typed, ok := data.(map[string]interface{}); ok {
		if entities, ok := typed["entities"].(map[string]interface{}); ok {
			event.Entities = entities
		}
		if facts, ok := typed["facts"].(map[string]interface{}); ok {
			event.Facts = facts
		}
	}
	return s.Publish(ctx, event)
}
