package investigation

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

// OpenReader never creates a missing database or changes its schema.
func OpenReader(path string) (*Store, error) { return open(path, true) }
func OpenStore(path string) (*Store, error)  { return open(path, false) }

func open(path string, readonly bool) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if !readonly {
		if err := os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		if err := f.Chmod(0600); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
	q := url.Values{"_pragma": {"busy_timeout(5000)"}}
	if readonly {
		q.Set("mode", "ro")
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	if !readonly {
		_, err = db.Exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
observed INTEGER NOT NULL, endpoint TEXT NOT NULL, entity TEXT NOT NULL, kind TEXT NOT NULL, body BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS events_time ON events(observed, seq);
CREATE INDEX IF NOT EXISTS events_entity ON events(entity, observed);
INSERT OR IGNORE INTO metadata(key, value) VALUES ('endpoint_id', ?);`, uuid.NewString())
		if err != nil {
			db.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) EndpointID() (string, error) {
	var id string
	err := s.db.QueryRow("SELECT value FROM metadata WHERE key = 'endpoint_id'").Scan(&id)
	return id, err
}

// Append persists an entire batch and applies retention atomically. Failed batches
// are not reported as recorded. The row cap bounds retained events, not file bytes.
func (s *Store) Append(ctx context.Context, events []Event, cutoff time.Time, maxEvents int) error {
	if maxEvents <= 0 {
		return fmt.Errorf("max_events must be positive")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, e := range events {
		if err := e.Validate(); err != nil {
			return err
		}
		body, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO events(id, observed, endpoint, entity, kind, body) VALUES(?,?,?,?,?,?)", e.ID, e.Timestamp.UnixNano(), e.EndpointID, e.EntityID, e.Kind, body); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM events WHERE observed < ?", cutoff.UnixNano()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM events WHERE seq IN (SELECT seq FROM events ORDER BY observed DESC, seq DESC LIMIT -1 OFFSET ?)", maxEvents); err != nil {
		return err
	}
	return tx.Commit()
}

type Filter struct {
	EndpointID string
	EntityID   string
	Kind       string
	Since      time.Time
	Until      time.Time
	Limit      int // zero streams the complete matching evidence set
}

// Walk uses one SQL read snapshot and stable chronological ordering. Callbacks
// must not call back into this Store, which has a single connection.
func (s *Store) Walk(ctx context.Context, f Filter, visit func(Event) error) error {
	if f.Limit < 0 || (!f.Since.IsZero() && !f.Until.IsZero() && f.Since.After(f.Until)) {
		return fmt.Errorf("invalid timeline range or limit")
	}
	query := "SELECT body FROM events WHERE 1=1"
	args := []interface{}{}
	for _, pair := range [][2]string{{"endpoint", f.EndpointID}, {"entity", f.EntityID}, {"kind", f.Kind}} {
		if pair[1] != "" {
			query += " AND " + pair[0] + " = ?"
			args = append(args, pair[1])
		}
	}
	if !f.Since.IsZero() {
		query += " AND observed >= ?"
		args = append(args, f.Since.UnixNano())
	}
	if !f.Until.IsZero() {
		query += " AND observed <= ?"
		args = append(args, f.Until.UnixNano())
	}
	query += " ORDER BY observed, seq"
	if f.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, f.Limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return err
		}
		var event Event
		if err := json.Unmarshal(body, &event); err != nil {
			return err
		}
		if err := event.Validate(); err != nil {
			return err
		}
		if err := visit(event); err != nil {
			return err
		}
	}
	return rows.Err()
}
