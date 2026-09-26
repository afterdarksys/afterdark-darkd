// Package journal reads the darkd schema-v2 event journal.
//
// Threats: a missing, unreadable, symlinked, oversized, wrong-schema, or
// malformed journal is an error. Empty results and rows marked partial,
// unavailable, or error are not a clean endpoint. This package does not
// collect sensors, authorize execution, or write the journal.
package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const SchemaVersion = 2
const MaxPayload = 64 * 1024
const maxLimit = 1000
const maxTypes = 8

const (
	StatusObserved    = "observed"
	StatusPartial     = "partial"
	StatusUnavailable = "unavailable"
	StatusError       = "error"
)

// FileTypes are the file observations the journal is the source of record for.
var FileTypes = []string{"file.integrity_changed", "file.write", "file.unlink"}

// FlowTypes are process-attributed connection observations.
var FlowTypes = []string{"network.connect"}

// SensorTypes is the endpoint timeline surface.
var SensorTypes = []string{
	"process.observed", "network.connect", "dns.query", "dns.capture",
	"file.integrity_changed", "file.write", "file.unlink",
	"endpoint_security.exec", "endpoint_security.fork", "endpoint_security.exit",
	"endpoint_security.signal",
}

// Record is one stored observation. Data is the original collector payload.
type Record struct {
	SchemaVersion    int             `json:"schema_version"`
	CollectionStatus string          `json:"collection_status"`
	ID               string          `json:"id"`
	Endpoint         string          `json:"endpoint_id"`
	Sequence         int64           `json:"sequence"`
	Time             time.Time       `json:"time"`
	Source           string          `json:"source"`
	Type             string          `json:"type"`
	Severity         string          `json:"severity"`
	Entities         map[string]any  `json:"entities,omitempty"`
	Facts            map[string]any  `json:"facts,omitempty"`
	Data             json.RawMessage `json:"data,omitempty"`
}

// Query bounds a read. Limit above maxLimit is rejected.
type Query struct {
	Types []string
	Since time.Time
	Limit int
}

// Summary is the only completeness claim a consumer should display.
type Summary struct {
	Count      int            `json:"count"`
	Complete   bool           `json:"complete"`
	Statuses   map[string]int `json:"statuses"`
	Limitation string         `json:"limitation,omitempty"`
	Enforced   bool           `json:"enforced"`
}

// Reader is a read-only view of events.sqlite.
type Reader struct {
	db *sql.DB
}

// DefaultPath is the daemon's packaged journal location.
func DefaultPath() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("PROGRAMDATA")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "AfterDark", "data", "events.sqlite")
	}
	return "/var/lib/afterdark/data/events.sqlite"
}

// Open rejects a path that is missing, not a regular file, or a symlink.
func Open(path string) (*Reader, error) {
	if path == "" {
		return nil, errors.New("event journal path required")
	}
	if strings.ContainsAny(path, "?\n\r") {
		return nil, errors.New("event journal path rejected")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("event journal unavailable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("event journal must be a regular file")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs), RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("event journal unavailable: %w", err)
	}
	var name string
	err = db.QueryRowContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name='events'").Scan(&name)
	if err != nil {
		db.Close()
		return nil, errors.New("event journal has no events table")
	}
	return &Reader{db: db}, nil
}

func (r *Reader) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

// List returns newest matches first. A malformed row fails the whole read.
func (r *Reader) List(ctx context.Context, q Query) ([]Record, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("event journal unavailable")
	}
	if q.Limit <= 0 || q.Limit > maxLimit {
		return nil, fmt.Errorf("event journal limit must be 1..%d", maxLimit)
	}
	if len(q.Types) > maxTypes {
		return nil, errors.New("event journal type filter is too wide")
	}
	sqlText := "SELECT kind, payload FROM events WHERE time>=?"
	args := []any{q.Since.UnixNano()}
	if q.Since.IsZero() {
		args[0] = int64(0)
	}
	if len(q.Types) > 0 {
		holders := make([]string, len(q.Types))
		for i, kind := range q.Types {
			if !validType(kind) {
				return nil, fmt.Errorf("event journal type %q rejected", kind)
			}
			holders[i] = "?"
			args = append(args, kind)
		}
		sqlText += " AND kind IN (" + strings.Join(holders, ",") + ")"
	}
	sqlText += " ORDER BY seq DESC LIMIT ?"
	args = append(args, q.Limit)
	rows, err := r.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var kind string
		var payload []byte
		if err = rows.Scan(&kind, &payload); err != nil {
			return nil, err
		}
		if len(payload) == 0 || len(payload) > MaxPayload {
			return nil, errors.New("event journal row exceeds payload limit")
		}
		var rec Record
		if err = json.Unmarshal(payload, &rec); err != nil {
			return nil, fmt.Errorf("event journal row rejected: %w", err)
		}
		if rec.SchemaVersion != SchemaVersion || rec.Type == "" || rec.Type != kind || !validStatus(rec.CollectionStatus) || rec.Source == "" {
			return nil, errors.New("event journal row failed schema check")
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// Summarize never reports an empty or gapped read as complete.
func Summarize(records []Record) Summary {
	summary := Summary{Count: len(records), Statuses: map[string]int{}, Enforced: false}
	if len(records) == 0 {
		summary.Limitation = "no events; absence is not a clean result"
		return summary
	}
	complete := true
	for _, rec := range records {
		summary.Statuses[rec.CollectionStatus]++
		if rec.CollectionStatus != StatusObserved {
			complete = false
		}
		if enforced, ok := rec.Facts["authorization.enforced"].(bool); ok && enforced {
			summary.Enforced = true
		}
	}
	summary.Complete = complete
	if !complete {
		summary.Limitation = "one or more events are partial, unavailable, or error"
	}
	return summary
}

func validStatus(status string) bool {
	switch status {
	case StatusObserved, StatusPartial, StatusUnavailable, StatusError:
		return true
	default:
		return false
	}
}

func validType(kind string) bool {
	if kind == "" || len(kind) > 64 {
		return false
	}
	for _, r := range kind {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '_' {
			return false
		}
	}
	return true
}
