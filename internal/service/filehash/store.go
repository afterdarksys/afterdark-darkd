package filehash

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// LocalStore provides local SQLite storage for file hashes
type LocalStore struct {
	db *sql.DB
}

// NewLocalStore creates a new local store
func NewLocalStore(dbPath string) (*LocalStore, error) {
	// Create directory if needed
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Create tables
	if err := createTables(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("create tables: %w", err)
	}

	return &LocalStore{db: db}, nil
}

func createTables(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS file_hashes (
			path TEXT PRIMARY KEY,
			filename TEXT NOT NULL,
			size INTEGER,
			mod_time INTEGER,
			sha256 TEXT NOT NULL,
			sha1 TEXT,
			md5 TEXT,
			first_seen INTEGER,
			last_seen INTEGER,
			synced INTEGER DEFAULT 0
		);

		CREATE INDEX IF NOT EXISTS idx_sha256 ON file_hashes(sha256);
		CREATE INDEX IF NOT EXISTS idx_synced ON file_hashes(synced);

		CREATE TABLE IF NOT EXISTS file_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			path TEXT NOT NULL,
			event_type TEXT NOT NULL,
			old_sha256 TEXT,
			new_sha256 TEXT,
			detected_at INTEGER
		);

		CREATE INDEX IF NOT EXISTS idx_events_path ON file_events(path);
		CREATE INDEX IF NOT EXISTS idx_events_time ON file_events(detected_at);
	`)
	return err
}

// Close closes the database connection
func (s *LocalStore) Close() error {
	return s.db.Close()
}

// Save saves or updates a file record
func (s *LocalStore) Save(record *FileRecord) error {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO file_hashes
		(path, filename, size, mod_time, sha256, sha1, md5, first_seen, last_seen, synced)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		record.Path,
		record.Filename,
		record.Size,
		record.ModTime.Unix(),
		record.SHA256,
		record.SHA1,
		record.MD5,
		record.FirstSeen.Unix(),
		record.LastSeen.Unix(),
		boolToInt(record.Synced),
	)
	return err
}

// Load loads a file record by path
func (s *LocalStore) Load(path string) (*FileRecord, error) {
	row := s.db.QueryRow(`
		SELECT path, filename, size, mod_time, sha256, sha1, md5, first_seen, last_seen, synced
		FROM file_hashes WHERE path = ?
	`, path)

	return scanRecord(row)
}

// LoadAll loads all file records
func (s *LocalStore) LoadAll() ([]*FileRecord, error) {
	rows, err := s.db.Query(`
		SELECT path, filename, size, mod_time, sha256, sha1, md5, first_seen, last_seen, synced
		FROM file_hashes
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*FileRecord
	for rows.Next() {
		record, err := scanRecordFromRows(rows)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, rows.Err()
}

// LoadUnsynced loads all unsynced records
func (s *LocalStore) LoadUnsynced() ([]*FileRecord, error) {
	rows, err := s.db.Query(`
		SELECT path, filename, size, mod_time, sha256, sha1, md5, first_seen, last_seen, synced
		FROM file_hashes WHERE synced = 0
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*FileRecord
	for rows.Next() {
		record, err := scanRecordFromRows(rows)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, rows.Err()
}

// Delete deletes a file record
func (s *LocalStore) Delete(path string) error {
	_, err := s.db.Exec(`DELETE FROM file_hashes WHERE path = ?`, path)
	return err
}

// RecordEvent records a file change event
func (s *LocalStore) RecordEvent(path, eventType, oldSHA256, newSHA256 string) error {
	_, err := s.db.Exec(`
		INSERT INTO file_events (path, event_type, old_sha256, new_sha256, detected_at)
		VALUES (?, ?, ?, ?, ?)
	`, path, eventType, oldSHA256, newSHA256, time.Now().Unix())
	return err
}

// GetRecentEvents returns recent file events
func (s *LocalStore) GetRecentEvents(limit int) ([]FileEvent, error) {
	rows, err := s.db.Query(`
		SELECT id, path, event_type, old_sha256, new_sha256, detected_at
		FROM file_events
		ORDER BY detected_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []FileEvent
	for rows.Next() {
		var e FileEvent
		var detectedAt int64
		err := rows.Scan(&e.ID, &e.Path, &e.EventType, &e.OldSHA256, &e.NewSHA256, &detectedAt)
		if err != nil {
			continue
		}
		e.DetectedAt = time.Unix(detectedAt, 0)
		events = append(events, e)
	}

	return events, rows.Err()
}

// Stats returns database statistics
func (s *LocalStore) Stats() (*StoreStats, error) {
	var stats StoreStats

	row := s.db.QueryRow(`SELECT COUNT(*) FROM file_hashes`)
	row.Scan(&stats.TotalFiles)

	row = s.db.QueryRow(`SELECT COUNT(*) FROM file_hashes WHERE synced = 0`)
	row.Scan(&stats.UnsyncedFiles)

	row = s.db.QueryRow(`SELECT COUNT(*) FROM file_events`)
	row.Scan(&stats.TotalEvents)

	return &stats, nil
}

// FileEvent represents a file change event
type FileEvent struct {
	ID         int64
	Path       string
	EventType  string
	OldSHA256  string
	NewSHA256  string
	DetectedAt time.Time
}

// StoreStats contains database statistics
type StoreStats struct {
	TotalFiles    int64
	UnsyncedFiles int64
	TotalEvents   int64
}

func scanRecord(row *sql.Row) (*FileRecord, error) {
	var r FileRecord
	var modTime, firstSeen, lastSeen int64
	var synced int

	err := row.Scan(
		&r.Path, &r.Filename, &r.Size, &modTime,
		&r.SHA256, &r.SHA1, &r.MD5,
		&firstSeen, &lastSeen, &synced,
	)
	if err != nil {
		return nil, err
	}

	r.ModTime = time.Unix(modTime, 0)
	r.FirstSeen = time.Unix(firstSeen, 0)
	r.LastSeen = time.Unix(lastSeen, 0)
	r.Synced = synced == 1

	return &r, nil
}

func scanRecordFromRows(rows *sql.Rows) (*FileRecord, error) {
	var r FileRecord
	var modTime, firstSeen, lastSeen int64
	var synced int

	err := rows.Scan(
		&r.Path, &r.Filename, &r.Size, &modTime,
		&r.SHA256, &r.SHA1, &r.MD5,
		&firstSeen, &lastSeen, &synced,
	)
	if err != nil {
		return nil, err
	}

	r.ModTime = time.Unix(modTime, 0)
	r.FirstSeen = time.Unix(firstSeen, 0)
	r.LastSeen = time.Unix(lastSeen, 0)
	r.Synced = synced == 1

	return &r, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
