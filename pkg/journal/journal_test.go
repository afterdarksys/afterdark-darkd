package journal

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestRejectsMissingSymlinkAndDirtyRows(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("empty path accepted")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing.sqlite")); err == nil {
		t.Fatal("missing journal accepted")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "events.sqlite")
	if err := os.WriteFile(target, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.sqlite")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("symlink accepted")
	}

	db := seed(t, filepath.Join(dir, "good.sqlite"))
	insert(t, db, "ok", "file.write", `{"schema_version":2,"collection_status":"observed","id":"ok","endpoint_id":"ep","sequence":1,"time":"2026-09-25T00:00:00Z","source":"esf_monitor","type":"file.write","severity":"info"}`)
	insert(t, db, "gap", "dns.capture", `{"schema_version":2,"collection_status":"unavailable","id":"gap","endpoint_id":"ep","sequence":2,"time":"2026-09-25T00:00:01Z","source":"dns_tunnel_detection","type":"dns.capture","severity":"info"}`)
	db.Close()

	reader, err := Open(filepath.Join(dir, "good.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	rows, err := reader.List(context.Background(), Query{Types: []string{"file.write", "dns.capture"}, Limit: 10})
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	summary := Summarize(rows)
	if summary.Complete || summary.Enforced || summary.Statuses["unavailable"] != 1 || summary.Limitation == "" {
		t.Fatalf("gapped journal looked complete: %+v", summary)
	}
	if _, err = reader.List(context.Background(), Query{Limit: 1001}); err == nil {
		t.Fatal("oversized limit accepted")
	}
	if _, err = reader.List(context.Background(), Query{Types: []string{"file.write;drop"}, Limit: 1}); err == nil {
		t.Fatal("type injection accepted")
	}

	empty, err := Open(seedEmpty(t))
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	none, err := empty.List(context.Background(), Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if sum := Summarize(none); sum.Complete || !strings.Contains(sum.Limitation, "absence") {
		t.Fatalf("empty journal looked clean: %+v", sum)
	}
}

func TestRejectsTamperedSchemaAndOversizedPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.sqlite")
	db := seed(t, path)
	insert(t, db, "old", "process.observed", `{"schema_version":1,"collection_status":"observed","id":"old","source":"process_tracker","type":"process.observed"}`)
	db.Close()
	reader, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err = reader.List(context.Background(), Query{Limit: 5}); err == nil {
		t.Fatal("wrong schema accepted")
	}

	path = filepath.Join(t.TempDir(), "big.sqlite")
	db = seed(t, path)
	insert(t, db, "big", "file.write", `{"schema_version":2,"collection_status":"observed","source":"esf_monitor","type":"file.write","data":"`+strings.Repeat("a", MaxPayload)+`"}`)
	db.Close()
	reader, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err = reader.List(context.Background(), Query{Limit: 5}); err == nil {
		t.Fatal("oversized payload accepted")
	}

	path = filepath.Join(t.TempDir(), "bad.sqlite")
	db = seed(t, path)
	insert(t, db, "bad", "file.write", `{`)
	db.Close()
	reader, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err = reader.List(context.Background(), Query{Limit: 5, Since: time.Unix(0, 0)}); err == nil {
		t.Fatal("truncated json accepted")
	}
}

func seed(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,time INTEGER NOT NULL,kind TEXT NOT NULL,severity TEXT NOT NULL,payload BLOB NOT NULL,delivered INTEGER NOT NULL DEFAULT 0)`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func seedEmpty(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "empty.sqlite")
	db := seed(t, path)
	db.Close()
	return path
}

func insert(t *testing.T, db *sql.DB, id, kind, payload string) {
	t.Helper()
	_, err := db.Exec("INSERT INTO events(id,time,kind,severity,payload) VALUES(?,?,?,?,?)", id, time.Now().UnixNano(), kind, "info", payload)
	if err != nil {
		t.Fatal(err)
	}
}
