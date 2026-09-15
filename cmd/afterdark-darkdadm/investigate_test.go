package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/investigation"
)

func runInvestigation(args ...string) (string, error) {
	c := investigateCmd()
	var output bytes.Buffer
	c.SetOut(&output)
	c.SetErr(&output)
	c.SetArgs(args)
	c.SilenceUsage = true
	c.SilenceErrors = true
	err := c.Execute()
	return output.String(), err
}

func TestInvestigationExportReplayWorkflow(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "events.db")
	s, err := investigation.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	events := []investigation.Event{
		{SchemaVersion: 1, ID: "one", EndpointID: "ep", Timestamp: now, Source: "process_tracker", Kind: "process.observed", Fields: map[string]string{"process.name": "test-shell"}},
		{SchemaVersion: 1, ID: "two", EndpointID: "ep", Timestamp: now.Add(time.Second), Source: "process_tracker", Kind: "process.observed", Fields: map[string]string{"process.name": "normal"}},
	}
	if err := s.Append(context.Background(), events, now.Add(-time.Hour), 100); err != nil {
		t.Fatal(err)
	}
	s.Close()
	rules := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rules, []byte(`{"schema_version":1,"rules":[{"id":"shell","version":"1.0","kind":"process.observed","all":[{"field":"process.name","operator":"contains","value":"test-"}]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	exported, err := runInvestigation("--db", db, "export")
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "evidence.ndjson")
	if err := os.WriteFile(input, []byte(exported), 0600); err != nil {
		t.Fatal(err)
	}
	live, err := runInvestigation("--db", db, "replay", "--rules", rules)
	if err != nil {
		t.Fatal(err)
	}
	offline, err := runInvestigation("replay", "--rules", rules, "--input", input)
	if err != nil {
		t.Fatal(err)
	}
	if live != offline {
		t.Fatalf("database/export replay differ: %s / %s", live, offline)
	}
	lines := strings.Split(strings.TrimSpace(live), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected match and summary: %s", live)
	}
	var summary struct {
		Scanned int `json:"events_scanned"`
		Matched int `json:"events_matched"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Scanned != 2 || summary.Matched != 1 {
		t.Fatalf("bad summary: %s", live)
	}
	filtered, err := runInvestigation("--db", db, "--since", now.Add(time.Second).Format(time.RFC3339Nano), "export")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(filtered, `"one"`) || !strings.Contains(filtered, `"two"`) {
		t.Fatalf("filter failed: %s", filtered)
	}
	if _, err := runInvestigation("--db", db, "--limit", "-1", "export"); err == nil {
		t.Fatal("negative limit accepted")
	}
	if _, err := runInvestigation("--db", db, "--since", "yesterday", "export"); err == nil {
		t.Fatal("bad timestamp accepted")
	}
	if err := os.WriteFile(input, []byte(exported+"broken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	partial, err := runInvestigation("replay", "--rules", rules, "--input", input)
	if err == nil || strings.Contains(partial, `"type":"summary"`) {
		t.Fatal("malformed evidence reported completed replay")
	}
}
