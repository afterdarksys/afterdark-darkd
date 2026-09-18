package investigation

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	canonical "github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
)

func collect(t *testing.T, s *Store, f Filter) []Event {
	t.Helper()
	events := []Event{}
	if err := s.Walk(context.Background(), f, func(e Event) error { events = append(events, e); return nil }); err != nil {
		t.Fatal(err)
	}
	return events
}

func TestStorePersistenceFilteringRetentionAndAtomicity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "events.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.EndpointID()
	if err != nil || id == "" {
		t.Fatalf("identity: %q %v", id, err)
	}
	now := time.Now().UTC()
	old := newEvent(id, "process_tracker", "process.observed", now.Add(-48*time.Hour))
	a := newEvent(id, "process_tracker", "process.observed", now.Add(-time.Minute))
	a.EntityID = "instance-a"
	b := newEvent(id, "connection_tracker", "network.observed", now)
	b.EntityID = "instance-a"
	if err := s.Append(context.Background(), []Event{b, old, a}, now.Add(-24*time.Hour), 10); err != nil {
		t.Fatal(err)
	}
	events := collect(t, s, Filter{})
	if len(events) != 2 || events[0].ID != a.ID || events[1].ID != b.ID {
		t.Fatalf("order/retention: %+v", events)
	}
	if got := collect(t, s, Filter{EndpointID: id, EntityID: "instance-a", Kind: "network.observed", Since: now, Until: now}); len(got) != 1 {
		t.Fatalf("inclusive filtering: %v", got)
	}
	if got := collect(t, s, Filter{EndpointID: "different"}); len(got) != 0 {
		t.Fatal("endpoint filter leaked")
	}
	c := newEvent(id, "process_tracker", "process.observed", now.Add(time.Second))
	if err := s.Append(context.Background(), []Event{c, {}}, now.Add(-time.Hour), 10); err == nil {
		t.Fatal("invalid event accepted")
	}
	if len(collect(t, s, Filter{})) != 2 {
		t.Fatal("batch was partially committed")
	}
	if err := s.Append(context.Background(), []Event{c}, now.Add(-time.Hour), 2); err != nil {
		t.Fatal(err)
	}
	if got := collect(t, s, Filter{}); len(got) != 2 || got[0].ID != b.ID {
		t.Fatal("row cap failed")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id2, err := s.EndpointID()
	if err != nil || id2 != id {
		t.Fatal("identity changed on reopen")
	}
	if len(collect(t, s, Filter{})) != 2 {
		t.Fatal("evidence not durable")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v", info.Mode())
	}
	missing := filepath.Join(t.TempDir(), "missing.db")
	if reader, err := OpenReader(missing); err == nil {
		reader.Close()
		t.Fatal("reader created missing database")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("reader mutated filesystem")
	}
}

func TestRecorderIdentityPrivacyReplayAndWriteFailure(t *testing.T) {
	root := t.TempDir()
	r := NewRecorder(root, models.InvestigationConfig{Retention: time.Hour, MaxEvents: 100})
	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer r.Stop(ctx)
	if r.Health().Status != service.HealthUnknown {
		t.Fatal("healthy before observation")
	}
	now := time.Now().UTC()
	p := models.Process{PID: 42, PPID: 1, Name: "test-shell", StartTime: now.Add(-time.Minute), CommandLine: "secret-token"}
	parent := models.Process{PID: 1, Name: "parent", StartTime: now.Add(-time.Hour)}
	snap := models.ProcessSnapshot{Timestamp: now, Processes: []models.Process{p, parent}}
	r.ObserveProcesses(snap)
	r.ObserveProcesses(snap)
	r.ObserveConnections([]models.ConnectionEvent{{Timestamp: now, EventType: "new", Connection: models.NetworkConnection{PID: p.PID, ProcessStartTime: p.StartTime, RemotePort: 4444}}})
	events := collect(t, r.store, Filter{})
	if len(events) != 3 {
		t.Fatalf("dedup failed: %d", len(events))
	}
	var proc, conn Event
	for _, e := range events {
		if e.Fields["process.name"] == "test-shell" {
			proc = e
		}
		if e.Kind == "network.observed" {
			conn = e
		}
		if _, ok := e.Fields["process.command_line"]; ok {
			t.Fatal("command line retained without opt-in")
		}
	}
	if proc.EntityID == "" || proc.EntityID != conn.EntityID || proc.ParentEntityID == "" {
		t.Fatal("process/network correlation missing")
	}
	rules, err := LoadRules(strings.NewReader(`{"schema_version":1,"rules":[{"id":"test","version":"1","description":"test port","kind":"network.observed","all":[{"field":"network.remote_port","operator":"equals","value":"4444"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	matches := rules.Evaluate(conn)
	if len(matches) != 1 || matches[0].EventID != conn.ID || matches[0].RuleVersion != "1" || matches[0].Evidence[0].Value != "4444" {
		t.Fatal("replay evidence missing")
	}
	if len(rules.Evaluate(proc)) != 0 {
		t.Fatal("rule matched wrong kind")
	}
	p.StartTime = now // same PID, new process
	snap.Processes = []models.Process{p}
	snap.Timestamp = now.Add(time.Second)
	r.ObserveProcesses(snap)
	if len(collect(t, r.store, Filter{})) != 4 {
		t.Fatal("PID reuse suppressed")
	}
	if r.Health().Status != service.HealthHealthy {
		t.Fatal("recorder not healthy")
	}
	p.Executable = "/new-executable"
	snap.Processes = []models.Process{p}
	r.ObserveProcesses(snap)
	r.ObserveProcesses(snap)
	if len(collect(t, r.store, Filter{})) != 5 {
		t.Fatal("metadata change lost or duplicate snapshot retained")
	}
	if err := r.store.Close(); err != nil {
		t.Fatal(err)
	}
	r.ObserveProcesses(snap)
	if r.Health().Status != service.HealthDegraded || r.failedBatches != 1 {
		t.Fatal("write failure hidden")
	}
}

func TestUnknownProcessIdentityAndParentReuse(t *testing.T) {
	now := time.Now()
	if EntityID("endpoint", 42, time.Time{}) != "" {
		t.Fatal("invented identity for unknown start")
	}
	if EntityID("endpoint", 42, time.UnixMilli(0)) != "" {
		t.Fatal("invented identity for zero OS start time")
	}
	p := models.Process{PID: 42, StartTime: now, CommandLine: "opted-in"}
	e := ProcessEvent("endpoint", p, &models.Process{PID: 1, StartTime: now.Add(time.Second)}, now, true)
	if e.ParentEntityID != "" {
		t.Fatal("linked parent PID to newer process")
	}
	if e.Fields["process.command_line"] != "opted-in" {
		t.Fatal("research opt-in missing")
	}
	if EntityID("other", p.PID, p.StartTime) == e.EntityID {
		t.Fatal("cross-endpoint identity collision")
	}
}

func TestCanonicalEvidenceDecodesForRuleReplay(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	canonicalEvent := canonical.Event{
		SchemaVersion: canonical.SchemaVersion, ID: "canonical", Endpoint: "endpoint-a", Time: now,
		Source: "connection_tracker", Type: "network.connect", CollectionStatus: canonical.CollectionPartial,
		CorrelationID: "endpoint-a:41:1789732800000000000",
		Facts:         map[string]any{"collection_method": "polling", "process.name": "curl", "network.remote_port": 443},
	}
	raw, err := json.Marshal(canonicalEvent)
	if err != nil {
		t.Fatal(err)
	}
	event, err := DecodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if event.SchemaVersion != SchemaVersion || event.EntityID != canonicalEvent.CorrelationID || event.Fields["network.remote_port"] != "443" || event.Fields["collection_status"] != canonical.CollectionPartial {
		t.Fatalf("canonical conversion lost evidence: %+v", event)
	}
	rules, err := LoadRules(strings.NewReader(`{"schema_version":1,"rules":[{"id":"port","version":"1","kind":"network.connect","all":[{"field":"network.remote_port","operator":"equals","value":"443"},{"field":"collection_status","operator":"equals","value":"partial"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if matches := rules.Evaluate(event); len(matches) != 1 || matches[0].EventID != "canonical" {
		t.Fatalf("canonical event did not replay: %+v", matches)
	}
	if _, err := DecodeEvent([]byte(`{"schema_version":3}`)); err == nil {
		t.Fatal("unknown canonical schema accepted")
	}
}

func TestRulesFailClosed(t *testing.T) {
	valid := RuleSet{SchemaVersion: 1, Rules: []Rule{{ID: "r", Version: "1", Kind: "process.observed", All: []Condition{{Field: "process.name", Operator: "regex", Value: "^test"}}}}}
	for _, change := range []func(*RuleSet){
		func(r *RuleSet) { r.SchemaVersion = 2 },
		func(r *RuleSet) { r.Rules[0].All = nil },
		func(r *RuleSet) { r.Rules[0].All[0].Field = "typo" },
		func(r *RuleSet) { r.Rules[0].All[0].Operator = "execute" },
		func(r *RuleSet) { r.Rules[0].All[0].Value = "[" },
		func(r *RuleSet) { r.Rules = append(r.Rules, r.Rules[0]) },
	} {
		body, _ := json.Marshal(valid)
		var candidate RuleSet
		json.Unmarshal(body, &candidate)
		change(&candidate)
		body, _ = json.Marshal(candidate)
		if _, err := LoadRules(strings.NewReader(string(body))); err == nil {
			t.Fatalf("accepted invalid rules: %s", body)
		}
	}
	body, _ := json.Marshal(valid)
	rules, err := LoadRules(strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	e := newEvent("ep", "process_tracker", "process.observed", time.Now())
	e.Fields["process.name"] = "test-shell"
	if len(rules.Evaluate(e)) != 1 {
		t.Fatal("regex did not match")
	}
	delete(e.Fields, "process.name")
	if len(rules.Evaluate(e)) != 0 {
		t.Fatal("missing field matched")
	}
	if _, err := LoadRules(strings.NewReader(string(body) + ` {}`)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	if _, err := LoadRules(strings.NewReader(`{"schema_version":1,"unknown":true}`)); err == nil {
		t.Fatal("unknown fields accepted")
	}
}

func TestVersionedSequenceRulesLoadAndReplay(t *testing.T) {
	rules, err := LoadRules(strings.NewReader(`{"schema_version":1,"sequences":[{"id":"chain","version":"1","within_seconds":60,"steps":[{"kind":"process.observed","all":[{"field":"process.name","operator":"equals","value":"curl"}]},{"kind":"network.connect","all":[{"field":"network.remote_port","operator":"equals","value":"443"}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	matches, err := rules.EvaluateSequences([]Event{{ID: "p", EntityID: "instance", Timestamp: now, Kind: "process.observed", Fields: map[string]string{"process.name": "curl"}}, {ID: "n", EntityID: "instance", Timestamp: now.Add(time.Second), Kind: "network.connect", Fields: map[string]string{"network.remote_port": "443"}}})
	if err != nil || len(matches) != 1 || matches[0].RuleID != "chain" {
		t.Fatalf("sequence replay failed: %#v (%v)", matches, err)
	}
	if _, err := LoadRules(strings.NewReader(`{"schema_version":1,"sequences":[{"id":"bad","version":"1","within_seconds":0,"steps":[]}]}`)); err == nil {
		t.Fatal("invalid sequence accepted")
	}
}

func TestBehavioralRuleExampleLoads(t *testing.T) {
	f, err := os.Open("../../configs/behavioral-rules.example.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rules, err := LoadRules(f)
	if err != nil || len(rules.Rules) != 1 || len(rules.Sequences) != 1 {
		t.Fatalf("example rule pack is invalid: %#v (%v)", rules, err)
	}
}
