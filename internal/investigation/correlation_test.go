package investigation

import (
	"testing"
	"time"
)

func TestSequenceRuleCorrelatesOnlyStableProcessInstances(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	rule := SequenceRule{ID: "persistence-to-network", Version: "1", Within: 5 * time.Minute, Steps: []Rule{
		{Kind: "persistence.observed", All: []Condition{{Field: "persistence.path", Operator: "contains", Value: "LaunchAgents"}}},
		{Kind: "network.connect", All: []Condition{{Field: "network.remote_port", Operator: "equals", Value: "443"}}},
	}}
	events := []Event{
		{ID: "network-other", EntityID: "other", Timestamp: now.Add(time.Minute), Kind: "network.connect", Fields: map[string]string{"network.remote_port": "443"}},
		{ID: "persist", EntityID: "process-a", Timestamp: now, Kind: "persistence.observed", Fields: map[string]string{"persistence.path": "/Library/LaunchAgents/x.plist"}},
		{ID: "network", EntityID: "process-a", Timestamp: now.Add(2 * time.Minute), Kind: "network.connect", Fields: map[string]string{"network.remote_port": "443"}},
		{ID: "unknown", Timestamp: now.Add(3 * time.Minute), Kind: "network.connect", Fields: map[string]string{"network.remote_port": "443"}},
	}
	matches, err := rule.EvaluateSequence(events)
	if err != nil || len(matches) != 1 || matches[0].EntityID != "process-a" || len(matches[0].EventIDs) != 2 || matches[0].EventIDs[1] != "network" {
		t.Fatalf("unsafe or missing correlation: %#v (%v)", matches, err)
	}
}

func TestSequenceRuleRejectsOutOfWindowAndInvalidRules(t *testing.T) {
	now := time.Now().UTC()
	rule := SequenceRule{ID: "r", Version: "1", Within: time.Minute, Steps: []Rule{{Kind: "a", All: []Condition{{Field: "x", Operator: "equals", Value: "1"}}}, {Kind: "b", All: []Condition{{Field: "y", Operator: "equals", Value: "2"}}}}}
	events := []Event{{ID: "a", EntityID: "entity", Timestamp: now, Kind: "a", Fields: map[string]string{"x": "1"}}, {ID: "b", EntityID: "entity", Timestamp: now.Add(2 * time.Minute), Kind: "b", Fields: map[string]string{"y": "2"}}}
	if matches, err := rule.EvaluateSequence(events); err != nil || len(matches) != 0 {
		t.Fatalf("out-of-window match: %#v (%v)", matches, err)
	}
	if _, err := (SequenceRule{}).EvaluateSequence(events); err == nil {
		t.Fatal("invalid sequence rule accepted")
	}
}
