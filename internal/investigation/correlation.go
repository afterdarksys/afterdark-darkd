package investigation

import (
	"fmt"
	"sort"
	"time"
)

// SequenceRule describes an ordered behavioral hypothesis. It is intentionally
// separate from a single-event Rule: a sequence can only link events that share
// a stable EntityID, never a reused PID or a guessed process relationship.
type SequenceRule struct {
	ID          string
	Version     string
	Description string
	Within      time.Duration
	Steps       []Rule
}

type SequenceMatch struct {
	RuleID      string    `json:"rule_id"`
	RuleVersion string    `json:"rule_version"`
	Description string    `json:"description,omitempty"`
	EntityID    string    `json:"entity_id"`
	EventIDs    []string  `json:"event_ids"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
}

// EvaluateSequence finds ordered matches within a single stable entity. Events
// without an EntityID are excluded: correlation must fail closed when process
// identity is unavailable. The input is copied before sorting.
func (r SequenceRule) EvaluateSequence(events []Event) ([]SequenceMatch, error) {
	if r.ID == "" || r.Version == "" || r.Within <= 0 || len(r.Steps) < 2 || len(r.Steps) > 8 {
		return nil, fmt.Errorf("invalid sequence rule")
	}
	for _, step := range r.Steps {
		if step.Kind == "" || len(step.All) == 0 {
			return nil, fmt.Errorf("sequence rule %q has invalid step", r.ID)
		}
	}
	ordered := append([]Event(nil), events...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Timestamp.Before(ordered[j].Timestamp) })
	byEntity := map[string][]Event{}
	for _, event := range ordered {
		if event.EntityID != "" {
			byEntity[event.EntityID] = append(byEntity[event.EntityID], event)
		}
	}
	matches := []SequenceMatch{}
	for entity, timeline := range byEntity {
		for start := range timeline {
			if !stepMatches(r.Steps[0], timeline[start]) {
				continue
			}
			selected := []Event{timeline[start]}
			next := 1
			for index := start + 1; index < len(timeline) && next < len(r.Steps); index++ {
				candidate := timeline[index]
				if candidate.Timestamp.Sub(selected[0].Timestamp) > r.Within {
					break
				}
				if stepMatches(r.Steps[next], candidate) {
					selected = append(selected, candidate)
					next++
				}
			}
			if next != len(r.Steps) {
				continue
			}
			ids := make([]string, len(selected))
			for i, event := range selected {
				ids[i] = event.ID
			}
			matches = append(matches, SequenceMatch{RuleID: r.ID, RuleVersion: r.Version, Description: r.Description, EntityID: entity, EventIDs: ids, StartedAt: selected[0].Timestamp, FinishedAt: selected[len(selected)-1].Timestamp})
		}
	}
	return matches, nil
}

func stepMatches(rule Rule, event Event) bool {
	if rule.Kind != event.Kind {
		return false
	}
	for _, condition := range rule.All {
		value, exists := event.Fields[condition.Field]
		if !exists {
			return false
		}
		switch condition.Operator {
		case "equals":
			if value != condition.Value {
				return false
			}
		case "contains":
			if !contains(value, condition.Value) {
				return false
			}
		case "regex":
			if condition.pattern == nil || !condition.pattern.MatchString(value) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func contains(value, expected string) bool {
	for index := 0; index+len(expected) <= len(value); index++ {
		if value[index:index+len(expected)] == expected {
			return true
		}
	}
	return expected == ""
}
