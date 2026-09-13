package investigation

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

type Condition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	pattern  *regexp.Regexp
}

type Rule struct {
	ID          string      `json:"id"`
	Version     string      `json:"version"`
	Description string      `json:"description"`
	Kind        string      `json:"kind"`
	All         []Condition `json:"all"`
}

type RuleSet struct {
	SHA256        string `json:"-"`
	SchemaVersion int    `json:"schema_version"`
	Rules         []Rule `json:"rules"`
}

type Match struct {
	EventID     string      `json:"event_id"`
	RuleID      string      `json:"rule_id"`
	RuleVersion string      `json:"rule_version"`
	Description string      `json:"description"`
	Evidence    []Condition `json:"evidence"`
}

// LoadRules rejects malformed or unknown constructs instead of silently widening
// a detection. Regexes use Go's bounded-time RE2 implementation.
func LoadRules(r io.Reader) (*RuleSet, error) {
	body, err := io.ReadAll(io.LimitReader(r, 4*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 4*1024*1024 {
		return nil, fmt.Errorf("rule set exceeds 4 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	var rules RuleSet
	if err := d.Decode(&rules); err != nil {
		return nil, err
	}
	rules.SHA256 = fmt.Sprintf("%x", sha256.Sum256(body))
	var extra interface{}
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("rules must contain exactly one JSON object")
	}
	if rules.SchemaVersion != SchemaVersion || len(rules.Rules) == 0 || len(rules.Rules) > 1000 {
		return nil, fmt.Errorf("unsupported rule schema or invalid rule count (1–1000)")
	}
	ids := map[string]bool{}
	for i := range rules.Rules {
		rule := &rules.Rules[i]
		if rule.ID == "" || rule.Version == "" || rule.Kind == "" || len(rule.All) == 0 || len(rule.All) > 32 || ids[rule.ID] {
			return nil, fmt.Errorf("invalid or duplicate rule %q", rule.ID)
		}
		ids[rule.ID] = true
		for j := range rule.All {
			c := &rule.All[j]
			if !knownFields[c.Field] || c.Value == "" || len(c.Value) > 4096 {
				return nil, fmt.Errorf("rule %s: invalid field or value", rule.ID)
			}
			switch c.Operator {
			case "equals", "contains":
			case "regex":
				var err error
				c.pattern, err = regexp.Compile(c.Value)
				if err != nil {
					return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
				}
			default:
				return nil, fmt.Errorf("rule %s: unsupported operator %q", rule.ID, c.Operator)
			}
		}
	}
	return &rules, nil
}

var knownFields = map[string]bool{
	"collection_method": true, "process.pid": true, "process.ppid": true,
	"process.name": true, "process.executable": true, "process.username": true,
	"process.start_time": true, "process.command_line": true, "network.protocol": true,
	"network.local_address": true, "network.local_port": true,
	"network.remote_address": true, "network.remote_port": true, "network.state": true,
}

func (r *RuleSet) Evaluate(e Event) []Match {
	matches := []Match{}
	for _, rule := range r.Rules {
		if rule.Kind != e.Kind {
			continue
		}
		evidence := []Condition{}
		for _, c := range rule.All {
			value, exists := e.Fields[c.Field]
			matched := false
			if exists {
				switch c.Operator {
				case "equals":
					matched = value == c.Value
				case "contains":
					matched = strings.Contains(value, c.Value)
				case "regex":
					matched = c.pattern != nil && c.pattern.MatchString(value)
				}
			}
			if !matched {
				break
			}
			evidence = append(evidence, Condition{Field: c.Field, Operator: c.Operator, Value: value})
		}
		if len(evidence) == len(rule.All) && len(evidence) > 0 {
			matches = append(matches, Match{EventID: e.ID, RuleID: rule.ID, RuleVersion: rule.Version, Description: rule.Description, Evidence: evidence})
		}
	}
	return matches
}
