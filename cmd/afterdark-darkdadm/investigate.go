package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/investigation"
	"github.com/spf13/cobra"
)

func investigateCmd() *cobra.Command {
	var dbPath, endpoint, entity, kind, since, until string
	var limit int
	cmd := &cobra.Command{Use: "investigate", Short: "Query local evidence and replay detection rules (requires database file access)"}
	cmd.PersistentFlags().StringVar(&dbPath, "db", "/var/lib/afterdark/investigation/events.db", "local evidence database")
	cmd.PersistentFlags().StringVar(&endpoint, "endpoint", "", "filter endpoint ID")
	cmd.PersistentFlags().StringVar(&entity, "entity", "", "filter process entity ID")
	cmd.PersistentFlags().StringVar(&kind, "kind", "", "filter event kind")
	cmd.PersistentFlags().StringVar(&since, "since", "", "inclusive start time (RFC3339)")
	cmd.PersistentFlags().StringVar(&until, "until", "", "inclusive end time (RFC3339)")
	cmd.PersistentFlags().IntVar(&limit, "limit", 0, "maximum events; 0 includes all matching events")
	filter := func() (investigation.Filter, error) {
		f := investigation.Filter{EndpointID: endpoint, EntityID: entity, Kind: kind, Limit: limit}
		var err error
		if since != "" {
			f.Since, err = time.Parse(time.RFC3339Nano, since)
			if err != nil {
				return f, fmt.Errorf("since: %w", err)
			}
		}
		if until != "" {
			f.Until, err = time.Parse(time.RFC3339Nano, until)
			if err != nil {
				return f, fmt.Errorf("until: %w", err)
			}
		}
		if limit < 0 || (!f.Since.IsZero() && !f.Until.IsZero() && f.Since.After(f.Until)) {
			return f, fmt.Errorf("invalid range or limit")
		}
		return f, nil
	}
	walk := func(c *cobra.Command, visit func(investigation.Event) error) error {
		f, err := filter()
		if err != nil {
			return err
		}
		s, err := investigation.OpenReader(dbPath)
		if err != nil {
			return err
		}
		defer s.Close()
		return s.Walk(c.Context(), f, visit)
	}
	cmd.AddCommand(&cobra.Command{Use: "timeline", Short: "Show observations in chronological order", Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			enc := json.NewEncoder(c.OutOrStdout())
			return walk(c, func(e investigation.Event) error {
				if outputJSON {
					return enc.Encode(e)
				}
				_, err := fmt.Fprintf(c.OutOrStdout(), "%s  %s  endpoint=%s  entity=%s  process=%q  remote=%s:%s\n", e.Timestamp.Format(time.RFC3339Nano), e.Kind, e.EndpointID, e.EntityID, e.Fields["process.name"], e.Fields["network.remote_address"], e.Fields["network.remote_port"])
				return err
			})
		}})
	cmd.AddCommand(&cobra.Command{Use: "export", Short: "Stream matching evidence as NDJSON to stdout", Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			enc := json.NewEncoder(c.OutOrStdout())
			return walk(c, func(e investigation.Event) error { return enc.Encode(e) })
		}})
	var rulesPath, input string
	replay := &cobra.Command{Use: "replay", Short: "Evaluate versioned rules without executing response actions", Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			f, err := filter()
			if err != nil {
				return err
			}
			rf, err := os.Open(rulesPath)
			if err != nil {
				return err
			}
			rules, err := investigation.LoadRules(rf)
			rf.Close()
			if err != nil {
				return err
			}
			enc := json.NewEncoder(c.OutOrStdout())
			counts := map[string]int{}
			for _, rule := range rules.Rules {
				counts[rule.ID] = 0
			}
			scanned, matched := 0, 0
			visit := func(e investigation.Event) error {
				if err := c.Context().Err(); err != nil {
					return err
				}
				scanned++
				matches := rules.Evaluate(e)
				if len(matches) > 0 {
					matched++
				}
				for _, match := range matches {
					counts[match.RuleID]++
					if err := enc.Encode(struct {
						Type  string              `json:"type"`
						Match investigation.Match `json:"match"`
					}{"match", match}); err != nil {
						return err
					}
				}
				return nil
			}
			if input == "" {
				err = walk(c, visit)
			} else {
				var in *os.File
				in, err = os.Open(input)
				if err != nil {
					return err
				}
				defer in.Close()
				scanner := bufio.NewScanner(in)
				scanner.Buffer(make([]byte, 64*1024), 1024*1024)
				line := 0
				for scanner.Scan() {
					line++
					var e investigation.Event
					if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
						return fmt.Errorf("evidence line %d: %w", line, err)
					}
					if err := e.Validate(); err != nil {
						return fmt.Errorf("evidence line %d: %w", line, err)
					}
					if (f.EndpointID != "" && e.EndpointID != f.EndpointID) || (f.EntityID != "" && e.EntityID != f.EntityID) || (f.Kind != "" && e.Kind != f.Kind) || (!f.Since.IsZero() && e.Timestamp.Before(f.Since)) || (!f.Until.IsZero() && e.Timestamp.After(f.Until)) {
						continue
					}
					if err := visit(e); err != nil {
						return err
					}
					if f.Limit > 0 && scanned >= f.Limit {
						break
					}
				}
				err = scanner.Err()
			}
			if err != nil {
				return err
			}
			return enc.Encode(struct {
				Type        string         `json:"type"`
				RulesSHA256 string         `json:"rules_sha256"`
				Scanned     int            `json:"events_scanned"`
				Matched     int            `json:"events_matched"`
				Counts      map[string]int `json:"matches_by_rule"`
			}{"summary", rules.SHA256, scanned, matched, counts})
		}}
	replay.Flags().StringVar(&rulesPath, "rules", "", "versioned JSON rule set (required)")
	replay.Flags().StringVar(&input, "input", "", "replay an exported NDJSON file instead of the database")
	_ = replay.MarkFlagRequired("rules")
	cmd.AddCommand(replay)
	return cmd
}
