package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/spf13/cobra"
)

type coverageSensor struct {
	Sensor        string         `json:"sensor"`
	State         string         `json:"state"`
	ObservedAt    string         `json:"observed_at"`
	LastSuccessAt string         `json:"last_success_at,omitempty"`
	Dropped       *int64         `json:"dropped,omitempty"`
	Errors        *int64         `json:"errors,omitempty"`
	Reason        string         `json:"reason,omitempty"`
	Details       map[string]any `json:"details,omitempty"`
}

type coverageReport struct {
	EventID          string           `json:"event_id"`
	GeneratedAt      time.Time        `json:"generated_at"`
	CollectionStatus string           `json:"collection_status"`
	EndpointID       string           `json:"endpoint_id"`
	Platform         string           `json:"platform"`
	DeploymentMode   string           `json:"deployment_mode"`
	Sensors          []coverageSensor `json:"sensors"`
}

func coverageCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "coverage",
		Short: "Show current sensor coverage, blind spots, and collection loss",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()
			client, err := newAdminClient(ctx)
			if err != nil {
				return err
			}
			response, err := client.GetEvents(ctx, &pb.GetEventsRequest{Limit: 1, EventType: "sensor.health"})
			if err != nil {
				return fmt.Errorf("read sensor coverage: %w", err)
			}
			if len(response.Events) == 0 {
				return fmt.Errorf("no sensor coverage event is available; wait for darkd telemetry collection")
			}
			report, err := decodeCoverage(response.Events[0])
			if err != nil {
				return err
			}
			if outputJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(report)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Sensor coverage: endpoint=%s platform=%s mode=%s collected=%s status=%s\n", report.EndpointID, report.Platform, report.DeploymentMode, report.GeneratedAt.Format(time.RFC3339), report.CollectionStatus)
			for _, sensor := range report.Sensors {
				line := fmt.Sprintf("  %-18s %-18s", sensor.Sensor, sensor.State)
				if sensor.Dropped != nil {
					line += fmt.Sprintf(" dropped=%d", *sensor.Dropped)
				}
				if sensor.Errors != nil {
					line += fmt.Sprintf(" errors=%d", *sensor.Errors)
				}
				if sensor.Reason != "" {
					line += " — " + sensor.Reason
				}
				fmt.Fprintln(cmd.OutOrStdout(), line)
			}
			return nil
		},
	}
}

func decodeCoverage(event *pb.Event) (coverageReport, error) {
	if event == nil || event.Type != "sensor.health" {
		return coverageReport{}, fmt.Errorf("coverage response does not contain a sensor.health event")
	}
	if event.Metadata["collection_status"] != "observed" {
		return coverageReport{}, fmt.Errorf("coverage collection is %q; do not treat it as a complete coverage report", event.Metadata["collection_status"])
	}
	var body struct {
		Sensors        []coverageSensor `json:"sensors"`
		Platform       string           `json:"platform"`
		DeploymentMode string           `json:"deployment_mode"`
	}
	if err := json.Unmarshal([]byte(event.Metadata["data"]), &body); err != nil {
		return coverageReport{}, fmt.Errorf("invalid sensor coverage evidence: %w", err)
	}
	if len(body.Sensors) == 0 || body.Platform == "" {
		return coverageReport{}, fmt.Errorf("incomplete sensor coverage evidence")
	}
	for _, sensor := range body.Sensors {
		if sensor.Sensor == "" || sensor.State == "" {
			return coverageReport{}, fmt.Errorf("invalid sensor coverage record")
		}
	}
	sort.Slice(body.Sensors, func(i, j int) bool { return body.Sensors[i].Sensor < body.Sensors[j].Sensor })
	generated := time.Time{}
	if event.Timestamp != nil {
		generated = time.Unix(event.Timestamp.Seconds, int64(event.Timestamp.Nanos)).UTC()
	}
	if generated.IsZero() {
		return coverageReport{}, fmt.Errorf("coverage event has no timestamp")
	}
	return coverageReport{EventID: event.Id, GeneratedAt: generated, CollectionStatus: event.Metadata["collection_status"], EndpointID: event.Metadata["endpoint_id"], Platform: body.Platform, DeploymentMode: body.DeploymentMode, Sensors: body.Sensors}, nil
}
