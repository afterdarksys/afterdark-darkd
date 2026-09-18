package main

import (
	"testing"
	"time"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
)

func TestDecodeCoveragePreservesBlindSpotsAndSortsSensors(t *testing.T) {
	event := &pb.Event{Id: "coverage", Type: "sensor.health", Timestamp: &pb.Timestamp{Seconds: 1789732800}, Metadata: map[string]string{
		"endpoint_id": "endpoint-a", "collection_status": "observed",
		"data": `{"platform":"linux","deployment_mode":"dogfood","sensors":[{"sensor":"telemetry","state":"running"},{"sensor":"ebpf","state":"permission_denied","reason":"requires CAP_BPF"}]}`,
	}}
	report, err := decodeCoverage(event)
	if err != nil {
		t.Fatal(err)
	}
	if report.GeneratedAt.IsZero() || report.GeneratedAt.Location() != time.UTC || report.Platform != "linux" || report.Sensors[0].Sensor != "ebpf" || report.Sensors[0].State != "permission_denied" {
		t.Fatalf("coverage evidence lost: %+v", report)
	}
}

func TestDecodeCoverageRejectsIncompleteEvidence(t *testing.T) {
	for _, event := range []*pb.Event{
		{Type: "process.observed", Metadata: map[string]string{}},
		{Type: "sensor.health", Metadata: map[string]string{"collection_status": "partial", "data": `{}`}},
		{Type: "sensor.health", Metadata: map[string]string{"collection_status": "observed", "data": `{"platform":"linux","sensors":[]}`}},
	} {
		if _, err := decodeCoverage(event); err == nil {
			t.Fatalf("incomplete evidence accepted: %#v", event)
		}
	}
}
