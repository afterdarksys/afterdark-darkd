// Package investigation records polling observations for investigation and rule replay.
package investigation

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	canonical "github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/google/uuid"
)

const SchemaVersion = 1

// Event timestamps describe when a sensor observed something, not an inferred
// execution/termination time. EntityID is absent when process start time is unknown.
type Event struct {
	SchemaVersion  int               `json:"schema_version"`
	ID             string            `json:"id"`
	EndpointID     string            `json:"endpoint_id"`
	Timestamp      time.Time         `json:"timestamp"`
	Source         string            `json:"source"`
	Kind           string            `json:"kind"`
	EntityID       string            `json:"entity_id,omitempty"`
	ParentEntityID string            `json:"parent_entity_id,omitempty"`
	Fields         map[string]string `json:"fields"`
}

func EntityID(endpoint string, pid int32, started time.Time) string {
	if pid <= 0 || started.IsZero() || started.UnixMilli() <= 0 {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s/%d/%d", endpoint, pid, started.UnixMilli()))))
}

func newEvent(endpoint, source, kind string, at time.Time) Event {
	return Event{SchemaVersion: SchemaVersion, ID: uuid.NewString(), EndpointID: endpoint,
		Timestamp: at.UTC(), Source: source, Kind: kind, Fields: map[string]string{"collection_method": "polling"}}
}

func ProcessEvent(endpoint string, p models.Process, parent *models.Process, at time.Time, commandLine bool) Event {
	e := newEvent(endpoint, "process_tracker", "process.observed", at)
	e.EntityID = EntityID(endpoint, p.PID, p.StartTime)
	if parent != nil && !p.StartTime.IsZero() && !parent.StartTime.After(p.StartTime) {
		e.ParentEntityID = EntityID(endpoint, parent.PID, parent.StartTime)
	}
	e.Fields["process.pid"] = fmt.Sprint(p.PID)
	e.Fields["process.ppid"] = fmt.Sprint(p.PPID)
	e.Fields["process.name"] = p.Name
	e.Fields["process.executable"] = p.Executable
	e.Fields["process.username"] = p.Username
	if !p.StartTime.IsZero() {
		e.Fields["process.start_time"] = p.StartTime.UTC().Format(time.RFC3339Nano)
	}
	if commandLine {
		e.Fields["process.command_line"] = p.CommandLine
	}
	return e
}

func ConnectionEvent(endpoint string, c models.ConnectionEvent) Event {
	kind := "network.observed"
	if c.EventType == "closed" {
		kind = "network.disappeared"
	}
	e := newEvent(endpoint, "connection_tracker", kind, c.Timestamp)
	e.EntityID = EntityID(endpoint, c.Connection.PID, c.Connection.ProcessStartTime)
	e.Fields["process.pid"] = fmt.Sprint(c.Connection.PID)
	e.Fields["process.name"] = c.Connection.ProcessName
	e.Fields["network.protocol"] = c.Connection.Protocol
	e.Fields["network.local_address"] = c.Connection.LocalAddr
	e.Fields["network.local_port"] = fmt.Sprint(c.Connection.LocalPort)
	e.Fields["network.remote_address"] = c.Connection.RemoteAddr
	e.Fields["network.remote_port"] = fmt.Sprint(c.Connection.RemotePort)
	e.Fields["network.state"] = c.Connection.State
	return e
}

func (e Event) Validate() error {
	if e.SchemaVersion != SchemaVersion || e.ID == "" || e.EndpointID == "" || e.Timestamp.IsZero() || e.Source == "" || e.Kind == "" {
		return fmt.Errorf("invalid event envelope or unsupported schema version")
	}
	return nil
}

// FromCanonical translates the durable v2 endpoint envelope into the replay
// model retained for compatibility with the original investigation database.
// CorrelationID is intentionally preferred over PID: it only exists when the
// source could establish a process instance using endpoint, PID, and start time.
func FromCanonical(e canonical.Event) (Event, error) {
	if e.SchemaVersion != canonical.SchemaVersion || e.ID == "" || e.Endpoint == "" || e.Time.IsZero() || e.Source == "" || e.Type == "" {
		return Event{}, fmt.Errorf("invalid canonical event envelope")
	}
	fields := make(map[string]string, len(e.Facts)+1)
	for key, value := range e.Facts {
		formatted, err := factString(value)
		if err != nil {
			return Event{}, fmt.Errorf("canonical fact %q: %w", key, err)
		}
		fields[key] = formatted
	}
	if e.CollectionStatus != "" {
		fields["collection_status"] = e.CollectionStatus
	}
	return Event{
		SchemaVersion: SchemaVersion,
		ID:            e.ID,
		EndpointID:    e.Endpoint,
		Timestamp:     e.Time.UTC(),
		Source:        e.Source,
		Kind:          e.Type,
		EntityID:      e.CorrelationID,
		Fields:        fields,
	}, nil
}

// DecodeEvent accepts both legacy investigation evidence (schema v1) and the
// canonical daemon envelope (schema v2). This lets existing rule packs replay
// against new telemetry while older case bundles remain readable.
func DecodeEvent(raw []byte) (Event, error) {
	var header struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return Event{}, err
	}
	switch header.SchemaVersion {
	case SchemaVersion:
		var event Event
		if err := json.Unmarshal(raw, &event); err != nil {
			return Event{}, err
		}
		if err := event.Validate(); err != nil {
			return Event{}, err
		}
		return event, nil
	case canonical.SchemaVersion:
		var event canonical.Event
		if err := json.Unmarshal(raw, &event); err != nil {
			return Event{}, err
		}
		return FromCanonical(event)
	default:
		return Event{}, fmt.Errorf("unsupported evidence schema version %d", header.SchemaVersion)
	}
}

func factString(value any) (string, error) {
	switch value := value.(type) {
	case nil:
		return "", nil
	case string:
		return value, nil
	case bool, float64, float32, int, int32, int64, uint, uint32, uint64, json.Number:
		return fmt.Sprint(value), nil
	default:
		encoded, err := json.Marshal(value)
		return string(encoded), err
	}
}
