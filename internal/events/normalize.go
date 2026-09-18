package events

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
)

// normalize adds a small, stable query surface for the event types that power
// endpoint correlation. Data remains the complete source payload so existing
// SIEM consumers and forensic workflows retain their original evidence.
//
// Facts deliberately exclude process command lines. They can contain secrets
// and are already governed by the source collector's explicit configuration.
func normalize(source string, data interface{}) (map[string]any, map[string]any, string) {
	var entities, facts map[string]any
	status := ""
	switch value := data.(type) {
	case models.Process:
		entities, facts = processFields(value)
	case *models.Process:
		if value != nil {
			entities, facts = processFields(*value)
		}
	case models.NetworkConnection:
		entities, facts = connectionFields(value)
	case *models.NetworkConnection:
		if value != nil {
			entities, facts = connectionFields(*value)
		}
	case map[string]interface{}:
		entities, facts, status = mapFields(value)
	}
	if facts == nil {
		facts = map[string]any{}
	}
	// Collection method is a fact about the observation, rather than a claim
	// about an entity. This lets detections distinguish polling from native
	// event streams without parsing source-specific payloads.
	switch source {
	case "process_tracker", "connection_tracker":
		facts["collection_method"] = "polling"
	case "ebpf_monitor":
		facts["collection_method"] = "ebpf"
	case "esf_monitor":
		facts["collection_method"] = "endpoint_security"
	}
	if len(entities) == 0 {
		entities = nil
	}
	if len(facts) == 0 {
		facts = nil
	}
	return entities, facts, status
}

func processFields(p models.Process) (map[string]any, map[string]any) {
	process := map[string]any{"pid": p.PID}
	if p.Name != "" {
		process["name"] = p.Name
	}
	if p.Executable != "" {
		process["executable"] = p.Executable
	}
	if !p.StartTime.IsZero() {
		process["start_time"] = p.StartTime.UTC().Format(time.RFC3339Nano)
	}
	facts := map[string]any{"process.pid": p.PID, "process.ppid": p.PPID}
	if p.Name != "" {
		facts["process.name"] = p.Name
	}
	if p.Executable != "" {
		facts["process.executable"] = p.Executable
	}
	if p.Username != "" {
		facts["process.username"] = p.Username
	}
	if !p.StartTime.IsZero() {
		facts["process.start_time"] = p.StartTime.UTC().Format(time.RFC3339Nano)
	}
	return map[string]any{"process": process}, facts
}

func connectionFields(c models.NetworkConnection) (map[string]any, map[string]any) {
	process := map[string]any{"pid": c.PID}
	if c.ProcessName != "" {
		process["name"] = c.ProcessName
	}
	if !c.ProcessStartTime.IsZero() {
		process["start_time"] = c.ProcessStartTime.UTC().Format(time.RFC3339Nano)
	}
	network := map[string]any{"protocol": c.Protocol, "remote_address": c.RemoteAddr, "remote_port": c.RemotePort}
	facts := map[string]any{
		"process.pid":            c.PID,
		"network.protocol":       c.Protocol,
		"network.local_address":  c.LocalAddr,
		"network.local_port":     c.LocalPort,
		"network.remote_address": c.RemoteAddr,
		"network.remote_port":    c.RemotePort,
		"network.state":          c.State,
	}
	if c.ProcessName != "" {
		facts["process.name"] = c.ProcessName
	}
	if !c.ProcessStartTime.IsZero() {
		facts["process.start_time"] = c.ProcessStartTime.UTC().Format(time.RFC3339Nano)
	}
	return map[string]any{"process": process, "network": network}, facts
}

func mapFields(data map[string]interface{}) (map[string]any, map[string]any, string) {
	var entities, facts map[string]any
	if value, ok := data["entities"].(map[string]interface{}); ok {
		entities = value
	}
	if value, ok := data["facts"].(map[string]interface{}); ok {
		facts = value
	}
	status, _ := data["collection_status"].(string)
	return entities, facts, status
}

// ProcessEntityID constructs a stable identity only when a process start time
// is known. PID alone is deliberately not an endpoint identity because it is
// reused by the operating system.
func ProcessEntityID(endpoint string, pid int32, started time.Time) string {
	if endpoint == "" || pid <= 0 || started.IsZero() {
		return ""
	}
	return fmt.Sprintf("%s:%d:%d", endpoint, pid, started.UTC().UnixNano())
}

func processCorrelationID(endpoint string, entities map[string]any) string {
	if endpoint == "" || len(entities) == 0 {
		return ""
	}
	process, ok := entities["process"].(map[string]any)
	if !ok {
		return ""
	}
	pid, ok := integer(process["pid"])
	if !ok || pid <= 0 {
		return ""
	}
	startedRaw, ok := process["start_time"].(string)
	if !ok {
		return ""
	}
	started, err := time.Parse(time.RFC3339Nano, startedRaw)
	if err != nil {
		return ""
	}
	return ProcessEntityID(endpoint, int32(pid), started)
}

func integer(value any) (int64, bool) {
	switch value := value.(type) {
	case int:
		return int64(value), true
	case int32:
		return int64(value), true
	case int64:
		return value, true
	case float64:
		if value == float64(int64(value)) {
			return int64(value), true
		}
	case json.Number:
		parsed, err := value.Int64()
		return parsed, err == nil
	case string:
		parsed, err := strconv.ParseInt(value, 10, 32)
		return parsed, err == nil
	}
	return 0, false
}
