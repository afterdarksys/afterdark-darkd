package siem

import (
	"context"
	"encoding/json"
	"github.com/afterdarksys/afterdark-darkd/internal/endpointreport"
	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"runtime"
	"strings"
	"time"
)

var sensorServices = map[string][]string{
	"telemetry": {"event_store"}, "process": {"process_tracker", "esf_monitor", "ebpf_monitor", "etw_monitor"},
	"network": {"connection_tracker", "conntrack", "network_monitor"}, "dns": {"dns_tunnel_detection"},
	"file_integrity": {"integrity_monitor"}, "patches": {"patch_monitor"}, "firewall": {},
	"host_ids": {}, "persistence": {"persistence_monitor"},
	"ransomware": {"canary"}, "self_protection": {},
}

func (s *Service) coverage(ctx context.Context, store *events.Store) error {
	states := map[string]endpointreport.Sensor{}
	for sensor, names := range sensorServices {
		observed := endpointreport.Capability(sensor, "unknown", "No registered sensor health report")
		components := map[string]any{}
		for _, name := range names {
			if instance := s.registry.Get(name); instance != nil {
				health := instance.Health()
				state := "unknown"
				switch health.Status {
				case service.HealthHealthy:
					state = "running"
				case service.HealthDegraded, service.HealthUnhealthy:
					state = "failed"
				}
				lower := strings.ToLower(health.Message)
				if strings.Contains(lower, "unsupported") || strings.Contains(lower, "not supported") {
					state = "unsupported"
				} else if strings.Contains(lower, "permission denied") {
					state = "permission_denied"
				} else if strings.Contains(lower, "disabled") {
					state = "disabled"
				}
				if health.LastCheck.IsZero() || time.Since(health.LastCheck) > 3*time.Minute {
					state = "unknown"
				}
				components[name] = map[string]any{"state": state, "last_check": health.LastCheck}
				if observed.State == "unknown" || state != "running" {
					observed = endpointreport.Capability(sensor, state, "Registered service health")
				}
				if sensor == "telemetry" {
					if dropped, ok := health.Metrics["rejected_events"].(uint64); ok {
						n := int64(dropped)
						observed.Dropped = &n
					}
				}
			}
		}
		observed.Details = map[string]any{"components": components, "scope": "service-reported health, not proof of complete sensor coverage"}
		states[sensor] = observed
	}
	native, observations := endpointreport.Collect(ctx)
	for _, state := range native {
		states[state.Sensor] = state
	}
	response := endpointreport.Capability("response", "running", "Authenticated allowlisted command receiver")
	response.Details = map[string]any{"actions": []string{"collect_status", "delivery_canary"}, "platform": runtime.GOOS}
	states["response"] = response
	list := []endpointreport.Sensor{}
	for _, value := range states {
		list = append(list, value)
	}
	raw, err := json.Marshal(map[string]any{"sensors": list, "platform": runtime.GOOS})
	if err != nil {
		return err
	}
	if err = store.Publish(ctx, events.Event{Source: "darkd_coverage", Type: "sensor.health", Data: raw}); err != nil {
		return err
	}
	for _, observation := range observations {
		raw, err = json.Marshal(observation.Data)
		if err != nil {
			return err
		}
		if err = store.Publish(ctx, events.Event{Source: "darkd_native_snapshot", Type: observation.Type, Data: raw, Facts: observation.Facts, Entities: observation.Entities}); err != nil {
			return err
		}
	}
	return store.Publish(ctx, events.Event{Source: "darkd_coverage", Type: "delivery.canary", Data: json.RawMessage(`{"purpose":"end-to-end delivery freshness"}`)})
}
func (s *Service) commands(ctx context.Context, store *events.Store) error {
	command, err := s.config.DarkAPI.ClaimCommand(ctx)
	if err != nil || command == nil {
		return err
	}
	receipt, err := store.CommandReceipt(ctx, command.ID)
	if err != nil {
		return err
	}
	if receipt == nil {
		receipt = &events.CommandReceipt{ID: command.ID, Action: command.Action, Status: "succeeded"}
		result := map[string]any{}
		var event *events.Event
		switch command.Action {
		case "collect_status":
			components := map[string]string{}
			for _, instance := range s.registry.All() {
				components[instance.Name()] = instance.Health().Status.String()
			}
			result["components"] = components
			result["platform"] = runtime.GOOS
		case "delivery_canary":
			result["event_id"] = command.ID
			event = &events.Event{ID: command.ID, Source: "darkd_response", Type: "delivery.canary", Data: json.RawMessage(`{"purpose":"requested delivery canary"}`)}
		default:
			receipt.Status = "failed"
			result["error"] = "unsupported action"
		}
		receipt.Result, err = json.Marshal(result)
		if err != nil {
			return err
		}
		if !command.ExpiresAt.After(time.Now()) {
			return context.DeadlineExceeded
		}
		if err = store.CompleteCommand(ctx, *receipt, event); err != nil {
			return err
		}
	}
	if receipt.Action != command.Action {
		return context.Canceled
	}
	return s.config.DarkAPI.AckCommand(ctx, command, receipt.Status, receipt.Result)
}
