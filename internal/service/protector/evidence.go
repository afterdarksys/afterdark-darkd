package protector

import (
	"context"
	"fmt"
	"github.com/afterdarksys/afterdark-darkd/internal/plugin"
	gnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"math"
	"net"
	"os"
	"time"
)

func processSnapshot(ctx context.Context) ([]map[string]any, error) {
	processes, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0, len(processes))
	for _, p := range processes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name, err := p.NameWithContext(ctx)
		if err != nil {
			continue
		}
		parent, _ := p.PpidWithContext(ctx)
		path, _ := p.ExeWithContext(ctx)
		start, _ := p.CreateTimeWithContext(ctx)
		result = append(result, map[string]any{"pid": p.Pid, "ppid": parent, "name": name, "path": path, "start_time_ms": start})
		if len(result) >= 10000 {
			return nil, fmt.Errorf("process snapshot limit exceeded")
		}
	}
	return result, nil
}

func (s *Service) evidence(kind string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	switch kind {
	case "process_snapshot":
		rows, err := processSnapshot(ctx)
		return map[string]any{"processes": rows}, err
	case "network_snapshot":
		rows, err := gnet.ConnectionsWithContext(ctx, "all")
		if len(rows) > 10000 {
			return nil, fmt.Errorf("connection snapshot limit exceeded")
		}
		return map[string]any{"connections": rows}, err
	case "behavior_analysis":
		if s.registry == nil {
			return nil, fmt.Errorf("behavior service unavailable")
		}
		candidate, err := s.registry.GetService("behavior_monitor")
		if err != nil {
			return nil, err
		}
		if provider, ok := candidate.(interface{ GetStatus() map[string]interface{} }); ok {
			return provider.GetStatus(), nil
		}
		return nil, fmt.Errorf("behavior service does not expose evidence")
	}
	return nil, fmt.Errorf("unknown evidence type")
}

func (s *Service) handleCommand(cmd Command) (map[string]any, error) {
	if cmd.ID == "" || cmd.Timestamp.IsZero() || time.Since(cmd.Timestamp) > 5*time.Minute || time.Until(cmd.Timestamp) > time.Minute {
		return nil, fmt.Errorf("missing or expired command identity")
	}
	ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	defer cancel()
	switch cmd.Type {
	case "collect_forensics":
		result := map[string]any{}
		for _, kind := range []string{"process_snapshot", "network_snapshot"} {
			data, err := s.evidence(kind)
			if err != nil {
				return nil, err
			}
			result[kind] = data
		}
		return result, nil
	case "kill_process":
		if !s.config.AllowRemoteResponse {
			return nil, fmt.Errorf("remote response disabled by local policy")
		}
		number, ok := cmd.Params["pid"].(float64)
		if !ok || number < 2 || number > math.MaxInt32 || math.Trunc(number) != number || int(number) == os.Getpid() {
			return nil, fmt.Errorf("invalid or protected PID")
		}
		expected, ok := cmd.Params["start_time_ms"].(float64)
		if !ok || expected <= 0 {
			return nil, fmt.Errorf("process start time is required to prevent PID reuse")
		}
		p, err := process.NewProcessWithContext(ctx, int32(number))
		if err != nil {
			return nil, err
		}
		created, err := p.CreateTimeWithContext(ctx)
		if err != nil {
			return nil, err
		}
		if float64(created) != expected {
			return nil, fmt.Errorf("process identity changed")
		}
		if err := p.KillWithContext(ctx); err != nil {
			return nil, err
		}
		return map[string]any{"terminated_pid": int32(number)}, nil
	case "block_connection":
		if !s.config.AllowRemoteResponse {
			return nil, fmt.Errorf("remote response disabled by local policy")
		}
		address, _ := cmd.Params["ip"].(string)
		ip := net.ParseIP(address)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, fmt.Errorf("invalid block destination")
		}
		if s.registry == nil {
			return nil, fmt.Errorf("firewall provider unavailable")
		}
		candidate, err := s.registry.GetService("firewall")
		if err != nil {
			return nil, err
		}
		firewall, ok := candidate.(plugin.FirewallPlugin)
		if !ok {
			return nil, fmt.Errorf("firewall provider unavailable")
		}
		blocked, err := firewall.BlockIP(ctx, ip.String(), "authorized remote response", s.Name(), 300, 0, nil)
		if err != nil {
			return nil, err
		}
		return map[string]any{"block": blocked}, nil
	}
	return nil, fmt.Errorf("unknown command type: %s", cmd.Type)
}

func (s *Service) collect(kind string, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			data, err := s.evidence(kind)
			if err != nil {
				s.QueueTelemetry("collection_error", map[string]any{"source": kind, "error": err.Error()})
				continue
			}
			s.QueueTelemetry(kind, data)
		}
	}
}
