package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/afterdarksys/afterdark-darkd/internal/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ManagePlugin operates only on plugins discovered inside the configured trust
// directory. Host.LoadPlugin performs the existing signature/ownership checks.
// Enable/disable affect this daemon session; startup policy stays in configuration.
func (s *Server) ManagePlugin(ctx context.Context, req *pb.PluginRequest) (*pb.PluginResponse, error) {
	s.pluginMu.Lock()
	defer s.pluginMu.Unlock()
	host := s.config.PluginHost
	if host == nil {
		return nil, status.Error(codes.FailedPrecondition, "plugin host unavailable")
	}
	encode := func(value any) (*pb.PluginResponse, error) {
		data, err := json.Marshal(value)
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		return &pb.PluginResponse{ResultJson: string(data)}, nil
	}
	paths, err := host.DiscoverPlugins()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if req.Action == "list" {
		entries := make([]map[string]any, 0, len(paths))
		for _, path := range paths {
			entry := map[string]any{"binary": filepath.Base(path), "enabled": false}
			if loaded, ok := host.GetPlugin(path); ok {
				entry["enabled"] = true
				entry["info"] = loaded.Info
			}
			entries = append(entries, entry)
		}
		return encode(entries)
	}
	if req.Name == "" || filepath.Base(req.Name) != req.Name || strings.ContainsAny(req.Name, "/\\") {
		return nil, status.Error(codes.InvalidArgument, "plugin name must be a basename or loaded plugin name")
	}
	var path string
	var loaded *plugin.LoadedPlugin
	if existing, ok := host.GetPluginByName(req.Name); ok {
		loaded = existing
		path = existing.Path
	} else {
		for _, candidate := range paths {
			if filepath.Base(candidate) == req.Name {
				path = candidate
				break
			}
		}
		if path != "" {
			loaded, _ = host.GetPlugin(path)
		}
	}
	if path == "" {
		return nil, status.Error(codes.NotFound, "plugin not found in trusted plugin directory")
	}
	switch req.Action {
	case "enable", "reload":
		if req.Action == "reload" && loaded != nil {
			if svc, ok := loaded.Raw.(plugin.ServicePlugin); ok {
				if err := svc.Stop(ctx); err != nil {
					return nil, status.Error(codes.Internal, err.Error())
				}
			}
			if err := host.UnloadPlugin(path); err != nil {
				return nil, status.Error(codes.Internal, err.Error())
			}
			loaded = nil
		}
		if loaded == nil {
			loaded, err = host.LoadPlugin(path)
			if err != nil {
				return nil, status.Error(codes.FailedPrecondition, err.Error())
			}
			if svc, ok := loaded.Raw.(plugin.ServicePlugin); ok {
				if err := svc.Configure(map[string]interface{}{}); err != nil {
					host.UnloadPlugin(path)
					return nil, status.Error(codes.FailedPrecondition, err.Error())
				}
				if err := svc.Start(ctx); err != nil {
					host.UnloadPlugin(path)
					return nil, status.Error(codes.Internal, err.Error())
				}
			}
		}
		return encode(map[string]any{"enabled": true, "plugin": loaded.Info, "scope": "current daemon session"})
	case "disable":
		if loaded != nil {
			if svc, ok := loaded.Raw.(plugin.ServicePlugin); ok {
				if err := svc.Stop(ctx); err != nil {
					return nil, status.Error(codes.Internal, err.Error())
				}
			}
			if err := host.UnloadPlugin(path); err != nil {
				return nil, status.Error(codes.Internal, err.Error())
			}
		}
		return encode(map[string]any{"enabled": false, "binary": filepath.Base(path), "scope": "current daemon session"})
	case "execute":
		if loaded == nil {
			return nil, status.Error(codes.FailedPrecondition, "plugin is disabled")
		}
		if req.PluginAction == "" {
			return nil, status.Error(codes.InvalidArgument, "plugin action required")
		}
		params := map[string]any{}
		if req.ParamsJson != "" {
			if len(req.ParamsJson) > 1024*1024 {
				return nil, status.Error(codes.InvalidArgument, "parameters exceed 1 MiB")
			}
			if err := json.Unmarshal([]byte(req.ParamsJson), &params); err != nil || params == nil {
				return nil, status.Error(codes.InvalidArgument, "parameters must be a JSON object")
			}
		}
		svc, ok := loaded.Raw.(plugin.ServicePlugin)
		if !ok {
			return nil, status.Error(codes.FailedPrecondition, "plugin does not expose service actions")
		}
		value, err := svc.Execute(ctx, req.PluginAction, params)
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		return encode(value)
	default:
		return nil, status.Error(codes.InvalidArgument, "action must be list, enable, disable, reload, or execute")
	}
}

func (s *Server) CaptureProfile(ctx context.Context, req *pb.ProfileRequest) (*pb.ProfileResponse, error) {
	var out bytes.Buffer
	switch req.Kind {
	case "cpu":
		if req.Seconds < 1 || req.Seconds > 60 {
			return nil, status.Error(codes.InvalidArgument, "CPU duration must be 1 to 60 seconds")
		}
		if err := pprof.StartCPUProfile(&out); err != nil {
			return nil, status.Error(codes.ResourceExhausted, err.Error())
		}
		timer := time.NewTimer(time.Duration(req.Seconds) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			pprof.StopCPUProfile()
			return nil, status.FromContextError(ctx.Err()).Err()
		case <-timer.C:
			pprof.StopCPUProfile()
		}
	case "heap":
		if err := pprof.WriteHeapProfile(&out); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
	case "mem":
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		if err := json.NewEncoder(&out).Encode(stats); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
	default:
		return nil, status.Error(codes.InvalidArgument, "profile must be cpu, mem, or heap")
	}
	if out.Len() > 3*1024*1024 {
		return nil, status.Error(codes.ResourceExhausted, "profile exceeds 3 MiB IPC response limit")
	}
	return &pb.ProfileResponse{Data: out.Bytes()}, nil
}
