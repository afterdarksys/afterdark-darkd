package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/plugin"
)

// ServicePluginImpl implements plugin.GRPCPlugin for service plugins
type ServicePluginImpl struct {
	plugin.Plugin
	Impl ServicePlugin
}

func (p *ServicePluginImpl) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterServicePluginServer(s, &serviceGRPCServer{Impl: p.Impl})
	return nil
}

func (p *ServicePluginImpl) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &serviceGRPCClient{client: pb.NewServicePluginClient(c)}, nil
}

// serviceGRPCServer is the gRPC server for ServicePlugin (plugin side)
type serviceGRPCServer struct {
	pb.UnimplementedServicePluginServer
	Impl ServicePlugin
}

func (s *serviceGRPCServer) Info(ctx context.Context, req *pb.Empty) (*pb.PluginInfo, error) {
	info := s.Impl.Info()
	return &pb.PluginInfo{
		Name:         info.Name,
		Version:      info.Version,
		Type:         string(info.Type),
		Description:  info.Description,
		Author:       info.Author,
		License:      info.License,
		Capabilities: info.Capabilities,
	}, nil
}

func (s *serviceGRPCServer) Configure(ctx context.Context, req *pb.ConfigureRequest) (*pb.ConfigureResponse, error) {
	config := make(map[string]interface{})

	// First, add simple string configs
	for k, v := range req.Config {
		config[k] = v
	}

	// Then overlay with complex JSON config if provided
	if len(req.ConfigJson) > 0 {
		var jsonConfig map[string]interface{}
		if err := json.Unmarshal(req.ConfigJson, &jsonConfig); err == nil {
			for k, v := range jsonConfig {
				config[k] = v
			}
		}
	}

	err := s.Impl.Configure(config)
	if err != nil {
		return &pb.ConfigureResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.ConfigureResponse{Success: true}, nil
}

func (s *serviceGRPCServer) Start(ctx context.Context, req *pb.ServiceStartRequest) (*pb.ServiceStartResponse, error) {
	err := s.Impl.Start(ctx)
	if err != nil {
		return &pb.ServiceStartResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.ServiceStartResponse{Success: true}, nil
}

func (s *serviceGRPCServer) Stop(ctx context.Context, req *pb.ServiceStopRequest) (*pb.ServiceStopResponse, error) {
	err := s.Impl.Stop(ctx)
	if err != nil {
		return &pb.ServiceStopResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.ServiceStopResponse{Success: true}, nil
}

func (s *serviceGRPCServer) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	health := s.Impl.Health()
	metrics := make(map[string]string)
	for k, v := range health.Metrics {
		if str, ok := v.(string); ok {
			metrics[k] = str
		} else {
			b, _ := json.Marshal(v)
			metrics[k] = string(b)
		}
	}
	return &pb.HealthResponse{
		Health: &pb.PluginHealth{
			State:         health.State.String(),
			Message:       health.Message,
			LastCheckUnix: health.LastCheck.Unix(),
			Metrics:       metrics,
		},
	}, nil
}

func (s *serviceGRPCServer) Execute(ctx context.Context, req *pb.ServiceExecuteRequest) (*pb.ServiceExecuteResponse, error) {
	params := make(map[string]interface{})
	if len(req.ParamsJson) > 0 {
		json.Unmarshal(req.ParamsJson, &params)
	}

	result, err := s.Impl.Execute(ctx, req.Action, params)
	if err != nil {
		return &pb.ServiceExecuteResponse{Success: false, Error: err.Error()}, nil
	}

	resultJSON, _ := json.Marshal(result)
	return &pb.ServiceExecuteResponse{
		Success:    true,
		ResultJson: resultJSON,
	}, nil
}

// serviceGRPCClient is the gRPC client for ServicePlugin (host side)
type serviceGRPCClient struct {
	client pb.ServicePluginClient
}

func (c *serviceGRPCClient) Info() PluginInfo {
	resp, err := c.client.Info(context.Background(), &pb.Empty{})
	if err != nil {
		return PluginInfo{}
	}
	return PluginInfo{
		Name:         resp.Name,
		Version:      resp.Version,
		Type:         PluginType(resp.Type),
		Description:  resp.Description,
		Author:       resp.Author,
		License:      resp.License,
		Capabilities: resp.Capabilities,
	}
}

func (c *serviceGRPCClient) Configure(config map[string]interface{}) error {
	configJSON, _ := json.Marshal(config)
	resp, err := c.client.Configure(context.Background(), &pb.ConfigureRequest{
		ConfigJson: configJSON,
	})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf(resp.Error)
	}
	return nil
}

func (c *serviceGRPCClient) Start(ctx context.Context) error {
	resp, err := c.client.Start(ctx, &pb.ServiceStartRequest{})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf(resp.Error)
	}
	return nil
}

func (c *serviceGRPCClient) Stop(ctx context.Context) error {
	resp, err := c.client.Stop(ctx, &pb.ServiceStopRequest{})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf(resp.Error)
	}
	return nil
}

func (c *serviceGRPCClient) Health() PluginHealth {
	resp, err := c.client.Health(context.Background(), &pb.HealthRequest{})
	if err != nil {
		return PluginHealth{
			State:     PluginStateError,
			Message:   err.Error(),
			LastCheck: time.Now(),
		}
	}

	state := parsePluginState(resp.Health.State)
	metrics := make(map[string]interface{})
	for k, v := range resp.Health.Metrics {
		metrics[k] = v
	}

	return PluginHealth{
		State:     state,
		Message:   resp.Health.Message,
		LastCheck: time.Unix(resp.Health.LastCheckUnix, 0),
		Metrics:   metrics,
	}
}

func (c *serviceGRPCClient) Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error) {
	paramsJSON, _ := json.Marshal(params)
	resp, err := c.client.Execute(ctx, &pb.ServiceExecuteRequest{
		Action:     action,
		ParamsJson: paramsJSON,
	})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf(resp.Error)
	}

	var result map[string]interface{}
	json.Unmarshal(resp.ResultJson, &result)
	return result, nil
}

// parsePluginState converts string to PluginState
func parsePluginState(s string) PluginState {
	switch s {
	case "loading":
		return PluginStateLoading
	case "ready":
		return PluginStateReady
	case "running":
		return PluginStateRunning
	case "stopping":
		return PluginStateStopping
	case "stopped":
		return PluginStateStopped
	case "error":
		return PluginStateError
	default:
		return PluginStateUnknown
	}
}
