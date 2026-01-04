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

// ReporterPluginImpl implements plugin.GRPCPlugin for reporter plugins
type ReporterPluginImpl struct {
	plugin.Plugin
	Impl ReporterPlugin
}

func (p *ReporterPluginImpl) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterReporterPluginServer(s, &reporterGRPCServer{Impl: p.Impl})
	return nil
}

func (p *ReporterPluginImpl) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &reporterGRPCClient{client: pb.NewReporterPluginClient(c)}, nil
}

// reporterGRPCServer is the gRPC server for ReporterPlugin (plugin side)
type reporterGRPCServer struct {
	pb.UnimplementedReporterPluginServer
	Impl ReporterPlugin
}

func (s *reporterGRPCServer) Info(ctx context.Context, req *pb.Empty) (*pb.PluginInfo, error) {
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

func (s *reporterGRPCServer) Configure(ctx context.Context, req *pb.ConfigureRequest) (*pb.ConfigureResponse, error) {
	config := make(map[string]interface{})
	for k, v := range req.Config {
		config[k] = v
	}
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

func (s *reporterGRPCServer) SupportedFormats(ctx context.Context, req *pb.ReporterFormatsRequest) (*pb.ReporterFormatsResponse, error) {
	formats := s.Impl.SupportedFormats()
	return &pb.ReporterFormatsResponse{Formats: formats}, nil
}

func (s *reporterGRPCServer) Generate(ctx context.Context, req *pb.ReporterGenerateRequest) (*pb.ReporterGenerateResponse, error) {
	var data map[string]interface{}
	if len(req.DataJson) > 0 {
		json.Unmarshal(req.DataJson, &data)
	}

	report, err := s.Impl.Generate(ctx, req.Format, data)
	if err != nil {
		return &pb.ReporterGenerateResponse{Success: false, Error: err.Error()}, nil
	}

	contentType := "application/octet-stream"
	switch req.Format {
	case "pdf":
		contentType = "application/pdf"
	case "html":
		contentType = "text/html"
	case "csv":
		contentType = "text/csv"
	case "json":
		contentType = "application/json"
	case "xml":
		contentType = "application/xml"
	}

	return &pb.ReporterGenerateResponse{
		Success:     true,
		Report:      report,
		ContentType: contentType,
	}, nil
}

func (s *reporterGRPCServer) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
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

// reporterGRPCClient is the gRPC client for ReporterPlugin (host side)
type reporterGRPCClient struct {
	client pb.ReporterPluginClient
}

func (c *reporterGRPCClient) Info() PluginInfo {
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

func (c *reporterGRPCClient) Configure(config map[string]interface{}) error {
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

func (c *reporterGRPCClient) SupportedFormats() []string {
	resp, err := c.client.SupportedFormats(context.Background(), &pb.ReporterFormatsRequest{})
	if err != nil {
		return nil
	}
	return resp.Formats
}

func (c *reporterGRPCClient) Generate(ctx context.Context, format string, data map[string]interface{}) ([]byte, error) {
	dataJSON, _ := json.Marshal(data)
	resp, err := c.client.Generate(ctx, &pb.ReporterGenerateRequest{
		Format:   format,
		DataJson: dataJSON,
	})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf(resp.Error)
	}
	return resp.Report, nil
}

func (c *reporterGRPCClient) Health() PluginHealth {
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
