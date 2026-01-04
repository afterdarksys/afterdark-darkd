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

// DataSourcePluginImpl implements plugin.GRPCPlugin for data source plugins
type DataSourcePluginImpl struct {
	plugin.Plugin
	Impl DataSourcePlugin
}

func (p *DataSourcePluginImpl) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterDataSourcePluginServer(s, &dataSourceGRPCServer{Impl: p.Impl})
	return nil
}

func (p *DataSourcePluginImpl) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &dataSourceGRPCClient{client: pb.NewDataSourcePluginClient(c)}, nil
}

// dataSourceGRPCServer is the gRPC server for DataSourcePlugin (plugin side)
type dataSourceGRPCServer struct {
	pb.UnimplementedDataSourcePluginServer
	Impl DataSourcePlugin
}

func (s *dataSourceGRPCServer) Info(ctx context.Context, req *pb.Empty) (*pb.PluginInfo, error) {
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

func (s *dataSourceGRPCServer) Configure(ctx context.Context, req *pb.ConfigureRequest) (*pb.ConfigureResponse, error) {
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

func (s *dataSourceGRPCServer) Connect(ctx context.Context, req *pb.DataSourceConnectRequest) (*pb.DataSourceConnectResponse, error) {
	err := s.Impl.Connect(ctx)
	if err != nil {
		return &pb.DataSourceConnectResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.DataSourceConnectResponse{Success: true}, nil
}

func (s *dataSourceGRPCServer) Disconnect(ctx context.Context, req *pb.DataSourceDisconnectRequest) (*pb.DataSourceDisconnectResponse, error) {
	err := s.Impl.Disconnect(ctx)
	if err != nil {
		return &pb.DataSourceDisconnectResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.DataSourceDisconnectResponse{Success: true}, nil
}

func (s *dataSourceGRPCServer) Query(ctx context.Context, req *pb.DataSourceQueryRequest) (*pb.DataSourceQueryResponse, error) {
	params := make(map[string]interface{})
	if len(req.ParamsJson) > 0 {
		json.Unmarshal(req.ParamsJson, &params)
	}

	results, err := s.Impl.Query(ctx, req.Query, params)
	if err != nil {
		return &pb.DataSourceQueryResponse{Success: false, Error: err.Error()}, nil
	}

	resultsJSON := make([][]byte, len(results))
	for i, r := range results {
		resultsJSON[i], _ = json.Marshal(r)
	}

	return &pb.DataSourceQueryResponse{
		Success:     true,
		ResultsJson: resultsJSON,
	}, nil
}

func (s *dataSourceGRPCServer) Subscribe(req *pb.DataSourceSubscribeRequest, stream pb.DataSourcePlugin_SubscribeServer) error {
	handler := func(data map[string]interface{}) {
		dataJSON, _ := json.Marshal(data)
		stream.Send(&pb.DataSourceSubscribeResponse{
			DataJson: dataJSON,
		})
	}

	return s.Impl.Subscribe(stream.Context(), req.Topic, handler)
}

func (s *dataSourceGRPCServer) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
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

// dataSourceGRPCClient is the gRPC client for DataSourcePlugin (host side)
type dataSourceGRPCClient struct {
	client pb.DataSourcePluginClient
}

func (c *dataSourceGRPCClient) Info() PluginInfo {
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

func (c *dataSourceGRPCClient) Configure(config map[string]interface{}) error {
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

func (c *dataSourceGRPCClient) Connect(ctx context.Context) error {
	resp, err := c.client.Connect(ctx, &pb.DataSourceConnectRequest{})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf(resp.Error)
	}
	return nil
}

func (c *dataSourceGRPCClient) Disconnect(ctx context.Context) error {
	resp, err := c.client.Disconnect(ctx, &pb.DataSourceDisconnectRequest{})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf(resp.Error)
	}
	return nil
}

func (c *dataSourceGRPCClient) Query(ctx context.Context, query string, params map[string]interface{}) ([]map[string]interface{}, error) {
	paramsJSON, _ := json.Marshal(params)
	resp, err := c.client.Query(ctx, &pb.DataSourceQueryRequest{
		Query:      query,
		ParamsJson: paramsJSON,
	})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf(resp.Error)
	}

	results := make([]map[string]interface{}, len(resp.ResultsJson))
	for i, r := range resp.ResultsJson {
		json.Unmarshal(r, &results[i])
	}
	return results, nil
}

func (c *dataSourceGRPCClient) Subscribe(ctx context.Context, topic string, handler func(data map[string]interface{})) error {
	stream, err := c.client.Subscribe(ctx, &pb.DataSourceSubscribeRequest{
		Topic: topic,
	})
	if err != nil {
		return err
	}

	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				return
			}
			var data map[string]interface{}
			json.Unmarshal(resp.DataJson, &data)
			handler(data)
		}
	}()

	return nil
}

func (c *dataSourceGRPCClient) Health() PluginHealth {
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
