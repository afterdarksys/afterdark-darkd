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

// StoragePluginImpl implements plugin.GRPCPlugin for storage plugins
type StoragePluginImpl struct {
	plugin.Plugin
	Impl StoragePlugin
}

func (p *StoragePluginImpl) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterStoragePluginServer(s, &storageGRPCServer{Impl: p.Impl})
	return nil
}

func (p *StoragePluginImpl) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &storageGRPCClient{client: pb.NewStoragePluginClient(c)}, nil
}

// storageGRPCServer is the gRPC server for StoragePlugin (plugin side)
type storageGRPCServer struct {
	pb.UnimplementedStoragePluginServer
	Impl StoragePlugin
}

func (s *storageGRPCServer) Info(ctx context.Context, req *pb.Empty) (*pb.PluginInfo, error) {
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

func (s *storageGRPCServer) Configure(ctx context.Context, req *pb.ConfigureRequest) (*pb.ConfigureResponse, error) {
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

func (s *storageGRPCServer) Connect(ctx context.Context, req *pb.StorageConnectRequest) (*pb.StorageConnectResponse, error) {
	err := s.Impl.Connect(ctx)
	if err != nil {
		return &pb.StorageConnectResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.StorageConnectResponse{Success: true}, nil
}

func (s *storageGRPCServer) Disconnect(ctx context.Context, req *pb.StorageDisconnectRequest) (*pb.StorageDisconnectResponse, error) {
	err := s.Impl.Disconnect(ctx)
	if err != nil {
		return &pb.StorageDisconnectResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.StorageDisconnectResponse{Success: true}, nil
}

func (s *storageGRPCServer) Get(ctx context.Context, req *pb.StorageGetRequest) (*pb.StorageGetResponse, error) {
	value, err := s.Impl.Get(ctx, req.Collection, req.Key)
	if err != nil {
		return &pb.StorageGetResponse{Success: false, Error: err.Error(), Found: false}, nil
	}
	if value == nil {
		return &pb.StorageGetResponse{Success: true, Found: false}, nil
	}
	return &pb.StorageGetResponse{Success: true, Found: true, Value: value}, nil
}

func (s *storageGRPCServer) Set(ctx context.Context, req *pb.StorageSetRequest) (*pb.StorageSetResponse, error) {
	err := s.Impl.Set(ctx, req.Collection, req.Key, req.Value)
	if err != nil {
		return &pb.StorageSetResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.StorageSetResponse{Success: true}, nil
}

func (s *storageGRPCServer) Delete(ctx context.Context, req *pb.StorageDeleteRequest) (*pb.StorageDeleteResponse, error) {
	err := s.Impl.Delete(ctx, req.Collection, req.Key)
	if err != nil {
		return &pb.StorageDeleteResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.StorageDeleteResponse{Success: true}, nil
}

func (s *storageGRPCServer) List(ctx context.Context, req *pb.StorageListRequest) (*pb.StorageListResponse, error) {
	keys, err := s.Impl.List(ctx, req.Collection, req.Prefix)
	if err != nil {
		return &pb.StorageListResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.StorageListResponse{Success: true, Keys: keys}, nil
}

func (s *storageGRPCServer) Query(ctx context.Context, req *pb.StorageQueryRequest) (*pb.StorageQueryResponse, error) {
	var query map[string]interface{}
	if len(req.QueryJson) > 0 {
		json.Unmarshal(req.QueryJson, &query)
	}

	results, err := s.Impl.Query(ctx, req.Collection, query)
	if err != nil {
		return &pb.StorageQueryResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.StorageQueryResponse{Success: true, Results: results}, nil
}

func (s *storageGRPCServer) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
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

// storageGRPCClient is the gRPC client for StoragePlugin (host side)
type storageGRPCClient struct {
	client pb.StoragePluginClient
}

func (c *storageGRPCClient) Info() PluginInfo {
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

func (c *storageGRPCClient) Configure(config map[string]interface{}) error {
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

func (c *storageGRPCClient) Connect(ctx context.Context) error {
	resp, err := c.client.Connect(ctx, &pb.StorageConnectRequest{})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf(resp.Error)
	}
	return nil
}

func (c *storageGRPCClient) Disconnect(ctx context.Context) error {
	resp, err := c.client.Disconnect(ctx, &pb.StorageDisconnectRequest{})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf(resp.Error)
	}
	return nil
}

func (c *storageGRPCClient) Get(ctx context.Context, collection, key string) ([]byte, error) {
	resp, err := c.client.Get(ctx, &pb.StorageGetRequest{
		Collection: collection,
		Key:        key,
	})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf(resp.Error)
	}
	if !resp.Found {
		return nil, nil
	}
	return resp.Value, nil
}

func (c *storageGRPCClient) Set(ctx context.Context, collection, key string, value []byte) error {
	resp, err := c.client.Set(ctx, &pb.StorageSetRequest{
		Collection: collection,
		Key:        key,
		Value:      value,
	})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf(resp.Error)
	}
	return nil
}

func (c *storageGRPCClient) Delete(ctx context.Context, collection, key string) error {
	resp, err := c.client.Delete(ctx, &pb.StorageDeleteRequest{
		Collection: collection,
		Key:        key,
	})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf(resp.Error)
	}
	return nil
}

func (c *storageGRPCClient) List(ctx context.Context, collection, prefix string) ([]string, error) {
	resp, err := c.client.List(ctx, &pb.StorageListRequest{
		Collection: collection,
		Prefix:     prefix,
	})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf(resp.Error)
	}
	return resp.Keys, nil
}

func (c *storageGRPCClient) Query(ctx context.Context, collection string, query map[string]interface{}) ([][]byte, error) {
	queryJSON, _ := json.Marshal(query)
	resp, err := c.client.Query(ctx, &pb.StorageQueryRequest{
		Collection: collection,
		QueryJson:  queryJSON,
	})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf(resp.Error)
	}
	return resp.Results, nil
}

func (c *storageGRPCClient) Health() PluginHealth {
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
