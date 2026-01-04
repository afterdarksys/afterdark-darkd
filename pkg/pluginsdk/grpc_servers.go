package pluginsdk

import (
	"context"
	"encoding/json"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/plugin"
)

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

// cliGRPCServer is the gRPC server for CLIPlugin (plugin side)
type cliGRPCServer struct {
	pb.UnimplementedCLIPluginServer
	Impl CLIPlugin
}

func (s *cliGRPCServer) Info(ctx context.Context, req *pb.Empty) (*pb.PluginInfo, error) {
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

func (s *cliGRPCServer) Configure(ctx context.Context, req *pb.ConfigureRequest) (*pb.ConfigureResponse, error) {
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

func (s *cliGRPCServer) Commands(ctx context.Context, req *pb.CLICommandsRequest) (*pb.CLICommandsResponse, error) {
	commands := s.Impl.Commands()
	pbCommands := make([]*pb.CLICommand, len(commands))
	for i, cmd := range commands {
		pbCommands[i] = convertCommandToPB(cmd)
	}
	return &pb.CLICommandsResponse{Commands: pbCommands}, nil
}

func convertCommandToPB(cmd CLICommand) *pb.CLICommand {
	flags := make([]*pb.CLIFlag, len(cmd.Flags))
	for i, f := range cmd.Flags {
		flags[i] = &pb.CLIFlag{
			Name:         f.Name,
			Shorthand:    f.Shorthand,
			Description:  f.Description,
			Type:         f.Type,
			DefaultValue: f.Default,
			Required:     f.Required,
		}
	}

	subcommands := make([]*pb.CLICommand, len(cmd.Subcommands))
	for i, sub := range cmd.Subcommands {
		subcommands[i] = convertCommandToPB(sub)
	}

	return &pb.CLICommand{
		Name:        cmd.Name,
		Description: cmd.Description,
		Usage:       cmd.Usage,
		Flags:       flags,
		Subcommands: subcommands,
	}
}

func (s *cliGRPCServer) Execute(ctx context.Context, req *pb.CLIExecuteRequest) (*pb.CLIExecuteResponse, error) {
	flags := make(map[string]interface{})
	for k, v := range req.Flags {
		flags[k] = v
	}
	if len(req.FlagsJson) > 0 {
		var jsonFlags map[string]interface{}
		if err := json.Unmarshal(req.FlagsJson, &jsonFlags); err == nil {
			for k, v := range jsonFlags {
				flags[k] = v
			}
		}
	}

	output, err := s.Impl.Execute(ctx, req.Command, req.Args, flags)
	if err != nil {
		return &pb.CLIExecuteResponse{
			Success:  false,
			Error:    err.Error(),
			Output:   output,
			ExitCode: 1,
		}, nil
	}
	return &pb.CLIExecuteResponse{
		Success:  true,
		Output:   output,
		ExitCode: 0,
	}, nil
}

func (s *cliGRPCServer) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
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
