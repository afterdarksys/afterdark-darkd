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

// CLIPluginImpl implements plugin.GRPCPlugin for CLI plugins
type CLIPluginImpl struct {
	plugin.Plugin
	Impl CLIPlugin
}

func (p *CLIPluginImpl) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterCLIPluginServer(s, &cliGRPCServer{Impl: p.Impl})
	return nil
}

func (p *CLIPluginImpl) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &cliGRPCClient{client: pb.NewCLIPluginClient(c)}, nil
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

// cliGRPCClient is the gRPC client for CLIPlugin (host side)
type cliGRPCClient struct {
	client pb.CLIPluginClient
}

func (c *cliGRPCClient) Info() PluginInfo {
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

func (c *cliGRPCClient) Configure(config map[string]interface{}) error {
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

func (c *cliGRPCClient) Commands() []CLICommand {
	resp, err := c.client.Commands(context.Background(), &pb.CLICommandsRequest{})
	if err != nil {
		return nil
	}

	commands := make([]CLICommand, len(resp.Commands))
	for i, cmd := range resp.Commands {
		commands[i] = convertCommandFromPB(cmd)
	}
	return commands
}

func convertCommandFromPB(cmd *pb.CLICommand) CLICommand {
	flags := make([]CLIFlag, len(cmd.Flags))
	for i, f := range cmd.Flags {
		flags[i] = CLIFlag{
			Name:        f.Name,
			Shorthand:   f.Shorthand,
			Description: f.Description,
			Type:        f.Type,
			Default:     f.DefaultValue,
			Required:    f.Required,
		}
	}

	subcommands := make([]CLICommand, len(cmd.Subcommands))
	for i, sub := range cmd.Subcommands {
		subcommands[i] = convertCommandFromPB(sub)
	}

	return CLICommand{
		Name:        cmd.Name,
		Description: cmd.Description,
		Usage:       cmd.Usage,
		Flags:       flags,
		Subcommands: subcommands,
	}
}

func (c *cliGRPCClient) Execute(ctx context.Context, command string, args []string, flags map[string]interface{}) (string, error) {
	flagsJSON, _ := json.Marshal(flags)
	resp, err := c.client.Execute(ctx, &pb.CLIExecuteRequest{
		Command:   command,
		Args:      args,
		FlagsJson: flagsJSON,
	})
	if err != nil {
		return "", err
	}
	if !resp.Success {
		return resp.Output, fmt.Errorf(resp.Error)
	}
	return resp.Output, nil
}

func (c *cliGRPCClient) Health() PluginHealth {
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
