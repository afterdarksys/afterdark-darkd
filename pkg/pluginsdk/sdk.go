// Package pluginsdk provides the SDK for building afterdark-darkd plugins.
//
// This package is the public API for plugin authors. It re-exports the types
// and functions needed to create plugins that integrate with the afterdark-darkd
// security daemon.
//
// # Quick Start
//
// To create a service plugin:
//
//	package main
//
//	import (
//		"context"
//		sdk "github.com/afterdarksys/afterdark-darkd/pkg/pluginsdk"
//	)
//
//	type MyService struct {
//		sdk.BaseServicePlugin
//	}
//
//	func (s *MyService) Info() sdk.PluginInfo {
//		return sdk.PluginInfo{
//			Name:        "my-service",
//			Version:     "1.0.0",
//			Type:        sdk.PluginTypeService,
//			Description: "My custom security service",
//			Author:      "Your Name",
//		}
//	}
//
//	func (s *MyService) Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error) {
//		// Implementation
//		return nil, nil
//	}
//
//	func main() {
//		sdk.ServeServicePlugin(&MyService{})
//	}
package pluginsdk

import (
	"context"
	"os"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/plugin"
)

// Re-export types for plugin authors
type (
	// PluginType identifies the kind of plugin
	PluginType string

	// PluginInfo contains metadata about a plugin
	PluginInfo struct {
		Name         string     `json:"name"`
		Version      string     `json:"version"`
		Type         PluginType `json:"type"`
		Description  string     `json:"description"`
		Author       string     `json:"author"`
		License      string     `json:"license"`
		Capabilities []string   `json:"capabilities,omitempty"`
	}

	// PluginState represents the current state of a plugin
	PluginState int

	// PluginHealth represents health status of a plugin
	PluginHealth struct {
		State     PluginState            `json:"state"`
		Message   string                 `json:"message,omitempty"`
		LastCheck time.Time              `json:"last_check"`
		Metrics   map[string]interface{} `json:"metrics,omitempty"`
	}

	// CLICommand represents a CLI command provided by a plugin
	CLICommand struct {
		Name        string     `json:"name"`
		Description string     `json:"description"`
		Usage       string     `json:"usage"`
		Flags       []CLIFlag  `json:"flags,omitempty"`
		Subcommands []CLICommand `json:"subcommands,omitempty"`
	}

	// CLIFlag represents a command-line flag
	CLIFlag struct {
		Name        string `json:"name"`
		Shorthand   string `json:"shorthand,omitempty"`
		Description string `json:"description"`
		Type        string `json:"type"` // "string", "int", "bool", "stringSlice"
		Default     string `json:"default,omitempty"`
		Required    bool   `json:"required"`
	}
)

// Plugin types
const (
	PluginTypeService    PluginType = "service"
	PluginTypeDataSource PluginType = "datasource"
	PluginTypeStorage    PluginType = "storage"
	PluginTypeReporter   PluginType = "reporter"
	PluginTypeCLI        PluginType = "cli"
)

// Plugin states
const (
	PluginStateUnknown PluginState = iota
	PluginStateLoading
	PluginStateReady
	PluginStateRunning
	PluginStateStopping
	PluginStateStopped
	PluginStateError
)

func (s PluginState) String() string {
	switch s {
	case PluginStateLoading:
		return "loading"
	case PluginStateReady:
		return "ready"
	case PluginStateRunning:
		return "running"
	case PluginStateStopping:
		return "stopping"
	case PluginStateStopped:
		return "stopped"
	case PluginStateError:
		return "error"
	default:
		return "unknown"
	}
}

// ProtocolVersion is the plugin protocol version
const ProtocolVersion = 1

// HandshakeConfig is used to validate plugin connections
var HandshakeConfig = plugin.HandshakeConfig{
	ProtocolVersion:  ProtocolVersion,
	MagicCookieKey:   "AFTERDARK_PLUGIN",
	MagicCookieValue: "darkd-v1",
}

// ServicePlugin is the interface for service-type plugins
type ServicePlugin interface {
	Info() PluginInfo
	Configure(config map[string]interface{}) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Health() PluginHealth
	Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error)
}

// DataSourcePlugin is the interface for data source plugins
type DataSourcePlugin interface {
	Info() PluginInfo
	Configure(config map[string]interface{}) error
	Connect(ctx context.Context) error
	Disconnect(ctx context.Context) error
	Query(ctx context.Context, query string, params map[string]interface{}) ([]map[string]interface{}, error)
	Subscribe(ctx context.Context, topic string, handler func(data map[string]interface{})) error
	Health() PluginHealth
}

// StoragePlugin is the interface for storage backend plugins
type StoragePlugin interface {
	Info() PluginInfo
	Configure(config map[string]interface{}) error
	Connect(ctx context.Context) error
	Disconnect(ctx context.Context) error
	Get(ctx context.Context, collection, key string) ([]byte, error)
	Set(ctx context.Context, collection, key string, value []byte) error
	Delete(ctx context.Context, collection, key string) error
	List(ctx context.Context, collection, prefix string) ([]string, error)
	Query(ctx context.Context, collection string, query map[string]interface{}) ([][]byte, error)
	Health() PluginHealth
}

// ReporterPlugin is the interface for report generator plugins
type ReporterPlugin interface {
	Info() PluginInfo
	Configure(config map[string]interface{}) error
	SupportedFormats() []string
	Generate(ctx context.Context, format string, data map[string]interface{}) ([]byte, error)
	Health() PluginHealth
}

// CLIPlugin is the interface for CLI command plugins
type CLIPlugin interface {
	Info() PluginInfo
	Configure(config map[string]interface{}) error
	Commands() []CLICommand
	Execute(ctx context.Context, command string, args []string, flags map[string]interface{}) (string, error)
	Health() PluginHealth
}

// BaseServicePlugin provides default implementations for ServicePlugin
type BaseServicePlugin struct {
	config  map[string]interface{}
	state   PluginState
	message string
}

func (b *BaseServicePlugin) Configure(config map[string]interface{}) error {
	b.config = config
	return nil
}

func (b *BaseServicePlugin) Start(ctx context.Context) error {
	b.state = PluginStateRunning
	return nil
}

func (b *BaseServicePlugin) Stop(ctx context.Context) error {
	b.state = PluginStateStopped
	return nil
}

func (b *BaseServicePlugin) Health() PluginHealth {
	return PluginHealth{
		State:     b.state,
		Message:   b.message,
		LastCheck: time.Now(),
	}
}

func (b *BaseServicePlugin) Config() map[string]interface{} {
	return b.config
}

func (b *BaseServicePlugin) SetState(state PluginState, message string) {
	b.state = state
	b.message = message
}

// BaseDataSourcePlugin provides default implementations for DataSourcePlugin
type BaseDataSourcePlugin struct {
	config  map[string]interface{}
	state   PluginState
	message string
}

func (b *BaseDataSourcePlugin) Configure(config map[string]interface{}) error {
	b.config = config
	return nil
}

func (b *BaseDataSourcePlugin) Connect(ctx context.Context) error {
	b.state = PluginStateRunning
	return nil
}

func (b *BaseDataSourcePlugin) Disconnect(ctx context.Context) error {
	b.state = PluginStateStopped
	return nil
}

func (b *BaseDataSourcePlugin) Subscribe(ctx context.Context, topic string, handler func(data map[string]interface{})) error {
	return nil // Default: no subscription support
}

func (b *BaseDataSourcePlugin) Health() PluginHealth {
	return PluginHealth{
		State:     b.state,
		Message:   b.message,
		LastCheck: time.Now(),
	}
}

func (b *BaseDataSourcePlugin) Config() map[string]interface{} {
	return b.config
}

func (b *BaseDataSourcePlugin) SetState(state PluginState, message string) {
	b.state = state
	b.message = message
}

// BaseStoragePlugin provides default implementations for StoragePlugin
type BaseStoragePlugin struct {
	config  map[string]interface{}
	state   PluginState
	message string
}

func (b *BaseStoragePlugin) Configure(config map[string]interface{}) error {
	b.config = config
	return nil
}

func (b *BaseStoragePlugin) Connect(ctx context.Context) error {
	b.state = PluginStateRunning
	return nil
}

func (b *BaseStoragePlugin) Disconnect(ctx context.Context) error {
	b.state = PluginStateStopped
	return nil
}

func (b *BaseStoragePlugin) Health() PluginHealth {
	return PluginHealth{
		State:     b.state,
		Message:   b.message,
		LastCheck: time.Now(),
	}
}

func (b *BaseStoragePlugin) Config() map[string]interface{} {
	return b.config
}

func (b *BaseStoragePlugin) SetState(state PluginState, message string) {
	b.state = state
	b.message = message
}

// BaseReporterPlugin provides default implementations for ReporterPlugin
type BaseReporterPlugin struct {
	config  map[string]interface{}
	state   PluginState
	message string
}

func (b *BaseReporterPlugin) Configure(config map[string]interface{}) error {
	b.config = config
	b.state = PluginStateReady
	return nil
}

func (b *BaseReporterPlugin) Health() PluginHealth {
	return PluginHealth{
		State:     b.state,
		Message:   b.message,
		LastCheck: time.Now(),
	}
}

func (b *BaseReporterPlugin) Config() map[string]interface{} {
	return b.config
}

func (b *BaseReporterPlugin) SetState(state PluginState, message string) {
	b.state = state
	b.message = message
}

// BaseCLIPlugin provides default implementations for CLIPlugin
type BaseCLIPlugin struct {
	config  map[string]interface{}
	state   PluginState
	message string
}

func (b *BaseCLIPlugin) Configure(config map[string]interface{}) error {
	b.config = config
	b.state = PluginStateReady
	return nil
}

func (b *BaseCLIPlugin) Health() PluginHealth {
	return PluginHealth{
		State:     b.state,
		Message:   b.message,
		LastCheck: time.Now(),
	}
}

func (b *BaseCLIPlugin) Config() map[string]interface{} {
	return b.config
}

func (b *BaseCLIPlugin) SetState(state PluginState, message string) {
	b.state = state
	b.message = message
}

// Logger returns an hclog.Logger for use in plugins
func Logger(name string) hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{
		Name:   name,
		Level:  hclog.LevelFromString(os.Getenv("PLUGIN_LOG_LEVEL")),
		Output: os.Stderr,
	})
}

// ServeServicePlugin starts the gRPC server for a service plugin
func ServeServicePlugin(impl ServicePlugin) {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"service": &servicePluginWrapper{Impl: impl},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

// ServeDataSourcePlugin starts the gRPC server for a data source plugin
func ServeDataSourcePlugin(impl DataSourcePlugin) {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"datasource": &dataSourcePluginWrapper{Impl: impl},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

// ServeStoragePlugin starts the gRPC server for a storage plugin
func ServeStoragePlugin(impl StoragePlugin) {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"storage": &storagePluginWrapper{Impl: impl},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

// ServeReporterPlugin starts the gRPC server for a reporter plugin
func ServeReporterPlugin(impl ReporterPlugin) {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"reporter": &reporterPluginWrapper{Impl: impl},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

// ServeCLIPlugin starts the gRPC server for a CLI plugin
func ServeCLIPlugin(impl CLIPlugin) {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"cli": &cliPluginWrapper{Impl: impl},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

// Plugin wrappers that implement plugin.GRPCPlugin

type servicePluginWrapper struct {
	plugin.Plugin
	Impl ServicePlugin
}

func (p *servicePluginWrapper) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterServicePluginServer(s, &serviceGRPCServer{Impl: p.Impl})
	return nil
}

func (p *servicePluginWrapper) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return nil, nil // Not used on plugin side
}

type dataSourcePluginWrapper struct {
	plugin.Plugin
	Impl DataSourcePlugin
}

func (p *dataSourcePluginWrapper) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterDataSourcePluginServer(s, &dataSourceGRPCServer{Impl: p.Impl})
	return nil
}

func (p *dataSourcePluginWrapper) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return nil, nil
}

type storagePluginWrapper struct {
	plugin.Plugin
	Impl StoragePlugin
}

func (p *storagePluginWrapper) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterStoragePluginServer(s, &storageGRPCServer{Impl: p.Impl})
	return nil
}

func (p *storagePluginWrapper) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return nil, nil
}

type reporterPluginWrapper struct {
	plugin.Plugin
	Impl ReporterPlugin
}

func (p *reporterPluginWrapper) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterReporterPluginServer(s, &reporterGRPCServer{Impl: p.Impl})
	return nil
}

func (p *reporterPluginWrapper) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return nil, nil
}

type cliPluginWrapper struct {
	plugin.Plugin
	Impl CLIPlugin
}

func (p *cliPluginWrapper) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterCLIPluginServer(s, &cliGRPCServer{Impl: p.Impl})
	return nil
}

func (p *cliPluginWrapper) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return nil, nil
}
